//! Bounded SSA representation changes, with an integer-only fallback.
mod algebra;
mod integer;
mod region;

use crate::config::{Config, MbaConfig};
use crate::pass_registry::{AmiceFunctionPass, AmicePass, AmicePassFlag};
use amice_llvm::inkwell2::{FunctionExt, ModuleExt};
use amice_macro::amice;
use amice_plugin::inkwell::attributes::AttributeLoc;
use amice_plugin::{PreservedAnalyses, inkwell::module::Module};

#[amice(
    priority = 955,
    name = "Mba",
    flag = AmicePassFlag::OptimizerLast | AmicePassFlag::FunctionLevel,
    config = MbaConfig,
)]
#[derive(Default)]
pub struct Mba {}

impl AmicePass for Mba {
    fn init(&mut self, cfg: &Config, _flag: AmicePassFlag) {
        self.default_config = cfg.mba.clone();
    }

    fn do_pass(&self, module: &mut Module<'_>) -> anyhow::Result<PreservedAnalyses> {
        let mut changed = false;
        let mut changed_effects = false;
        // 先快照函数列表：循环内要 &mut 调 read_function_annotate，
        // 与 get_functions() 的借用冲突（vm_virtualize/mod.rs 同此做法）。
        let functions = module
            .get_functions()
            .into_iter()
            .filter(|f| !f.is_undef_function() && !f.is_llvm_function())
            .collect::<Vec<_>>();

        for function in functions {
            if function
                .get_string_attribute(AttributeLoc::Function, "amice.mba.done")
                .is_some()
            {
                continue;
            }

            // ── 标了 VMP 的函数不上混淆（2026-11-14 本 fork 新增）─────────
            //
            // 语义是【互斥而非叠加】：每个函数只吃一层最强的保护。
            //
            // 为什么必须跳过：`Flatten` 在 PipelineStart 先跑，把函数体改成
            // 状态机后，`VmVirtualize`（OptimizerLast）看到的已不是原始 CFG，
            // prepare_virtualization 失败 → 该函数被 VMP 跳过 →
            // 防护从"读不懂"降级为"1~2 小时读懂"。实测见消费方
            // nox/nc_guard_boot.c 的 NC_OBF 注释。
            //
            // 反过来，标了 VMP 的函数再上 MBA 也是白花体积：函数体已是 VM
            // 字节码，MBA 加工到的只有 wrapper 的几条胶水指令。
            //
            // ⚠️ 日志用 info 不用 warn：被跳过是预期行为，不是异常。
            // ⚠️ 格式固定 "[amice] skip <Pass> for VMP function: <name>"，
            //    消费方按这个前缀 grep 统计 VMP 生效函数数。
            let vmp_target = module
                .read_function_annotate(function)
                .map(|exprs| {
                    let joined = exprs.join(" ");
                    joined.contains("+vm_virtualize")
                        || joined.contains("+vmp")
                        || joined.contains("vm_virtualize=1")
                        || joined.contains("vm_virtualize=true")
                })
                .unwrap_or(false);
            if vmp_target {
                log::info!(
                    "[amice] skip Mba for VMP function: {:?}",
                    function.get_name()
                );
                continue;
            }

            let cfg = self.parse_function_annotations(module, function)?;
            if !cfg.enable {
                continue;
            }
            let (rewritten, effects) = region::rewrite(module, function, &cfg)?;
            changed_effects |= effects;
            if rewritten {
                let attr = module.get_context().create_string_attribute("amice.mba.done", "1");
                function.add_attribute(AttributeLoc::Function, attr);
                changed = true;
            }
        }
        if changed_effects {
            // Caller summaries and explicit call-site attributes can retain
            // memory(none), including through indirect calls and aliases. Both
            // volatile guards and constrained FP access observable state.
            module.invalidate_memory_attrs_for_volatile();
        }
        Ok(if changed {
            PreservedAnalyses::None
        } else {
            PreservedAnalyses::All
        })
    }
}
