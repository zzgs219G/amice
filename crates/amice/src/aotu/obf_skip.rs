//! 混淆 pass 的公共判据（2026-11-18 本 fork 新增）
//!
//! ## 解决什么问题
//!
//! `.ncx` 段在锁箱后是**密文**，而密文完全不可压缩（熵 8.0，zlib 压不动）。
//! 所以任何让 `.ncx` 变大的 pass 都是**直接线性增加 APK 体积**，
//! 而同样操作作用在 `.text`（明文）上只需几 KB。
//!
//! 实测（简盒样本，2026-11-18）：
//!
//! | | `.text` | `.ncx` |
//! |---|---|---|
//! | 混淆关 | 67,668 B | 49,192 B |
//! | 混淆开 | 109,524 B（+42 KB，可压） | 190,324 B（+141 KB，不可压） |
//!
//! 而 `.ncx` 里的增量主要来自 **dex2c 产物**：单方法 `onCreate` 转译后
//! 是 22,716 B 的巨型函数（Dalvik 255 个局部变量全部摊平成 C 变量），
//! 被 `Flatten` 改写成状态机后膨胀到 95,936 B（4.2 倍）。
//!
//! 关键是这笔膨胀**收益为零**：
//!   · dex2c 保护的是"Java 方法的执行形态"，不是"藏代码"——
//!     原 Java 代码仍在 `classes.dex` 里明文可读（只是被改成 native 声明）
//!   · 攻击者想读业务逻辑，直接看 dex 就够了，不需要解 `.ncx`
//!   · 而 dex2c 产物因寄存器天然超限（Dalvik 255 变量 > VM 的 32 寄存器），
//!     从来就没被 VMP 保护过（protect.sh:1600 有完整记录）
//!
//! ## 结论
//!
//! 混淆应该只作用于**明文段**（`.text` 等，可压缩，且确实是防逆向对象），
//! 不该作用于 `.ncx`（密文、不可压缩、且其中 dex2c 部分收益为零）。
//!
//! 由环境变量 `AMICE_OBF_SKIP_SECTIONS` 指定要排除的段（逗号分隔），
//! 默认 `.ncx`。留空 = 恢复旧行为（对所有段都混淆）。

use amice_plugin::inkwell::values::{FunctionValue, GlobalValue};
use std::sync::OnceLock;

/// 默认排除的段：`.ncx` 是锁箱后的密文段，混淆只会线性增加 APK 体积。
pub const DEFAULT_SKIP_SECTIONS: &str = ".ncx";

fn skip_list() -> &'static Vec<String> {
    static LIST: OnceLock<Vec<String>> = OnceLock::new();
    LIST.get_or_init(|| {
        let raw = std::env::var("AMICE_OBF_SKIP_SECTIONS")
            .unwrap_or_else(|_| DEFAULT_SKIP_SECTIONS.to_string());
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// 该函数是否位于"不参与混淆"的段。
///
/// ⚠️ section 在 LLVM 里是 GlobalObject 的独立字段，不是 function attribute，
///    必须用 `get_section()` 读（与 `vm_virtualize/mod.rs` 里 `set_section`
///    的用法同源）。
/// ⚠️ 无 section 属性 = 默认 `.text`，返回 false（照常混淆）。
pub fn in_obf_skip_section(function: FunctionValue<'_>) -> bool {
    let list = skip_list();
    if list.is_empty() {
        return false;
    }
    let Some(section) = function.get_section() else {
        return false; // 默认段（.text），不排除
    };
    let Ok(name) = section.to_str() else {
        return false;
    };
    let name = name.trim();
    list.iter().any(|s| s == name)
}

/// 统一的日志：告诉读日志的人"这个函数为什么没被混淆"。
///
/// 为什么必须打日志：本项目反复踩"静默跳过"的坑（AGENTS §3.3
/// "日志有输出 ≠ 防护生效"，反过来"防护没生效但日志不说"更糟）。
/// 跳过混淆是预期行为，但必须可观测，否则下次有人看到 `.ncx` 明文
/// 会误以为是配置没生效。
pub fn log_skip(pass_name: &str, function: FunctionValue<'_>) {
    log::info!(
        "[amice] skip {pass_name} for section-excluded function: {:?}",
        function.get_name()
    );
}
