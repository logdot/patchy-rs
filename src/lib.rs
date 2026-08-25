//! Runtime code patching for 64-bit Windows processes.
//!
//! Patchy prepares overwrites and x86-64 call trampolines before installing
//! them as one batch with [`finalize_patches`]. It currently targets only the
//! Windows x64 ABI.

#![cfg_attr(not(all(target_os = "windows", target_arch = "x86_64")), allow(unused))]

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("patchy currently supports only 64-bit Windows targets");

mod arch;
mod error;
mod patch;
mod process_module;
mod relative_jump;
mod session;
mod trampoline;

pub use error::PatchError;
pub use patch::Patch;
pub use process_module::ProcessModule;
pub use relative_jump::relative_offset;
pub use session::finalize_patches;
pub use trampoline::{Label, Trampoline};

/// Selects which hook return register is allowed to replace the original value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnType {
    /// Preserve both `RAX` and `XMM0`.
    None,
    /// Keep the hook's result in `RAX`.
    Rax,
    /// Keep the hook's result in `XMM0`.
    Xmm0,
}
