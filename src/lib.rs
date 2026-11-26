//! Runtime code patching for 64-bit Windows processes.
//!
//! Patchy prepares overwrites and x86-64 call trampolines in a [`PatchSession`]
//! before installing them permanently as one batch. It currently targets only
//! the Windows x64 ABI.

#![cfg_attr(not(all(target_os = "windows", target_arch = "x86_64")), allow(unused))]

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("patchy currently supports only 64-bit Windows targets");

mod patch;
mod process_module;
mod relative_jump;
mod session;

pub use patch::Patch;
pub use patchy_code::{
    CallBridge, Condition, DetourSite, FlagPolicy, KeepReturn, Label, PatchError, StackAlignment,
    Trampoline, TrampolineFixup, TrampolinePlan, relative_offset,
};
pub use process_module::ProcessModule;
pub use session::PatchSession;

/// A result returned by Patchy operations.
pub type Result<T = ()> = std::result::Result<T, PatchError>;
