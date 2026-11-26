//! x86-64 trampoline construction without a process patching engine.
//!
//! This crate owns code generation only. It neither reads source addresses
//! nor allocates executable memory. Runtime addresses require a 64-bit host.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("patchy-code requires a 64-bit host");

mod bridge;
mod error;
mod plan;
mod trampoline;

pub use bridge::{CallBridge, FlagPolicy, KeepReturn, StackAlignment};
pub use error::PatchError;
pub use plan::{TrampolineFixup, TrampolinePlan};
pub use trampoline::{Condition, DetourSite, Label, Trampoline};

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

/// Calculates a signed 32-bit relative displacement.
///
/// `next_instruction` is the address immediately after the instruction that
/// will contain the displacement.
pub fn relative_offset(next_instruction: usize, destination: usize) -> Result<i32, PatchError> {
    let displacement = destination as i128 - next_instruction as i128;
    i32::try_from(displacement).map_err(|_| PatchError::RelativeJumpOutOfRange {
        next_instruction,
        destination,
    })
}
