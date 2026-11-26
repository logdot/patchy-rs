use core::slice;

use crate::{
    CallBridge, PatchError, Trampoline,
    relative_jump::{NEAR_JUMP_SIZE, build_near_jump},
    session::{PatchSession, PendingPatch},
};

/// Describes a patch prepared in a [`PatchSession`].
///
/// This value does not own the prepared patch. Dropping it does not remove the
/// patch from its session, and installed patches are permanent.
pub struct Patch {
    trampoline: Option<CodeAllocation>,
}

#[derive(Clone, Copy)]
struct CodeAllocation {
    address: usize,
}

impl PatchSession {
    /// Replaces `size` bytes at `address` with a call described by `bridge`,
    /// then resumes execution at `address + size`.
    ///
    /// The overwritten instructions do not run. `size` must be at least five
    /// and cover only complete instructions. To run some of them first, build
    /// a [`Trampoline`] and use [`detour_trampoline`](Self::detour_trampoline).
    ///
    /// # Safety
    ///
    /// `address..address + size` must be readable and contain complete
    /// instructions, none of which may be a branch target other than the first.
    /// The bridge must satisfy the requirements documented on
    /// [`Trampoline::call`] for the machine state at `address`, where `RSP` has
    /// the alignment given by `bridge.incoming_stack`.
    pub unsafe fn patch_call(
        &mut self,
        address: usize,
        size: usize,
        bridge: CallBridge<'_>,
    ) -> Result<Patch, PatchError> {
        let resume = address
            .checked_add(size)
            .ok_or(PatchError::AddressOverflow)?;
        let mut trampoline = Trampoline::new();
        // SAFETY: The caller provides the guarantees `Trampoline::call`
        // requires, and the trampoline starts at the patched instruction.
        unsafe { trampoline.call(bridge) }.relative_jump(resume);

        // SAFETY: The caller guarantees the source range and the generated
        // trampoline preserves state on its only exit.
        unsafe { self.detour_trampoline(address, size, trampoline) }
    }

    /// Prepares a near jump from `address` to `trampoline`.
    ///
    /// The trampoline remains executable for the lifetime of the process and
    /// must transfer control to the appropriate continuation itself.
    ///
    /// # Safety
    ///
    /// The source range must be readable and contain complete instructions.
    /// `trampoline` must contain valid x86-64 machine code whose exits preserve
    /// the surrounding function state.
    pub unsafe fn detour(
        &mut self,
        address: usize,
        size: usize,
        trampoline: &[u8],
    ) -> Result<Patch, PatchError> {
        let trampoline = trampoline.to_vec();
        // SAFETY: The caller provides the same guarantees required by
        // `detour_with`.
        unsafe {
            self.detour_with(address, size, trampoline.len(), move |_| {
                Ok(trampoline.clone())
            })
        }
    }

    /// Prepares a near jump to a relocation-aware trampoline.
    ///
    /// # Safety
    ///
    /// The source range must be readable and contain complete instructions.
    /// The built trampoline must preserve the surrounding function state on
    /// every exit.
    pub unsafe fn detour_trampoline(
        &mut self,
        address: usize,
        size: usize,
        trampoline: Trampoline,
    ) -> Result<Patch, PatchError> {
        let trampoline_size = trampoline.len();
        if trampoline_size == 0 {
            return Err(PatchError::EmptyTrampoline);
        }

        // SAFETY: The caller provides the validity guarantees documented by
        // this method.
        unsafe {
            self.detour_with(address, size, trampoline_size, move |trampoline_address| {
                trampoline.build(trampoline_address)
            })
        }
    }

    /// Prepares a near jump whose trampoline depends on its allocated address.
    ///
    /// `build` may be called more than once while a reachable allocation is
    /// sought and must always return exactly `trampoline_size` bytes.
    ///
    /// # Safety
    ///
    /// The source range must be readable and contain complete instructions.
    /// The built trampoline must be valid x86-64 machine code whose exits
    /// preserve the surrounding function state.
    pub unsafe fn detour_with<F>(
        &mut self,
        address: usize,
        size: usize,
        trampoline_size: usize,
        build: F,
    ) -> Result<Patch, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        if size < NEAR_JUMP_SIZE {
            return Err(PatchError::PatchTooSmall {
                size,
                minimum: NEAR_JUMP_SIZE,
            });
        }
        if trampoline_size == 0 {
            return Err(PatchError::EmptyTrampoline);
        }

        // SAFETY: The caller guarantees that this source range is readable.
        let overwritten = unsafe { slice::from_raw_parts(address as *const u8, size) }.to_vec();
        // SAFETY: The caller provides the validity guarantees documented by
        // this method.
        unsafe { self.prepare_detour(address, overwritten, trampoline_size, build) }
    }

    unsafe fn prepare_detour<F>(
        &mut self,
        address: usize,
        overwritten: Vec<u8>,
        trampoline_size: usize,
        build: F,
    ) -> Result<Patch, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        self.ensure_patch_does_not_overlap(address, overwritten.len())?;

        let trampoline_address = self.allocate_trampoline(address, trampoline_size, &build)?;
        let replacement = build_near_jump(address, trampoline_address, overwritten.len())?;

        self.pending.push(PendingPatch {
            address,
            expected: overwritten,
            replacement,
        });

        Ok(Patch {
            trampoline: Some(CodeAllocation {
                address: trampoline_address,
            }),
        })
    }

    /// Prepares an in-place byte overwrite at `address`.
    ///
    /// # Safety
    ///
    /// The destination range must be readable and writable after its page
    /// protection is changed. The replacement must contain valid instructions
    /// for every path that can execute it.
    pub unsafe fn overwrite(&mut self, address: usize, data: &[u8]) -> Result<Patch, PatchError> {
        if data.is_empty() {
            return Err(PatchError::EmptyPatch);
        }

        // SAFETY: The caller guarantees that this source range is readable.
        let overwritten =
            unsafe { slice::from_raw_parts(address as *const u8, data.len()) }.to_vec();
        self.ensure_patch_does_not_overlap(address, data.len())?;
        self.pending.push(PendingPatch {
            address,
            expected: overwritten,
            replacement: data.to_vec(),
        });

        Ok(Patch { trampoline: None })
    }
}

impl Patch {
    /// Returns the allocated trampoline address, if this patch has one.
    pub fn trampoline_address(&self) -> Option<usize> {
        self.trampoline.map(|allocation| allocation.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlagPolicy, KeepReturn, StackAlignment};

    #[test]
    fn invalid_patch_inputs_return_errors() {
        unsafe {
            let mut session = PatchSession::new();
            assert!(matches!(
                session.patch_call(
                    0,
                    4,
                    CallBridge {
                        callback: std::ptr::null(),
                        incoming_stack: StackAlignment::Aligned16,
                        flags: FlagPolicy::Preserve,
                        keep_return: KeepReturn::Neither,
                        before_call: &[],
                        after_call: &[],
                    }
                ),
                Err(PatchError::PatchTooSmall {
                    size: 4,
                    minimum: NEAR_JUMP_SIZE
                })
            ));
            assert!(matches!(
                session.detour(0, NEAR_JUMP_SIZE, &[]),
                Err(PatchError::EmptyTrampoline)
            ));
            assert!(matches!(
                session.overwrite(0, &[]),
                Err(PatchError::EmptyPatch)
            ));
        }
    }
}
