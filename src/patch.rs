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

/// The captured source span of a detour being prepared.
///
/// Use this in [`PatchSession::detour_trampoline_with`] to place replay and
/// continuation jumps without rereading the source or calculating its end.
pub struct DetourSite<'a> {
    overwritten: &'a [u8],
    continuation: usize,
}

impl DetourSite<'_> {
    /// Appends the captured source instructions at the current position.
    ///
    /// These are the same bytes checked during installation. Patchy copies
    /// them without decoding or relocating them.
    ///
    /// # Safety
    ///
    /// The captured span must contain only whole instructions. The caller must
    /// ensure that they execute correctly at the trampoline's new address and
    /// with the machine state at this point in its control flow. In particular,
    /// a relative branch, call, or RIP-relative operand that targets something
    /// outside the copied span generally cannot be replayed verbatim.
    pub unsafe fn replay_verbatim(&self, trampoline: &mut Trampoline) {
        trampoline.bytes(self.overwritten);
    }

    /// Appends a jump to the first byte after the overwritten span.
    pub fn resume(&self, trampoline: &mut Trampoline) {
        trampoline.relative_jump(self.continuation);
    }
}

impl PatchSession {
    /// Replaces `size` bytes at `address` with a call described by `bridge`,
    /// then resumes execution at `address + size`.
    ///
    /// The overwritten instructions do not run. `size` must be at least five
    /// and cover only complete instructions. To replay them, use
    /// [`detour_trampoline_with`](Self::detour_trampoline_with).
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
        // SAFETY: The caller guarantees the source range and the generated
        // trampoline calls the bridge with the declared state, then resumes.
        unsafe {
            self.detour_trampoline_with(address, size, |site| {
                let mut trampoline = Trampoline::new();
                trampoline.call(bridge);
                site.resume(&mut trampoline);
                Ok(trampoline)
            })
        }
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
        if trampoline.is_empty() {
            return Err(PatchError::EmptyTrampoline);
        }
        // SAFETY: Both methods require a valid source span and trampoline.
        unsafe { self.detour_trampoline_with(address, size, |_| Ok(trampoline)) }
    }

    /// Captures the source span, then builds a trampoline for that detour.
    ///
    /// `build` runs once after capture. Use [`DetourSite::replay_verbatim`] and
    /// [`DetourSite::resume`] to insert replay and continuation jumps wherever
    /// they belong in the trampoline, including on individual branches.
    ///
    /// # Safety
    ///
    /// `address..address + size` must remain readable through installation and
    /// consist of whole instructions with no incoming branches into the middle
    /// of the span. The returned trampoline must contain valid x86-64 code and
    /// preserve the state required by the surrounding function on every exit.
    pub unsafe fn detour_trampoline_with<F>(
        &mut self,
        address: usize,
        size: usize,
        build: F,
    ) -> Result<Patch, PatchError>
    where
        F: FnOnce(DetourSite<'_>) -> Result<Trampoline, PatchError>,
    {
        let continuation = detour_end(address, size)?;
        // SAFETY: The caller guarantees a readable source range.
        let overwritten = unsafe { slice::from_raw_parts(address as *const u8, size) }.to_vec();
        let trampoline = build(DetourSite {
            overwritten: &overwritten,
            continuation,
        })?;
        let trampoline_size = trampoline.len();
        if trampoline_size == 0 {
            return Err(PatchError::EmptyTrampoline);
        }

        // SAFETY: The caller provides the validity guarantees documented by
        // this method.
        unsafe {
            self.prepare_detour(
                address,
                overwritten,
                trampoline_size,
                |trampoline_address| trampoline.build(trampoline_address),
            )
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
        detour_end(address, size)?;
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

fn detour_end(address: usize, size: usize) -> Result<usize, PatchError> {
    if size < NEAR_JUMP_SIZE {
        return Err(PatchError::PatchTooSmall {
            size,
            minimum: NEAR_JUMP_SIZE,
        });
    }
    address.checked_add(size).ok_or(PatchError::AddressOverflow)
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
