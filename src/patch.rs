use core::slice;

use crate::{
    PatchError, ReturnType, Trampoline,
    arch::build_call,
    relative_jump::{NEAR_JUMP, NEAR_JUMP_SIZE, build_near_jump, relative_offset},
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
    /// Prepares a call to `function` at `address`.
    ///
    /// `size` determines how many bytes are overwritten and must be at least
    /// five.
    ///
    /// # Safety
    ///
    /// `address..address + size` must be readable and contain complete
    /// instructions. The callback and selected return register must be
    /// compatible with the machine state at the patch site.
    pub unsafe fn patch_call(
        &mut self,
        address: usize,
        function: *const (),
        size: usize,
        save_overwritten: bool,
        allow_return: ReturnType,
    ) -> Result<Patch, PatchError> {
        if size < NEAR_JUMP_SIZE {
            return Err(PatchError::PatchTooSmall {
                size,
                minimum: NEAR_JUMP_SIZE,
            });
        }

        // SAFETY: The caller guarantees that this source range is readable.
        let overwritten = unsafe { slice::from_raw_parts(address as *const u8, size) }.to_vec();
        let mut trampoline = Vec::new();

        if save_overwritten {
            trampoline.extend_from_slice(&overwritten);
        }
        trampoline.extend_from_slice(&build_call(function, allow_return));

        let jump_displacement = trampoline.len() + 1;
        trampoline.extend_from_slice(&[NEAR_JUMP, 0, 0, 0, 0]);
        let trampoline_size = trampoline.len();
        let continuation = address
            .checked_add(size)
            .ok_or(PatchError::AddressOverflow)?;

        // SAFETY: The source range was validated above and remains the
        // caller's responsibility until installation.
        unsafe {
            self.prepare_detour(
                address,
                overwritten,
                trampoline_size,
                move |trampoline_address| {
                    let mut code = trampoline.clone();
                    let next_instruction = trampoline_address
                        .checked_add(code.len())
                        .ok_or(PatchError::AddressOverflow)?;
                    let displacement = relative_offset(next_instruction, continuation)?;
                    code[jump_displacement..jump_displacement + 4]
                        .copy_from_slice(&displacement.to_le_bytes());
                    Ok(code)
                },
            )
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

    #[test]
    fn invalid_patch_inputs_return_errors() {
        unsafe {
            let mut session = PatchSession::new();
            assert!(matches!(
                session.patch_call(0, std::ptr::null(), 4, false, ReturnType::None),
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
