use core::slice;

use crate::{
    PatchError, ReturnType,
    arch::build_call,
    relative_jump::{NEAR_JUMP, NEAR_JUMP_SIZE, build_near_jump, relative_offset},
    session::{PendingPatch, patch_manager},
};

/// A handle describing a patch prepared for installation.
pub struct Patch {
    trampoline: Option<CodeAllocation>,
}

#[derive(Clone, Copy)]
struct CodeAllocation {
    address: usize,
}

impl Patch {
    /// Prepares a call to `function` at `address`.
    ///
    /// `size` determines how many bytes are overwritten and must be at least
    /// five. The patch is installed by calling [`crate::finalize_patches`].
    ///
    /// # Safety
    ///
    /// `address..address + size` must be readable and contain complete
    /// instructions. The callback and selected return register must be
    /// compatible with the machine state at the patch site.
    pub unsafe fn patch_call(
        address: usize,
        function: *const (),
        size: usize,
        save_overwritten: bool,
        allow_return: ReturnType,
    ) -> Self {
        assert!(
            size >= NEAR_JUMP_SIZE,
            "A patch call requires at least five bytes"
        );

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
            .expect("patch continuation address overflowed");

        // SAFETY: The source range was validated above and remains the
        // caller's responsibility until installation.
        unsafe {
            Self::prepare_detour(
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
        .unwrap_or_else(|error| panic!("Unable to prepare call patch at {address:#x}: {error}"))
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
    pub unsafe fn detour(address: usize, size: usize, trampoline: &[u8]) -> Self {
        let trampoline = trampoline.to_vec();
        // SAFETY: The caller provides the same guarantees required by
        // `detour_with`.
        unsafe {
            Self::detour_with(address, size, trampoline.len(), move |_| {
                Ok(trampoline.clone())
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
        address: usize,
        size: usize,
        trampoline_size: usize,
        build: F,
    ) -> Self
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        assert!(
            size >= NEAR_JUMP_SIZE,
            "A detour requires at least five bytes"
        );
        assert!(trampoline_size > 0, "A detour trampoline cannot be empty");

        // SAFETY: The caller guarantees that this source range is readable.
        let overwritten = unsafe { slice::from_raw_parts(address as *const u8, size) }.to_vec();
        // SAFETY: The caller provides the validity guarantees documented by
        // this method.
        unsafe { Self::prepare_detour(address, overwritten, trampoline_size, build) }
            .unwrap_or_else(|error| panic!("Unable to prepare detour at {address:#x}: {error}"))
    }

    unsafe fn prepare_detour<F>(
        address: usize,
        overwritten: Vec<u8>,
        trampoline_size: usize,
        build: F,
    ) -> Result<Self, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        let mut manager = patch_manager();
        let session = manager.session_mut()?;
        session.ensure_patch_does_not_overlap(address, overwritten.len())?;

        let trampoline_address = session.allocate_trampoline(address, trampoline_size, &build)?;
        let replacement = build_near_jump(address, trampoline_address, overwritten.len())?;

        session.pending.push(PendingPatch {
            address,
            overwritten: overwritten.clone(),
            replacement,
        });

        Ok(Self {
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
    pub unsafe fn overwrite(address: usize, data: &[u8]) -> Self {
        assert!(!data.is_empty(), "A patch must overwrite at least one byte");

        // SAFETY: The caller guarantees that this source range is readable.
        let overwritten =
            unsafe { slice::from_raw_parts(address as *const u8, data.len()) }.to_vec();
        let mut manager = patch_manager();
        let session = manager
            .session_mut()
            .unwrap_or_else(|error| panic!("Unable to prepare patch at {address:#x}: {error}"));
        session
            .ensure_patch_does_not_overlap(address, data.len())
            .unwrap_or_else(|error| panic!("Unable to prepare patch at {address:#x}: {error}"));
        session.pending.push(PendingPatch {
            address,
            overwritten: overwritten.clone(),
            replacement: data.to_vec(),
        });

        Self { trampoline: None }
    }

    /// Returns the allocated trampoline address, if this patch has one.
    pub fn trampoline_address(&self) -> Option<usize> {
        self.trampoline.map(|allocation| allocation.address)
    }
}
