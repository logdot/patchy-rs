use core::slice;
use std::{
    collections::BTreeSet,
    ffi::c_void,
    sync::{Mutex, MutexGuard, OnceLock},
};

use mmap_rs::{Mmap, MmapMut, MmapOptions};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect},
    Threading::GetCurrentProcess,
};

use crate::{
    PatchError,
    relative_jump::{
        CandidateAddresses, NEAR_JUMP_SIZE, align_down, candidate_bounds, relative_offset,
        slot_range,
    },
};

#[derive(Default)]
pub(crate) struct PatchSession {
    pages: Vec<MutableCodePage>,
    pub(crate) pending: Vec<PendingPatch>,
}

struct MutableCodePage {
    mapping: MmapMut,
    used: usize,
}

pub(crate) struct PendingPatch {
    pub(crate) address: usize,
    pub(crate) overwritten: Vec<u8>,
    pub(crate) replacement: Vec<u8>,
}

struct PatchRuntime {
    pages: Vec<Mmap>,
    patches: Vec<PendingPatch>,
}

pub(crate) struct PatchManager {
    session: Option<PatchSession>,
    runtime: Option<PatchRuntime>,
}

impl PatchManager {
    fn new() -> Self {
        Self {
            session: Some(PatchSession::default()),
            runtime: None,
        }
    }

    pub(crate) fn session_mut(&mut self) -> Result<&mut PatchSession, PatchError> {
        if self.runtime.is_some() {
            return Err(PatchError::AlreadyFinalized);
        }

        self.session.as_mut().ok_or(PatchError::AlreadyFinalized)
    }
}

static PATCH_MANAGER: OnceLock<Mutex<PatchManager>> = OnceLock::new();

pub(crate) fn patch_manager() -> MutexGuard<'static, PatchManager> {
    PATCH_MANAGER
        .get_or_init(|| Mutex::new(PatchManager::new()))
        .lock()
        .expect("patch manager mutex poisoned")
}

impl PatchSession {
    pub(crate) fn ensure_patch_does_not_overlap(
        &self,
        address: usize,
        size: usize,
    ) -> Result<(), PatchError> {
        if size == 0 {
            return Err(PatchError::EmptyPatch);
        }

        let end = address
            .checked_add(size)
            .ok_or(PatchError::AddressOverflow)?;
        for patch in &self.pending {
            let patch_end = patch
                .address
                .checked_add(patch.replacement.len())
                .ok_or(PatchError::AddressOverflow)?;
            if address < patch_end && patch.address < end {
                return Err(PatchError::OverlappingPatch {
                    first: patch.address,
                    second: address,
                });
            }
        }

        Ok(())
    }

    pub(crate) fn allocate_trampoline<F>(
        &mut self,
        hook: usize,
        trampoline_size: usize,
        build: &F,
    ) -> Result<usize, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        let page_size = MmapOptions::page_size();
        if trampoline_size > page_size {
            return Err(PatchError::TrampolineTooLarge {
                size: trampoline_size,
                capacity: page_size,
            });
        }

        let hook_next_instruction = hook
            .checked_add(NEAR_JUMP_SIZE)
            .ok_or(PatchError::AddressOverflow)?;

        for page in &mut self.pages {
            let Some(range) = slot_range(page.used, trampoline_size, page_size) else {
                continue;
            };
            let trampoline_address = (page.mapping.as_ptr() as usize)
                .checked_add(range.start)
                .ok_or(PatchError::AddressOverflow)?;
            if relative_offset(hook_next_instruction, trampoline_address).is_err() {
                continue;
            }

            let code = match build(trampoline_address) {
                Ok(code) => code,
                Err(PatchError::RelativeJumpOutOfRange { .. }) => continue,
                Err(error) => return Err(error),
            };
            validate_trampoline_size(trampoline_size, code.len())?;
            page.mapping[range.clone()].copy_from_slice(&code);
            page.used = range.end;
            return Ok(trampoline_address);
        }

        self.allocate_trampoline_page(hook, trampoline_size, build)
    }

    fn allocate_trampoline_page<F>(
        &mut self,
        hook: usize,
        trampoline_size: usize,
        build: &F,
    ) -> Result<usize, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        let page_size = MmapOptions::page_size();
        let granularity = MmapOptions::allocation_granularity();
        let hook_next_instruction = hook
            .checked_add(NEAR_JUMP_SIZE)
            .ok_or(PatchError::AddressOverflow)?;
        let (minimum, maximum) = candidate_bounds(hook_next_instruction, page_size, granularity)?;
        let mut last_error = None;

        for candidate in CandidateAddresses::new(hook, minimum, maximum, granularity)? {
            if let Some(address) = self.try_allocate_page(
                candidate,
                hook_next_instruction,
                trampoline_size,
                build,
                &mut last_error,
            )? {
                return Ok(address);
            }
        }

        Err(PatchError::NoMemoryCave { hook, last_error })
    }

    fn try_allocate_page<F>(
        &mut self,
        candidate: usize,
        hook_next_instruction: usize,
        trampoline_size: usize,
        build: &F,
        last_error: &mut Option<String>,
    ) -> Result<Option<usize>, PatchError>
    where
        F: Fn(usize) -> Result<Vec<u8>, PatchError>,
    {
        let page_size = MmapOptions::page_size();
        let options =
            MmapOptions::new(page_size).map_err(|error| PatchError::Mapping(error.to_string()))?;
        let mut mapping = match options.with_address(candidate).map_mut() {
            Ok(mapping) => mapping,
            Err(error) => {
                *last_error = Some(error.to_string());
                return Ok(None);
            }
        };

        let actual_address = mapping.as_ptr() as usize;
        if actual_address != candidate {
            *last_error = Some(format!(
                "requested {candidate:#x}, but the mapping was placed at {actual_address:#x}"
            ));
            return Ok(None);
        }
        if relative_offset(hook_next_instruction, actual_address).is_err() {
            *last_error = Some(format!(
                "mapping at {actual_address:#x} was outside rel32 range"
            ));
            return Ok(None);
        }

        let code = match build(actual_address) {
            Ok(code) => code,
            Err(PatchError::RelativeJumpOutOfRange { .. }) => {
                *last_error = Some(format!(
                    "trampoline exits were unreachable from {actual_address:#x}"
                ));
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        validate_trampoline_size(trampoline_size, code.len())?;
        mapping[..trampoline_size].copy_from_slice(&code);
        self.pages.push(MutableCodePage {
            mapping,
            used: trampoline_size,
        });

        Ok(Some(actual_address))
    }
}

fn validate_trampoline_size(expected: usize, actual: usize) -> Result<(), PatchError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PatchError::UnexpectedTrampolineSize { expected, actual })
    }
}

struct SourceProtection {
    address: usize,
    old: PAGE_PROTECTION_FLAGS,
}

unsafe fn protect_patch_sources(
    patches: &[PendingPatch],
) -> Result<Vec<SourceProtection>, PatchError> {
    let page_size = MmapOptions::page_size();
    let mut source_pages = BTreeSet::new();

    for patch in patches {
        let last_byte = patch
            .address
            .checked_add(patch.replacement.len() - 1)
            .ok_or(PatchError::AddressOverflow)?;
        let first_page = align_down(patch.address, page_size);
        let last_page = align_down(last_byte, page_size);
        let mut page = first_page;

        loop {
            source_pages.insert(page);
            if page == last_page {
                break;
            }
            page = page
                .checked_add(page_size)
                .ok_or(PatchError::AddressOverflow)?;
        }
    }

    let mut protections = Vec::with_capacity(source_pages.len());
    for address in source_pages {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        // SAFETY: Each address is page-aligned and belongs to a source range
        // supplied by the caller.
        if let Err(error) = unsafe {
            VirtualProtect(
                address as *const c_void,
                page_size,
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        } {
            // SAFETY: These entries record protections successfully changed
            // earlier in this function.
            unsafe { restore_patch_sources(&protections)? };
            return Err(PatchError::Protection {
                address,
                error: error.to_string(),
            });
        }
        protections.push(SourceProtection { address, old });
    }

    Ok(protections)
}

unsafe fn restore_patch_sources(protections: &[SourceProtection]) -> Result<(), PatchError> {
    let page_size = MmapOptions::page_size();
    let mut first_error = None;

    for protection in protections.iter().rev() {
        let mut ignored = PAGE_PROTECTION_FLAGS(0);
        // SAFETY: The protection entry came from a successful VirtualProtect
        // call for this page.
        if let Err(error) = unsafe {
            VirtualProtect(
                protection.address as *const c_void,
                page_size,
                protection.old,
                &mut ignored,
            )
        } {
            first_error.get_or_insert_with(|| PatchError::Protection {
                address: protection.address,
                error: error.to_string(),
            });
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

unsafe fn validate_patch_sources(patches: &[PendingPatch]) -> Result<(), PatchError> {
    for patch in patches {
        // SAFETY: Patch preparation required this source range to remain
        // readable through installation.
        let current =
            unsafe { slice::from_raw_parts(patch.address as *const u8, patch.overwritten.len()) };
        if current != patch.overwritten {
            return Err(PatchError::SourceChanged {
                address: patch.address,
            });
        }
    }

    Ok(())
}

/// Seals all prepared trampoline pages as executable and installs every patch.
///
/// This process-wide patch set can be finalized only once.
///
/// # Safety
///
/// No other thread may execute a patch source while its instructions are being
/// replaced. Every source range and prepared trampoline must still satisfy the
/// requirements documented by the corresponding [`crate::Patch`] operation.
pub unsafe fn finalize_patches() -> Result<(), PatchError> {
    let mut manager = patch_manager();
    if manager.runtime.is_some() || manager.session.is_none() {
        return Err(PatchError::AlreadyFinalized);
    }

    let session = manager.session.take().ok_or(PatchError::AlreadyFinalized)?;
    let mut executable_pages = Vec::with_capacity(session.pages.len());
    for page in session.pages {
        match page.mapping.make_exec() {
            Ok(mapping) => executable_pages.push(mapping),
            Err((_mapping, error)) => return Err(PatchError::Mapping(error.to_string())),
        }
    }

    // SAFETY: The pseudo-handle is valid in the current process.
    let process = unsafe { GetCurrentProcess() };
    for page in &executable_pages {
        // SAFETY: Every page is a live executable mapping in this process.
        unsafe { FlushInstructionCache(process, Some(page.as_ptr() as *const c_void), page.len()) }
            .map_err(|error| PatchError::InstructionCache {
                address: page.as_ptr() as usize,
                error: error.to_string(),
            })?;
    }

    // SAFETY: The caller guarantees all prepared sources remain readable.
    unsafe { validate_patch_sources(&session.pending)? };
    // SAFETY: The caller guarantees the source ranges may be modified.
    let protections = unsafe { protect_patch_sources(&session.pending)? };
    // SAFETY: Revalidate after changing protections to narrow the race window.
    if let Err(error) = unsafe { validate_patch_sources(&session.pending) } {
        // SAFETY: `protections` records each changed source page.
        unsafe { restore_patch_sources(&protections)? };
        return Err(error);
    }

    let runtime = PatchRuntime {
        pages: executable_pages,
        patches: session.pending,
    };
    let page_count = runtime.pages.len();
    let patch_count = runtime.patches.len();
    manager.runtime = Some(runtime);

    let runtime = manager
        .runtime
        .as_ref()
        .expect("patch runtime disappeared during installation");
    for patch in &runtime.patches {
        // SAFETY: Source protections are writable and the source range was
        // validated immediately before this copy.
        unsafe {
            std::ptr::copy_nonoverlapping(
                patch.replacement.as_ptr(),
                patch.address as *mut u8,
                patch.replacement.len(),
            );
        }
    }

    for patch in &runtime.patches {
        // SAFETY: The replacement range is live executable memory in this
        // process.
        unsafe {
            FlushInstructionCache(
                process,
                Some(patch.address as *const c_void),
                patch.replacement.len(),
            )
        }
        .expect("unable to flush the instruction cache after installing patches");
    }
    // SAFETY: `protections` records each changed source page.
    unsafe { restore_patch_sources(&protections) }
        .expect("unable to restore source page protections after installing patches");

    log::info!("Installed {patch_count} patch(es) using {page_count} shared trampoline page(s)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Patch, ReturnType, relative_jump::NEAR_JUMP};
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
    };

    const DEAD_BEEF: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn dummy() {
        println!("Dummy function");
    }

    #[test]
    fn patch_calls_share_a_page_and_install_together() {
        unsafe {
            let size = 64;
            let test_memory =
                VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            assert!(!test_memory.is_null(), "Failed to allocate test memory");

            let test_data = DEAD_BEEF.to_vec().repeat(size / DEAD_BEEF.len());
            std::ptr::copy_nonoverlapping(test_data.as_ptr(), test_memory as *mut u8, size);

            let first_address = test_memory as usize;
            let second_address = first_address + 32;
            let first = Patch::patch_call(
                first_address,
                dummy as *const (),
                10,
                true,
                ReturnType::None,
            );
            let second = Patch::patch_call(
                second_address,
                dummy as *const (),
                10,
                true,
                ReturnType::None,
            );

            let first_trampoline = first
                .trampoline_address()
                .expect("first patch has no trampoline");
            let second_trampoline = second
                .trampoline_address()
                .expect("second patch has no trampoline");
            assert_eq!(
                align_down(first_trampoline, MmapOptions::page_size()),
                align_down(second_trampoline, MmapOptions::page_size())
            );
            assert_ne!(first_trampoline, second_trampoline);

            let replayed = slice::from_raw_parts(first_trampoline as *const u8, 10);
            assert_eq!(&replayed[..DEAD_BEEF.len()], &DEAD_BEEF);
            assert_eq!(
                slice::from_raw_parts(first_address as *const u8, 4),
                &DEAD_BEEF
            );

            finalize_patches().unwrap();

            assert_eq!(*(first_address as *const u8), NEAR_JUMP);
            assert_eq!(*(second_address as *const u8), NEAR_JUMP);
            VirtualFree(test_memory, 0, MEM_RELEASE).unwrap();
        }
    }
}
