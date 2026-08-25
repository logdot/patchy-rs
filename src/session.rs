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

/// A batch of runtime patches being prepared for permanent installation.
///
/// Dropping a session before installation discards its patches and releases
/// its writable trampoline allocations without modifying the target process.
#[derive(Default)]
pub struct PatchSession {
    pages: Vec<MutableCodePage>,
    pub(crate) pending: Vec<PendingPatch>,
}

struct MutableCodePage {
    mapping: MmapMut,
    used: usize,
}

pub(crate) struct PendingPatch {
    pub(crate) address: usize,
    pub(crate) expected: Vec<u8>,
    pub(crate) replacement: Vec<u8>,
}

#[derive(Clone, Copy)]
struct InstalledPatch {
    address: usize,
    size: usize,
}

struct PermanentPatchSet {
    _pages: Vec<Mmap>,
    patches: Vec<InstalledPatch>,
}

static PERMANENT_PATCH_SETS: OnceLock<Mutex<Vec<PermanentPatchSet>>> = OnceLock::new();

fn permanent_patch_sets() -> MutexGuard<'static, Vec<PermanentPatchSet>> {
    PERMANENT_PATCH_SETS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl PatchSession {
    /// Creates an empty patch preparation session.
    pub fn new() -> Self {
        Self::default()
    }

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
            unsafe { slice::from_raw_parts(patch.address as *const u8, patch.expected.len()) };
        if current != patch.expected {
            return Err(PatchError::SourceChanged {
                address: patch.address,
            });
        }
    }

    Ok(())
}

fn ensure_patches_do_not_overlap_installed(
    installed_sets: &[PermanentPatchSet],
    pending: &[PendingPatch],
) -> Result<(), PatchError> {
    for patch in pending {
        let patch_end = patch
            .address
            .checked_add(patch.replacement.len())
            .ok_or(PatchError::AddressOverflow)?;
        for installed in installed_sets
            .iter()
            .flat_map(|patch_set| &patch_set.patches)
        {
            let installed_end = installed
                .address
                .checked_add(installed.size)
                .ok_or(PatchError::AddressOverflow)?;
            if patch.address < installed_end && installed.address < patch_end {
                return Err(PatchError::OverlappingPatch {
                    first: installed.address,
                    second: patch.address,
                });
            }
        }
    }

    Ok(())
}

impl PatchSession {
    /// Seals this session's trampoline pages and installs every prepared patch.
    ///
    /// Installation is permanent: the source modifications and executable
    /// trampoline allocations remain live until the process exits. A library
    /// containing any callback or destination referenced by these patches must
    /// therefore remain loaded for the same duration.
    ///
    /// # Safety
    ///
    /// No other thread may execute a patch source while its instructions are
    /// being replaced. Every source range and prepared trampoline must still
    /// satisfy the requirements documented by the corresponding patch
    /// preparation operation.
    pub unsafe fn install_permanently(self) -> Result<(), PatchError> {
        let Self { pages, pending } = self;
        let mut executable_pages = Vec::with_capacity(pages.len());
        for page in pages {
            match page.mapping.make_exec() {
                Ok(mapping) => executable_pages.push(mapping),
                Err((_mapping, error)) => return Err(PatchError::Mapping(error.to_string())),
            }
        }

        // SAFETY: The pseudo-handle is valid in the current process.
        let process = unsafe { GetCurrentProcess() };
        for page in &executable_pages {
            // SAFETY: Every page is a live executable mapping in this process.
            unsafe {
                FlushInstructionCache(process, Some(page.as_ptr() as *const c_void), page.len())
            }
            .map_err(|error| PatchError::InstructionCache {
                address: page.as_ptr() as usize,
                error: error.to_string(),
            })?;
        }

        let mut installed_sets = permanent_patch_sets();
        ensure_patches_do_not_overlap_installed(&installed_sets, &pending)?;

        // SAFETY: The caller guarantees all prepared sources remain readable.
        unsafe { validate_patch_sources(&pending)? };
        // SAFETY: The caller guarantees the source ranges may be modified.
        let protections = unsafe { protect_patch_sources(&pending)? };
        // SAFETY: Revalidate after changing protections to narrow the race
        // window.
        if let Err(error) = unsafe { validate_patch_sources(&pending) } {
            // SAFETY: `protections` records each changed source page.
            unsafe { restore_patch_sources(&protections)? };
            return Err(error);
        }

        let page_count = executable_pages.len();
        let patch_count = pending.len();
        installed_sets.push(PermanentPatchSet {
            _pages: executable_pages,
            patches: pending
                .iter()
                .map(|patch| InstalledPatch {
                    address: patch.address,
                    size: patch.replacement.len(),
                })
                .collect(),
        });

        for patch in &pending {
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

        let instruction_cache_result = pending.iter().try_for_each(|patch| {
            // SAFETY: The replacement range is live executable memory in this
            // process.
            unsafe {
                FlushInstructionCache(
                    process,
                    Some(patch.address as *const c_void),
                    patch.replacement.len(),
                )
            }
            .map_err(|error| PatchError::InstructionCache {
                address: patch.address,
                error: error.to_string(),
            })
        });
        // SAFETY: `protections` records each changed source page.
        let protection_result = unsafe { restore_patch_sources(&protections) };
        instruction_cache_result?;
        protection_result?;

        log::info!(
            "Installed {patch_count} permanent patch(es) using {page_count} shared trampoline page(s)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReturnType, relative_jump::NEAR_JUMP};
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
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
            let mut session = PatchSession::new();
            let first = session
                .patch_call(
                    first_address,
                    dummy as *const (),
                    10,
                    true,
                    ReturnType::None,
                )
                .unwrap();
            let second = session
                .patch_call(
                    second_address,
                    dummy as *const (),
                    10,
                    true,
                    ReturnType::None,
                )
                .unwrap();

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

            session.install_permanently().unwrap();

            assert_eq!(*(first_address as *const u8), NEAR_JUMP);
            assert_eq!(*(second_address as *const u8), NEAR_JUMP);
        }
    }
}
