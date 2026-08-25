use std::{ffi::c_void, mem, ptr};

use patchy::{PatchError, PatchSession, ReturnType};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
    Threading::GetCurrentProcess,
};

const PAGE_SIZE: usize = 4096;
const RETURN_ONE: [u8; 6] = [0xB8, 1, 0, 0, 0, 0xC3];
const RETURN_TWO: [u8; 6] = [0xB8, 2, 0, 0, 0, 0xC3];
const RETURN_THREE: [u8; 6] = [0xB8, 3, 0, 0, 0, 0xC3];
const RETURN_FOUR: [u8; 6] = [0xB8, 4, 0, 0, 0, 0xC3];
const RETURN_FIVE: [u8; 6] = [0xB8, 5, 0, 0, 0, 0xC3];
const RETURN_SIX: [u8; 6] = [0xB8, 6, 0, 0, 0, 0xC3];
const RETURN_SEVEN: [u8; 6] = [0xB8, 7, 0, 0, 0, 0xC3];
const RETURN_EIGHT: [u8; 6] = [0xB8, 8, 0, 0, 0, 0xC3];

extern "C" fn return_42() -> u32 {
    42
}

unsafe fn allocate_test_page() -> usize {
    // SAFETY: A new private page is requested from the current process.
    let page = unsafe {
        VirtualAlloc(
            None,
            PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    assert!(!page.is_null(), "VirtualAlloc failed");
    page as usize
}

unsafe fn write_code(address: usize, code: &[u8]) {
    // SAFETY: Test addresses come from the writable page allocated above.
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), address as *mut u8, code.len()) };
    // SAFETY: The pseudo-handle and allocated source range are valid.
    unsafe {
        FlushInstructionCache(
            GetCurrentProcess(),
            Some(address as *const c_void),
            code.len(),
        )
    }
    .expect("FlushInstructionCache failed");
}

unsafe fn call_u32(address: usize) -> u32 {
    // SAFETY: Each test function contains `MOV EAX, imm32; RET` before it is
    // called, or a Patchy trampoline that eventually returns to that `RET`.
    let function: unsafe extern "C" fn() -> u32 = unsafe { mem::transmute(address) };
    // SAFETY: The generated function uses the declared signature.
    unsafe { function() }
}

#[test]
fn sessions_prepare_install_and_remain_permanent() {
    unsafe {
        let page = allocate_test_page();
        let overwrite_address = page;
        let call_address = page + 64;
        let dropped_address = page + 128;
        let changed_address = page + 192;

        write_code(overwrite_address, &RETURN_ONE);
        write_code(call_address, &RETURN_SEVEN);
        write_code(dropped_address, &RETURN_FOUR);
        write_code(changed_address, &RETURN_SIX);

        let mut session = PatchSession::new();
        session.overwrite(overwrite_address, &RETURN_TWO).unwrap();
        let callback_patch = session
            .patch_call(
                call_address,
                return_42 as *const (),
                5,
                false,
                ReturnType::Rax,
            )
            .unwrap();
        assert!(callback_patch.trampoline_address().is_some());

        // Preparation alone must not modify either source function.
        assert_eq!(call_u32(overwrite_address), 1);
        assert_eq!(call_u32(call_address), 7);

        session.install_permanently().unwrap();
        assert_eq!(call_u32(overwrite_address), 2);
        assert_eq!(call_u32(call_address), 42);

        // A later permanent session may not replace an installed range.
        let mut overlapping = PatchSession::new();
        overlapping
            .overwrite(overwrite_address, &RETURN_THREE)
            .unwrap();
        assert!(matches!(
            overlapping.install_permanently(),
            Err(PatchError::OverlappingPatch { .. })
        ));
        assert_eq!(call_u32(overwrite_address), 2);

        // Dropping preparation state leaves its source untouched.
        let mut dropped = PatchSession::new();
        dropped.overwrite(dropped_address, &RETURN_FIVE).unwrap();
        drop(dropped);
        assert_eq!(call_u32(dropped_address), 4);

        // Installation rejects a source modified after preparation.
        let mut changed = PatchSession::new();
        changed.overwrite(changed_address, &RETURN_SEVEN).unwrap();
        write_code(changed_address, &RETURN_EIGHT);
        assert!(matches!(
            changed.install_permanently(),
            Err(PatchError::SourceChanged { address }) if address == changed_address
        ));
        assert_eq!(call_u32(changed_address), 8);

        // The page is intentionally not freed: permanently installed source
        // ranges and trampolines must remain allocated until process exit.
    }
}
