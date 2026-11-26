use std::{ffi::c_void, mem, ptr};

use patchy::{
    CallBridge, Condition, FlagPolicy, KeepReturn, PatchError, PatchSession, StackAlignment,
    Trampoline,
};
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

const REPLAY_BYTES: [u8; 5] = [0x83, 0xc0, 0x02, 0x66, 0x90]; // ADD EAX, 2; NOP

extern "C" fn times_ten(value: u32) -> u32 {
    value.wrapping_mul(10)
}

fn run_replay_hook(replay_first: bool) -> u32 {
    // SAFETY: Only this test uses the private page. The subject sets EAX to 1,
    // adds 2 at the hook site, then adds 1 at the continuation and returns.
    unsafe {
        let subject = allocate_test_page();
        write_code(subject, &[0xb8, 1, 0, 0, 0]); // MOV EAX, 1
        let address = subject + 5;
        write_code(address, &REPLAY_BYTES);
        write_code(address + REPLAY_BYTES.len(), &[0x83, 0xc0, 0x01, 0xc3]);

        let mut session = PatchSession::new();
        session
            .detour_trampoline_with(address, REPLAY_BYTES.len(), |site| {
                let mut code = Trampoline::new();
                if replay_first {
                    site.replay_verbatim(&mut code);
                }
                code.call(CallBridge {
                    callback: times_ten as *const (),
                    incoming_stack: StackAlignment::Offset8,
                    flags: FlagPolicy::Preserve,
                    keep_return: KeepReturn::Rax,
                    before_call: &[0x89, 0xc1], // MOV ECX, EAX
                    after_call: &[],
                });
                if !replay_first {
                    site.replay_verbatim(&mut code);
                }
                site.resume(&mut code);
                Ok(code)
            })
            .unwrap();
        session.install_permanently().unwrap();
        call_u32(subject)
    }
}

#[test]
fn replay_before_call_changes_the_callback_argument() {
    assert_eq!(run_replay_hook(true), 31);
}

#[test]
fn replay_after_call_changes_the_callback_result() {
    assert_eq!(run_replay_hook(false), 13);
}

#[test]
fn a_callback_predicate_can_skip_replay() {
    // SAFETY: The private subject is equivalent to a Windows x64 function
    // taking a u32 in ECX. The detour preserves the entry stack and callback ABI.
    unsafe {
        let subject = allocate_test_page();
        write_code(subject, &[0x89, 0xc8]); // MOV EAX, ECX
        let address = subject + 2;
        write_code(address, &REPLAY_BYTES);
        write_code(address + REPLAY_BYTES.len(), &[0x83, 0xc0, 0x01, 0xc3]);

        let mut session = PatchSession::new();
        session
            .detour_trampoline_with(address, REPLAY_BYTES.len(), |site| {
                let mut code = Trampoline::new();
                let skip = code.new_label();
                code.call(CallBridge {
                    callback: times_ten as *const (),
                    incoming_stack: StackAlignment::Offset8,
                    flags: FlagPolicy::KeepProduced,
                    keep_return: KeepReturn::Neither,
                    before_call: &[],
                    after_call: &[0x84, 0xc0], // TEST AL, AL
                });
                code.jump_if(Condition::NotEqual, skip);
                site.replay_verbatim(&mut code);
                code.bind(skip)?;
                site.resume(&mut code);
                Ok(code)
            })
            .unwrap();
        session.install_permanently().unwrap();
        let function: unsafe extern "C" fn(u32) -> u32 = mem::transmute(subject);
        assert_eq!(function(0), 3);
        assert_eq!(function(7), 8);
    }
}

#[test]
fn replay_uses_the_snapshot_validated_during_installation() {
    // SAFETY: The private page is readable and no thread executes from it.
    unsafe {
        let address = allocate_test_page();
        write_code(address, &RETURN_ONE);
        let mut session = PatchSession::new();
        let patch = session
            .detour_trampoline_with(address, REPLAY_BYTES.len(), |site| {
                write_code(address, &RETURN_TWO);
                let mut code = Trampoline::new();
                site.replay_verbatim(&mut code);
                site.resume(&mut code);
                Ok(code)
            })
            .unwrap();
        let replayed = std::slice::from_raw_parts(
            patch.trampoline_address().unwrap() as *const u8,
            REPLAY_BYTES.len(),
        );
        assert_eq!(replayed, &RETURN_ONE[..REPLAY_BYTES.len()]);
        assert!(matches!(
            session.install_permanently(),
            Err(PatchError::SourceChanged { address: changed }) if changed == address
        ));
    }
}

/// Register state exchanged with the generated subject function. Offsets are
/// hard-coded in the machine code emitted by `subject_code`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Registers {
    rax: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r13: u64,
    flags: u64,
    rsp_before_site: u64,
    rsp_after_site: u64,
    _padding: u64,
    xmm: [u128; 6],
}

fn input_registers() -> Registers {
    Registers {
        rax: 0x1111_1111_1111_1100,
        rcx: 0x2222_2222_2222_2222,
        rdx: 0x3333_3333_3333_3333,
        r8: 0x4444_4444_4444_4444,
        r9: 0x5555_5555_5555_5555,
        r10: 0x6666_6666_6666_6666,
        r11: 0x7777_7777_7777_7777,
        r13: 0x1313_1313_1313_1313,
        xmm: [
            0x0000_0000_0000_0001_0000_0000_0000_0010,
            0x0000_0000_0000_0002_0000_0000_0000_0020,
            0x0000_0000_0000_0003_0000_0000_0000_0030,
            0x0000_0000_0000_0004_0000_0000_0000_0040,
            0x0000_0000_0000_0005_0000_0000_0000_0050,
            0x0000_0000_0000_0006_0000_0000_0000_0060,
        ],
        ..Registers::default()
    }
}

fn mov_rax_imm64(value: u64) -> Vec<u8> {
    let mut code = vec![0x48, 0xb8];
    code.extend_from_slice(&value.to_le_bytes());
    code
}

/// A Windows-x64 callback written in machine code so that it can explicitly
/// store its register arguments into the caller-allocated home slots, record
/// its entry `RSP`, and then clobber every volatile register.
fn callback_code(probe: usize, return_value: u32) -> Vec<u8> {
    let mut code = vec![
        0x48, 0x89, 0x4c, 0x24, 0x08, // MOV [RSP+0x08], RCX
        0x48, 0x89, 0x54, 0x24, 0x10, // MOV [RSP+0x10], RDX
        0x4c, 0x89, 0x44, 0x24, 0x18, // MOV [RSP+0x18], R8
        0x4c, 0x89, 0x4c, 0x24, 0x20, // MOV [RSP+0x20], R9
    ];
    code.extend(mov_rax_imm64(probe as u64));
    code.extend_from_slice(&[0x48, 0x89, 0x20]); // MOV [RAX], RSP
    code.extend_from_slice(&[
        0x66, 0x0f, 0x76, 0xc0, // PCMPEQD XMM0, XMM0
        0x66, 0x0f, 0x76, 0xc9, // PCMPEQD XMM1, XMM1
        0x66, 0x0f, 0x76, 0xd2, // PCMPEQD XMM2, XMM2
        0x66, 0x0f, 0x76, 0xdb, // PCMPEQD XMM3, XMM3
        0x66, 0x0f, 0x76, 0xe4, // PCMPEQD XMM4, XMM4
        0x66, 0x0f, 0x76, 0xed, // PCMPEQD XMM5, XMM5
        0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, // MOV RCX, -1
        0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // MOV RDX, -1
        0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, // MOV R8, -1
        0x49, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, // MOV R9, -1
        0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // MOV R10, -1
        0x49, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff, // MOV R11, -1
        0x4d, 0x31, 0xdb, // XOR R11, R11
        0xb8, // MOV EAX, imm32
    ]);
    code.extend_from_slice(&return_value.to_le_bytes());
    code.push(0xc3); // RET
    code
}

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;
const R11: u8 = 11;
const R13: u8 = 13;
const GPR_OFFSETS: [(u8, u32); 8] = [
    (RAX, 0x00),
    (RCX, 0x08),
    (RDX, 0x10),
    (R8, 0x18),
    (R9, 0x20),
    (R10, 0x28),
    (R11, 0x30),
    (R13, 0x38),
];
const XMM_OFFSET: u32 = 0x60;
const SITE_SIZE: usize = 5;

fn load_gpr(code: &mut Vec<u8>, register: u8, offset: u32) {
    // MOV reg, [RCX+disp32]
    code.extend_from_slice(&[
        0x48 | ((register >> 3) << 2),
        0x8b,
        0x81 | ((register & 7) << 3),
    ]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn store_gpr(code: &mut Vec<u8>, register: u8, offset: u32) {
    // MOV [RBX+disp32], reg
    code.extend_from_slice(&[
        0x48 | ((register >> 3) << 2),
        0x89,
        0x83 | ((register & 7) << 3),
    ]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn load_xmm(code: &mut Vec<u8>, register: u8, offset: u32) {
    // MOVDQU xmm, [RCX+disp32]
    code.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x81 | (register << 3)]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn store_xmm(code: &mut Vec<u8>, register: u8, offset: u32) {
    // MOVDQU [RBX+disp32], xmm
    code.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x83 | (register << 3)]);
    code.extend_from_slice(&offset.to_le_bytes());
}

/// `extern "C" fn(input: *const Registers, output: *mut Registers)`.
///
/// Loads `input` into the volatile registers, runs a five-byte patchable site
/// with `RSP` at the requested alignment and known flags, then stores the
/// resulting state in `output`. Returns the code and the site's offset.
fn subject_code(rsp_offset_at_site: u64) -> (Vec<u8>, usize) {
    let mut code = vec![
        0x53, // PUSH RBX
        0x41, 0x55, // PUSH R13
        0x48, 0x89, 0xd3, // MOV RBX, RDX
    ];
    // Entry RSP is 8 mod 16, and so is RSP after the two pushes.
    if rsp_offset_at_site == 0 {
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x08]); // SUB RSP, 8
    }
    for (register, offset) in GPR_OFFSETS {
        if register != RCX {
            load_gpr(&mut code, register, offset);
        }
    }
    for register in 0..6 {
        load_xmm(&mut code, register, XMM_OFFSET + 16 * u32::from(register));
    }
    load_gpr(&mut code, RCX, 0x08);
    code.extend_from_slice(&[0x48, 0x89, 0x63, 0x48]); // MOV [RBX+0x48], RSP
    code.extend_from_slice(&[0x48, 0x39, 0xe4, 0xf9]); // CMP RSP, RSP; STC

    let site = code.len();
    code.extend_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]); // NOP DWORD [RAX+RAX]

    code.extend_from_slice(&[0x9c, 0x8f, 0x43, 0x40]); // PUSHFQ; POP [RBX+0x40]
    code.extend_from_slice(&[0x48, 0x89, 0x63, 0x50]); // MOV [RBX+0x50], RSP
    for (register, offset) in GPR_OFFSETS {
        store_gpr(&mut code, register, offset);
    }
    for register in 0..6 {
        store_xmm(&mut code, register, XMM_OFFSET + 16 * u32::from(register));
    }
    if rsp_offset_at_site == 0 {
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08]); // ADD RSP, 8
    }
    code.extend_from_slice(&[0x41, 0x5d, 0x5b, 0xc3]); // POP R13; POP RBX; RET
    (code, site)
}

struct SubjectRun {
    output: Registers,
    callback_entry_rsp: u64,
}

/// Patches the subject's site with a bridge through `PatchSession::patch_call`
/// and runs it. The bridge's callback is the machine-code callback above.
fn run_bridge(
    incoming_stack: StackAlignment,
    flags: FlagPolicy,
    keep_return: KeepReturn,
    before_call: &[u8],
    after_call: &[u8],
    callback_return: u32,
) -> SubjectRun {
    const CALLBACK_OFFSET: usize = 0;
    const SUBJECT_OFFSET: usize = 0x200;
    const PROBE_OFFSET: usize = 0x400;

    let rsp_offset_at_site = match incoming_stack {
        StackAlignment::Aligned16 => 0,
        StackAlignment::Offset8 => 8,
    };
    // SAFETY: A private executable page is used only by this test, and every
    // written range lies inside it.
    let (page, subject, site, probe) = unsafe {
        let page = allocate_test_page();
        let (code, site) = subject_code(rsp_offset_at_site);
        write_code(
            page + CALLBACK_OFFSET,
            &callback_code(page + PROBE_OFFSET, callback_return),
        );
        write_code(page + SUBJECT_OFFSET, &code);
        (
            page,
            page + SUBJECT_OFFSET,
            page + SUBJECT_OFFSET + site,
            page + PROBE_OFFSET,
        )
    };

    let mut session = PatchSession::new();
    let bridge = CallBridge {
        callback: (page + CALLBACK_OFFSET) as *const (),
        incoming_stack,
        flags,
        keep_return,
        before_call,
        after_call,
    };
    // SAFETY: The site is a five-byte NOP inside the subject, where RSP has
    // the declared alignment; the callback follows the Windows-x64 ABI.
    unsafe { session.patch_call(site, SITE_SIZE, bridge) }.unwrap();
    // SAFETY: The subject and callback pages remain allocated.
    unsafe { session.install_permanently() }.unwrap();

    let input = input_registers();
    let mut output = Registers::default();
    // SAFETY: The subject follows this signature and preserves non-volatile
    // registers; the callback wrote its entry RSP to the probe slot.
    let callback_entry_rsp = unsafe {
        let function: unsafe extern "C" fn(*const Registers, *mut Registers) =
            mem::transmute(subject);
        function(&input, &mut output);
        (probe as *const u64).read()
    };
    SubjectRun {
        output,
        callback_entry_rsp,
    }
}

const BOTH_ALIGNMENTS: [StackAlignment; 2] = [StackAlignment::Aligned16, StackAlignment::Offset8];
// CF | PF | AF | ZF | SF | OF
const ARITHMETIC_FLAGS: u64 = 0x8d5;
// `CMP RSP, RSP; STC` leaves ZF, PF and CF set.
const INPUT_FLAGS: u64 = 0x45;
const TEST_AL_AL: [u8; 2] = [0x84, 0xc0];
const MOV_R13D_EAX: [u8; 3] = [0x41, 0x89, 0xc5];
const ALL_ONES: u128 = u128::MAX;

fn assert_registers_restored(output: &Registers, except_rax: bool, except_xmm0: bool) {
    let input = input_registers();
    if !except_rax {
        assert_eq!(output.rax, input.rax, "RAX");
    }
    assert_eq!(output.rcx, input.rcx, "RCX");
    assert_eq!(output.rdx, input.rdx, "RDX");
    assert_eq!(output.r8, input.r8, "R8");
    assert_eq!(output.r9, input.r9, "R9");
    assert_eq!(output.r10, input.r10, "R10");
    assert_eq!(output.r11, input.r11, "R11");
    for register in usize::from(except_xmm0)..6 {
        assert_eq!(output.xmm[register], input.xmm[register], "XMM{register}");
    }
}

#[test]
fn callback_home_slot_writes_do_not_corrupt_saved_registers() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(
            stack,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
            &[],
            &[],
            1,
        );

        assert_registers_restored(&run.output, false, false);
    }
}

#[test]
fn callback_is_entered_with_the_stack_aligned_for_a_call() {
    for stack in BOTH_ALIGNMENTS {
        for flags in [FlagPolicy::Preserve, FlagPolicy::KeepProduced] {
            let run = run_bridge(stack, flags, KeepReturn::Neither, &[], &[], 1);

            // The call pushes the return address onto a 16-byte aligned RSP.
            assert_eq!(run.callback_entry_rsp % 16, 8, "{stack:?} {flags:?}");
        }
    }
}

#[test]
fn bridge_leaves_the_stack_pointer_as_it_found_it() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(
            stack,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
            &[],
            &[],
            1,
        );

        assert_eq!(run.output.rsp_after_site, run.output.rsp_before_site);
    }
}

#[test]
fn kept_rax_holds_the_callback_result() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(stack, FlagPolicy::Preserve, KeepReturn::Rax, &[], &[], 42);

        assert_eq!(run.output.rax, 42);
        assert_registers_restored(&run.output, true, false);
    }
}

#[test]
fn kept_xmm0_holds_the_callback_result() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(stack, FlagPolicy::Preserve, KeepReturn::Xmm0, &[], &[], 1);

        assert_eq!(run.output.xmm[0], ALL_ONES);
        assert_registers_restored(&run.output, false, true);
    }
}

#[test]
fn preserved_flags_are_the_incoming_flags() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(
            stack,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
            &[],
            &[],
            1,
        );

        assert_eq!(run.output.flags & ARITHMETIC_FLAGS, INPUT_FLAGS);
    }
}

#[test]
fn predicate_flags_survive_restoring_rax() {
    for stack in BOTH_ALIGNMENTS {
        // The callback returns AL = 1, while the incoming RAX has AL = 0, so
        // ZF is clear only if `TEST AL, AL` saw the callback's result.
        let run = run_bridge(
            stack,
            FlagPolicy::KeepProduced,
            KeepReturn::Neither,
            &[],
            &TEST_AL_AL,
            1,
        );

        assert_eq!(run.output.flags & ARITHMETIC_FLAGS & 0x40, 0, "ZF");
        assert_eq!(run.output.rax, input_registers().rax);
    }
}

#[test]
fn post_call_store_keeps_original_rax_and_flags() {
    for stack in BOTH_ALIGNMENTS {
        let run = run_bridge(
            stack,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
            &[],
            &MOV_R13D_EAX,
            7,
        );

        assert_eq!(run.output.r13, 7);
        assert_eq!(run.output.rax, input_registers().rax);
        assert_eq!(run.output.flags & ARITHMETIC_FLAGS, INPUT_FLAGS);
    }
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
                5,
                CallBridge {
                    callback: return_42 as *const (),
                    incoming_stack: StackAlignment::Aligned16,
                    flags: FlagPolicy::Preserve,
                    keep_return: KeepReturn::Rax,
                    before_call: &[],
                    after_call: &[],
                },
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
