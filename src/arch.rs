use crate::ReturnType;

const CALL_BYTES: [u8; 8] = [0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x08];

// SUB RSP, 0x8 — fixes 16-byte stack alignment when the push count is odd.
const ALIGN_STACK: [u8; 4] = [0x48, 0x83, 0xEC, 0x08];
// ADD RSP, 0x8 — removes the alignment padding.
const UNALIGN_STACK: [u8; 4] = [0x48, 0x83, 0xC4, 0x08];

// PUSH RAX
const SAVE_RAX: [u8; 1] = [0x50];
// MOVDQU [RSP + 0x00], XMM0
const SAVE_XMM0: [u8; 5] = [0xF3, 0x0F, 0x7F, 0x04, 0x24];
const SAVE_REGISTERS: [u8; 44] = [
    // PUSH RCX
    0x51, // PUSH RDX
    0x52, // PUSH R8
    0x41, 0x50, // PUSH R9
    0x41, 0x51, // PUSH R10
    0x41, 0x52, // PUSH R11
    0x41, 0x53, // SUB RSP, 0x60
    0x48, 0x83, 0xEC, 0x60, // MOVDQU [RSP + 0x10], XMM1
    0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x10, // MOVDQU [RSP + 0x20], XMM2
    0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x20, // MOVDQU [RSP + 0x30], XMM3
    0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x30, // MOVDQU [RSP + 0x40], XMM4
    0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x40, // MOVDQU [RSP + 0x50], XMM5
    0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x50,
];

// POP RAX
const LOAD_RAX: [u8; 1] = [0x58];
// MOVDQU XMM0, [RSP + 0x00]
const LOAD_XMM0: [u8; 5] = [0xF3, 0x0F, 0x6F, 0x04, 0x24];
const LOAD_REGISTERS: [u8; 44] = [
    // MOVDQU XMM1, [RSP + 0x10]
    0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // MOVDQU XMM2, [RSP + 0x20]
    0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x20, // MOVDQU XMM3, [RSP + 0x30]
    0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x30, // MOVDQU XMM4, [RSP + 0x40]
    0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x40, // MOVDQU XMM5, [RSP + 0x50]
    0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x50, // ADD RSP, 0x60
    0x48, 0x83, 0xC4, 0x60, // POP R11
    0x41, 0x5B, // POP R10
    0x41, 0x5A, // POP R9
    0x41, 0x59, // POP R8
    0x41, 0x58, // POP RDX
    0x5A, // POP RCX
    0x59,
];

pub(crate) fn build_call(function: *const (), allow_return: ReturnType) -> Vec<u8> {
    let mut code = Vec::new();
    let needs_alignment = allow_return != ReturnType::Rax;

    if needs_alignment {
        code.extend_from_slice(&SAVE_RAX);
    }
    code.extend_from_slice(&SAVE_REGISTERS);
    if needs_alignment {
        code.extend_from_slice(&ALIGN_STACK);
    }
    if allow_return != ReturnType::Xmm0 {
        code.extend_from_slice(&SAVE_XMM0);
    }

    code.extend_from_slice(&CALL_BYTES);
    code.extend_from_slice(&(function as usize).to_le_bytes());

    if allow_return != ReturnType::Xmm0 {
        code.extend_from_slice(&LOAD_XMM0);
    }
    if needs_alignment {
        code.extend_from_slice(&UNALIGN_STACK);
    }
    code.extend_from_slice(&LOAD_REGISTERS);
    if needs_alignment {
        code.extend_from_slice(&LOAD_RAX);
    }

    code
}
