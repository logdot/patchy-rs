//! The single machine-code generator behind every callback call site.

/// The alignment of `RSP` when control reaches the first byte of a bridge.
///
/// This describes the stack after any instructions that run before the bridge,
/// such as replayed overwritten instructions, have executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackAlignment {
    /// `RSP` is a multiple of 16, as inside the body of a function after its
    /// prologue.
    Aligned16,
    /// `RSP` is 8 more than a multiple of 16, as at a function's first
    /// instruction when the return address has just been pushed.
    Offset8,
}

/// What a bridge does with the flags register.
///
/// The call itself and the register restoration are free to change flags; this
/// selects what the instruction after the bridge observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagPolicy {
    /// Save the incoming flags first and restore them last. Flags produced by
    /// the callback or by [`CallBridge::after_call`] are discarded.
    Preserve,
    /// Leave the flags as they are once [`CallBridge::after_call`] has run.
    /// The restoration code never modifies flags, so a predicate such as
    /// `TEST AL, AL` in `after_call` can steer a following conditional jump.
    ///
    /// With an empty `after_call` the flags are whatever the callback happened
    /// to leave, which is unspecified. Choose [`FlagPolicy::Preserve`] unless
    /// the following code consumes flags that `after_call` produced.
    KeepProduced,
}

/// Which callback return register the bridge leaves unrestored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepReturn {
    /// Restore `RAX` and `XMM0`, discarding the callback's result.
    Neither,
    /// Leave the callback's result in `RAX`; restore `XMM0`.
    Rax,
    /// Leave the callback's result in `XMM0`; restore `RAX`.
    Xmm0,
}

/// A Windows-x64 call to `callback` surrounded by register preservation.
///
/// The bridge saves the volatile general-purpose registers `RAX`, `RCX`, `RDX`,
/// `R8`, `R9`, `R10` and `R11`, and the low 128 bits of `XMM0` through `XMM5`.
/// It allocates the 32-byte shadow space the callee may use as its home slots
/// and pads the stack so that `RSP` is 16-byte aligned at the call.
///
/// The callback must not take stack-passed arguments. The bridge uses the
/// stack slots beyond shadow space to save registers, not to pass arguments.
///
/// It does not save or restore non-volatile registers, `XMM6` and above, the
/// upper halves of the `YMM` registers, `MXCSR`, the x87 state or the
/// direction flag. The callback must follow the Windows-x64 ABI so that the
/// ones it must preserve are preserved, and the direction flag must be clear
/// when the bridge is entered.
///
/// Control flows through the bridge in this order:
///
/// 1. the incoming flags are saved when [`FlagPolicy::Preserve`] is selected;
/// 2. the volatile registers are saved;
/// 3. [`before_call`](Self::before_call) runs;
/// 4. the callback is called;
/// 5. [`after_call`](Self::after_call) runs, seeing the callback's results;
/// 6. the registers are restored, except those selected by
///    [`keep_return`](Self::keep_return);
/// 7. the flags are restored when [`FlagPolicy::Preserve`] is selected.
///
/// # Safety requirements for the byte slices
///
/// Both slices are copied verbatim and must be straight-line code. They are
/// not relocated, so they must not contain relative branches or calls that
/// leave the slice, RIP-relative operands, or any other position-dependent
/// encoding. Every path through a slice must fall through to its end with
/// `RSP` unchanged, so they must not push, pop or otherwise move `RSP`. They
/// must not return, jump away, or fault.
///
/// The saved registers are still live while `before_call` runs, so it may read
/// the original arguments and overwrite volatile registers to set up callback
/// arguments. `after_call` may read `RAX` and `XMM0` as returned by the
/// callback and may overwrite volatile registers freely, since they are
/// restored afterwards. Either slice may deliberately write a non-volatile
/// register, which the bridge never restores.
#[derive(Clone, Copy, Debug)]
pub struct CallBridge<'a> {
    /// The Windows-x64 function to call.
    pub callback: *const (),
    /// The alignment of `RSP` when the bridge is entered.
    pub incoming_stack: StackAlignment,
    /// What the bridge does with the flags register.
    pub flags: FlagPolicy,
    /// The callback return register that is not restored.
    pub keep_return: KeepReturn,
    /// Code that runs after the registers are saved, immediately before the
    /// call.
    pub before_call: &'a [u8],
    /// Code that runs immediately after the call, before registers are
    /// restored.
    pub after_call: &'a [u8],
}

const PUSHFQ: u8 = 0x9c;
const POPFQ: u8 = 0x9d;
const SAVED_GPR_COUNT: usize = 7;
const SHADOW_SPACE: u32 = 0x20;
const XMM_SAVE_SIZE: u32 = 0x60;

// PUSH RAX, RCX, RDX, R8, R9, R10, R11.
const SAVE_GPRS: [u8; 11] = [
    0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
];
// POP R11, R10, R9, R8, RDX, RCX.
const RESTORE_GPRS_EXCEPT_RAX: [u8; 10] =
    [0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59];
// CALL [RIP+2]; JMP +8; <8-byte callback address>.
const CALL_ABSOLUTE: [u8; 8] = [0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x08];

/// Appends the machine code for `bridge` to `code`.
pub(crate) fn emit_call_bridge(code: &mut Vec<u8>, bridge: &CallBridge<'_>) {
    let preserve_flags = bridge.flags == FlagPolicy::Preserve;
    let entry_offset = match bridge.incoming_stack {
        StackAlignment::Aligned16 => 0,
        StackAlignment::Offset8 => 8,
    };
    let pushes = SAVED_GPR_COUNT + usize::from(preserve_flags);
    let padding = ((entry_offset + 8 * pushes) % 16) as u32;
    // The shadow space is the lowest part of the frame, directly above the
    // return address the call pushes, so the callee's home-slot stores cannot
    // reach the saved XMM registers above it.
    let frame_size = SHADOW_SPACE + XMM_SAVE_SIZE + padding;
    let xmm_slot = |register: u8| SHADOW_SPACE as u8 + 16 * register;

    if preserve_flags {
        code.push(PUSHFQ);
    }
    code.extend_from_slice(&SAVE_GPRS);
    // SUB RSP, imm32
    code.extend_from_slice(&[0x48, 0x81, 0xec]);
    code.extend_from_slice(&frame_size.to_le_bytes());
    for register in 0..6 {
        // MOVDQU [RSP+disp8], XMMn
        code.extend_from_slice(&[
            0xf3,
            0x0f,
            0x7f,
            0x44 | (register << 3),
            0x24,
            xmm_slot(register),
        ]);
    }

    code.extend_from_slice(bridge.before_call);
    code.extend_from_slice(&CALL_ABSOLUTE);
    code.extend_from_slice(&(bridge.callback as usize).to_le_bytes());
    code.extend_from_slice(bridge.after_call);

    let first_restored_xmm = u8::from(bridge.keep_return == KeepReturn::Xmm0);
    for register in first_restored_xmm..6 {
        // MOVDQU XMMn, [RSP+disp8]
        code.extend_from_slice(&[
            0xf3,
            0x0f,
            0x6f,
            0x44 | (register << 3),
            0x24,
            xmm_slot(register),
        ]);
    }
    // LEA, unlike ADD, leaves the flags untouched.
    code.extend_from_slice(&[0x48, 0x8d, 0xa4, 0x24]); // LEA RSP, [RSP+imm32]
    code.extend_from_slice(&frame_size.to_le_bytes());
    code.extend_from_slice(&RESTORE_GPRS_EXCEPT_RAX);
    if bridge.keep_return == KeepReturn::Rax {
        code.extend_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0x08]); // LEA RSP, [RSP+8]
    } else {
        code.push(0x58); // POP RAX
    }
    if preserve_flags {
        code.push(POPFQ);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(
        incoming_stack: StackAlignment,
        flags: FlagPolicy,
        keep_return: KeepReturn,
    ) -> CallBridge<'static> {
        CallBridge {
            callback: 0x1_4000_1000usize as *const (),
            incoming_stack,
            flags,
            keep_return,
            before_call: &[0x90],
            after_call: &[0x84, 0xc0],
        }
    }

    fn emit(bridge: &CallBridge<'_>) -> Vec<u8> {
        let mut code = Vec::new();
        emit_call_bridge(&mut code, bridge);
        code
    }

    fn sub_rsp_immediate(code: &[u8]) -> u32 {
        let at = code
            .windows(3)
            .position(|w| w == [0x48, 0x81, 0xec])
            .unwrap();
        u32::from_le_bytes(code[at + 3..at + 7].try_into().unwrap())
    }

    #[test]
    fn stack_is_aligned_at_the_call_for_every_entry_alignment_and_flag_policy() {
        for (stack, entry_offset) in [(StackAlignment::Aligned16, 0), (StackAlignment::Offset8, 8)]
        {
            for flags in [FlagPolicy::Preserve, FlagPolicy::KeepProduced] {
                let code = emit(&bridge(stack, flags, KeepReturn::Neither));
                let pushes = 7 + usize::from(flags == FlagPolicy::Preserve);
                // RSP at the call is the entry RSP minus everything pushed or
                // allocated, so it is a multiple of 16 exactly when that
                // total has the same remainder as the entry RSP.
                let consumed = 8 * pushes + sub_rsp_immediate(&code) as usize;
                assert_eq!(consumed % 16, entry_offset, "{stack:?} {flags:?}");
            }
        }
    }

    #[test]
    fn shadow_space_lies_below_every_saved_xmm_register() {
        let code = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
        ));

        // MOVDQU [RSP+0x20], XMM0 is the lowest save slot.
        assert!(
            code.windows(6)
                .any(|w| w == [0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x20])
        );
        assert!(
            !code
                .windows(6)
                .any(|w| w[..5] == [0xf3, 0x0f, 0x7f, 0x44, 0x24] && w[5] < 0x20)
        );
    }

    #[test]
    fn flags_are_saved_first_and_restored_last_only_when_preserved() {
        let preserved = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::Preserve,
            KeepReturn::Neither,
        ));
        assert_eq!(preserved[0], PUSHFQ);
        assert_eq!(preserved.last(), Some(&POPFQ));

        let kept = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::KeepProduced,
            KeepReturn::Neither,
        ));
        assert!(!kept.contains(&PUSHFQ));
        assert_ne!(kept.last(), Some(&POPFQ));
    }

    #[test]
    fn kept_return_registers_are_not_restored() {
        let restore_xmm0 = [0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x20];
        let discard_rax = [0x48, 0x8d, 0x64, 0x24, 0x08];
        let restores_xmm0 = |code: &[u8]| code.windows(6).any(|w| w == restore_xmm0);
        let discards_rax = |code: &[u8]| code.windows(5).any(|w| w == discard_rax);

        let neither = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::KeepProduced,
            KeepReturn::Neither,
        ));
        assert!(restores_xmm0(&neither) && !discards_rax(&neither) && neither.ends_with(&[0x58]));

        let rax = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::KeepProduced,
            KeepReturn::Rax,
        ));
        assert!(restores_xmm0(&rax) && discards_rax(&rax));

        let xmm0 = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::KeepProduced,
            KeepReturn::Xmm0,
        ));
        assert!(!restores_xmm0(&xmm0) && !discards_rax(&xmm0) && xmm0.ends_with(&[0x58]));
    }

    #[test]
    fn byte_slices_surround_the_call_verbatim() {
        let code = emit(&bridge(
            StackAlignment::Aligned16,
            FlagPolicy::KeepProduced,
            KeepReturn::Neither,
        ));
        let call = code.windows(8).position(|w| w == CALL_ABSOLUTE).unwrap();
        let before = code
            .windows(7)
            .position(|w| w[6] == 0x90 && w[..6] == [0xf3, 0x0f, 0x7f, 0x6c, 0x24, 0x70])
            .unwrap();

        assert_eq!(before + 6, call - 1);
        assert_eq!(&code[call + 16..call + 18], [0x84, 0xc0]);
    }
}
