use crate::{
    CallBridge, FlagPolicy, KeepReturn, PatchError, ReturnType, StackAlignment, TrampolineFixup,
    TrampolinePlan, bridge::emit_call_bridge, relative_offset,
};

/// An internal destination in a [`Trampoline`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(usize);

/// An x86 condition used by a near conditional jump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Condition {
    /// Overflow flag set.
    Overflow = 0x80,
    /// Overflow flag clear.
    NotOverflow = 0x81,
    /// Unsigned below.
    Below = 0x82,
    /// Unsigned above or equal.
    AboveOrEqual = 0x83,
    /// Equal or zero.
    Equal = 0x84,
    /// Not equal or not zero.
    NotEqual = 0x85,
    /// Unsigned below or equal.
    BelowOrEqual = 0x86,
    /// Unsigned above.
    Above = 0x87,
    /// Sign flag set.
    Sign = 0x88,
    /// Sign flag clear.
    NotSign = 0x89,
    /// Parity flag set.
    Parity = 0x8A,
    /// Parity flag clear.
    NotParity = 0x8B,
    /// Signed less.
    Less = 0x8C,
    /// Signed greater or equal.
    GreaterOrEqual = 0x8D,
    /// Signed less or equal.
    LessOrEqual = 0x8E,
    /// Signed greater.
    Greater = 0x8F,
}

#[derive(Clone, Copy)]
enum Target {
    Address(usize),
    Label(Label),
    Resume,
}

#[derive(Clone, Copy)]
struct RelativeFixup {
    displacement_offset: usize,
    next_instruction_offset: usize,
    target: Target,
}

/// The source span associated with a detour builder.
///
/// These helpers record where to replay and resume. They do not need to read
/// the source or know where the trampoline will be placed.
pub struct DetourSite {
    size: usize,
}

impl DetourSite {
    /// Creates a builder site for a source span of `size` bytes. That size must
    /// match the detour that will use this trampoline.
    pub const fn new(size: usize) -> Self {
        Self { size }
    }

    /// Inserts the captured source bytes at this point in the trampoline.
    ///
    /// The installer supplies the same snapshot it validates before writing.
    /// The bytes are replayed without decoding or relocation.
    ///
    /// # Safety
    ///
    /// The span must contain whole instructions that still work at their new
    /// address and in the machine state where the replay runs. For example,
    /// relative branches, calls, or RIP-relative operands addressing something
    /// outside the span generally cannot be replayed verbatim.
    pub unsafe fn replay_verbatim(&self, trampoline: &mut Trampoline) {
        if self.size == 0 {
            return;
        }
        let start = trampoline.code.len();
        let end = start
            .checked_add(self.size)
            .expect("trampoline size overflow");
        trampoline.code.resize(end, 0);
        trampoline.replay_ranges.push(start..end);
    }

    /// Appends a jump to the first byte after the overwritten span.
    pub fn resume(&self, trampoline: &mut Trampoline) {
        trampoline.code.push(0xe9);
        trampoline.push_relative_fixup(Target::Resume);
    }
}

/// A fixed-size x86-64 trampoline with address-dependent branch fixups.
#[derive(Clone, Default)]
pub struct Trampoline {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    relative_fixups: Vec<RelativeFixup>,
    replay_ranges: Vec<std::ops::Range<usize>>,
}

impl Trampoline {
    /// Creates an empty trampoline.
    pub const fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: Vec::new(),
            relative_fixups: Vec::new(),
            replay_ranges: Vec::new(),
        }
    }

    /// Returns the trampoline's encoded size.
    pub fn len(&self) -> usize {
        self.code.len()
    }

    /// Returns whether the trampoline contains no instructions.
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    /// Appends machine-code bytes without interpreting them.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.code.extend_from_slice(bytes);
        self
    }

    /// Creates an unbound internal label.
    pub fn new_label(&mut self) -> Label {
        let label = Label(self.labels.len());
        self.labels.push(None);
        label
    }

    /// Binds `label` to the current end of the trampoline.
    pub fn bind(&mut self, label: Label) -> Result<&mut Self, PatchError> {
        let Some(position) = self.labels.get_mut(label.0) else {
            return Err(PatchError::InvalidLabel { label: label.0 });
        };
        if position.is_some() {
            return Err(PatchError::LabelAlreadyBound { label: label.0 });
        }

        *position = Some(self.code.len());
        Ok(self)
    }

    /// Appends an address-independent absolute call.
    pub fn absolute_call(&mut self, function: *const ()) -> &mut Self {
        // CALL [RIP+2]; JMP +8; <8-byte function pointer>
        self.code
            .extend_from_slice(&[0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08]);
        self.code
            .extend_from_slice(&(function as usize).to_le_bytes());
        self
    }

    /// Appends an address-independent absolute jump.
    pub fn absolute_jump(&mut self, destination: usize) -> &mut Self {
        // JMP [RIP]; <8-byte destination pointer>
        self.code
            .extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        self.code.extend_from_slice(&destination.to_le_bytes());
        self
    }

    /// Appends a five-byte relative jump to an absolute runtime address.
    pub fn relative_jump(&mut self, destination: usize) -> &mut Self {
        self.code.push(0xE9);
        self.push_relative_fixup(Target::Address(destination));
        self
    }

    /// Appends a five-byte relative jump to an internal label.
    pub fn jump_to(&mut self, label: Label) -> &mut Self {
        self.code.push(0xE9);
        self.push_relative_fixup(Target::Label(label));
        self
    }

    /// Appends a six-byte near conditional jump to an internal label.
    pub fn jump_if(&mut self, condition: Condition, label: Label) -> &mut Self {
        self.code.extend_from_slice(&[0x0F, condition as u8]);
        self.push_relative_fixup(Target::Label(label));
        self
    }

    /// Appends a call to `bridge.callback` with volatile registers preserved.
    ///
    /// See [`CallBridge`] for the registers saved, the stack and flag
    /// semantics, and the requirements on its byte slices.
    ///
    /// # Safety
    ///
    /// The bridge's `incoming_stack` must describe `RSP` where this code is
    /// placed, after every instruction that precedes it in the trampoline. The
    /// callback must follow the Windows-x64 ABI and must not take stack-passed
    /// arguments. The `before_call` and `after_call` bytes must satisfy the
    /// requirements documented on [`CallBridge`].
    pub unsafe fn call(&mut self, bridge: CallBridge<'_>) -> &mut Self {
        emit_call_bridge(&mut self.code, &bridge);
        self
    }

    /// Calls a function while preserving volatile Windows-x64 registers.
    ///
    /// This is the form used by the C ABI. It is equivalent to [`call`] with
    /// a 16-byte aligned incoming stack and [`FlagPolicy::KeepProduced`]:
    /// `argument_setup` is `before_call`, `result_handling` is `after_call`,
    /// and `allow_return` selects the kept return register. The callback must
    /// not take stack-passed arguments.
    ///
    /// [`call`]: Self::call
    pub fn preserved_call(
        &mut self,
        function: *const (),
        argument_setup: &[u8],
        result_handling: &[u8],
        allow_return: ReturnType,
    ) -> &mut Self {
        let keep_return = match allow_return {
            ReturnType::None => KeepReturn::Neither,
            ReturnType::Rax => KeepReturn::Rax,
            ReturnType::Xmm0 => KeepReturn::Xmm0,
        };
        // SAFETY: The method's callers already promise what `call` requires:
        // an aligned incoming stack and straight-line byte sequences.
        unsafe {
            self.call(CallBridge {
                callback: function,
                incoming_stack: StackAlignment::Aligned16,
                flags: FlagPolicy::KeepProduced,
                keep_return,
                before_call: argument_setup,
                after_call: result_handling,
            })
        }
    }

    /// Builds a trampoline that does not use site-relative replay or resume.
    /// For a site-dependent trampoline, use [`Self::into_plan`] instead.
    pub fn build(&self, address: usize) -> Result<Vec<u8>, PatchError> {
        self.clone().into_plan()?.build(address)
    }

    /// Resolves internal labels and produces a plan for the installer.
    pub fn into_plan(self) -> Result<TrampolinePlan, PatchError> {
        let mut code = self.code;
        let mut fixups = Vec::with_capacity(self.replay_ranges.len() + self.relative_fixups.len());
        fixups.extend(
            self.replay_ranges
                .into_iter()
                .map(|range| TrampolineFixup::Replay {
                    offset: range.start,
                    size: range.len(),
                }),
        );
        for fixup in self.relative_fixups {
            let offset = fixup.displacement_offset;
            match fixup.target {
                Target::Address(destination) => {
                    fixups.push(TrampolineFixup::Relative {
                        offset,
                        destination,
                    });
                }
                Target::Resume => fixups.push(TrampolineFixup::Resume { offset }),
                Target::Label(label) => {
                    let Some(position) = self.labels.get(label.0) else {
                        return Err(PatchError::InvalidLabel { label: label.0 });
                    };
                    let position = position.ok_or(PatchError::UnboundLabel { label: label.0 })?;
                    let displacement = relative_offset(fixup.next_instruction_offset, position)?;
                    code[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
                }
            }
        }

        TrampolinePlan::new(code, fixups)
    }

    fn push_relative_fixup(&mut self, target: Target) {
        let displacement_offset = self.code.len();
        self.code.extend_from_slice(&[0; 4]);
        self.relative_fixups.push(RelativeFixup {
            displacement_offset,
            next_instruction_offset: self.code.len(),
            target,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_plan_resolves_replay_and_resume_at_placement() {
        let site = DetourSite::new(5);
        let mut trampoline = Trampoline::new();
        let skip = trampoline.new_label();
        trampoline.jump_if(Condition::Equal, skip);
        // SAFETY: The test supplies relocatable NOP instructions and never executes them.
        unsafe { site.replay_verbatim(&mut trampoline) };
        trampoline.bind(skip).unwrap();
        site.resume(&mut trampoline);

        assert_eq!(trampoline.len(), 16);
        let plan = trampoline.into_plan().unwrap();
        let (template, fixups) = plan.parts();
        let plan = TrampolinePlan::new(template.to_vec(), fixups.to_vec()).unwrap();
        let original = [0x90; 5];
        for address in [0x1000, 0x2000] {
            let code = plan.build_for_site(address, &original, 0x3005).unwrap();
            assert_eq!(&code[2..6], &5i32.to_le_bytes());
            assert_eq!(&code[6..11], &original);
            assert_eq!(
                &code[12..16],
                &((0x3005 - address - 16) as i32).to_le_bytes()
            );
        }
    }

    #[test]
    fn a_site_plan_cannot_be_built_without_its_site() {
        let mut trampoline = Trampoline::new();
        DetourSite::new(5).resume(&mut trampoline);
        assert!(matches!(
            trampoline.build(0x1000),
            Err(PatchError::MissingDetourSite)
        ));
    }

    #[test]
    fn internal_and_external_jumps_are_fixed_up() {
        let mut trampoline = Trampoline::new();
        let destination = trampoline.new_label();
        trampoline.jump_if(Condition::NotEqual, destination);
        trampoline.bytes(&[0x90; 3]);
        trampoline.bind(destination).unwrap();
        trampoline.relative_jump(0x180001000);

        let code = trampoline.build(0x180000000).unwrap();
        assert_eq!(i32::from_le_bytes(code[2..6].try_into().unwrap()), 3);
        assert_eq!(
            i32::from_le_bytes(code[10..14].try_into().unwrap()),
            0x1000 - 14
        );
    }

    #[test]
    fn unbound_labels_are_rejected() {
        let mut trampoline = Trampoline::new();
        let destination = trampoline.new_label();
        trampoline.jump_to(destination);

        assert!(matches!(
            trampoline.build(0x180000000),
            Err(PatchError::UnboundLabel { .. })
        ));
    }

    #[test]
    fn predicate_call_preserves_all_volatile_registers() {
        let mut trampoline = Trampoline::new();
        let returned_true = trampoline.new_label();
        trampoline.preserved_call(
            0x140001000usize as *const (),
            &[0x48, 0x89, 0xF9],
            &[0x84, 0xC0],
            ReturnType::None,
        );
        trampoline.jump_if(Condition::NotEqual, returned_true);
        trampoline.bind(returned_true).unwrap();

        let code = trampoline.build(0x180000000).unwrap();
        assert!(code.starts_with(&[0x50, 0x51, 0x52, 0x41, 0x50]));
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0xF3, 0x0F, 0x7F, 0x44, 0x24, 0x20])
        );
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x70])
        );
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0xF3, 0x0F, 0x6F, 0x44, 0x24, 0x20])
        );
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x70])
        );
        assert!(code.windows(3).any(|bytes| bytes == [0x48, 0x89, 0xF9]));
        assert!(code.windows(2).any(|bytes| bytes == [0x84, 0xC0]));
        assert!(code.ends_with(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn result_handling_can_compare_arbitrary_values() {
        let mut trampoline = Trampoline::new();
        let returned_five = trampoline.new_label();
        trampoline.preserved_call(
            0x140001000usize as *const (),
            &[],
            &[0x3C, 0x05],
            ReturnType::None,
        );
        trampoline.jump_if(Condition::Equal, returned_five);
        trampoline.bind(returned_five).unwrap();

        let code = trampoline.build(0x180000000).unwrap();
        assert!(code.windows(2).any(|bytes| bytes == [0x3C, 0x05]));
        assert!(code.ends_with(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn selected_return_register_remains_available() {
        let mut trampoline = Trampoline::new();
        trampoline.preserved_call(0x140001000usize as *const (), &[], &[], ReturnType::Rax);

        let code = trampoline.build(0x180000000).unwrap();
        assert!(code.ends_with(&[0x48, 0x8D, 0x64, 0x24, 0x08]));
    }
}
