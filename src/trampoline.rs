use crate::{PatchError, ReturnType, arch::push_preserved_call, relative_offset};

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
}

#[derive(Clone, Copy)]
struct RelativeFixup {
    displacement_offset: usize,
    next_instruction_offset: usize,
    target: Target,
}

/// A fixed-size x86-64 trampoline with address-dependent branch fixups.
#[derive(Clone, Default)]
pub struct Trampoline {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    relative_fixups: Vec<RelativeFixup>,
}

impl Trampoline {
    /// Creates an empty trampoline.
    pub const fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: Vec::new(),
            relative_fixups: Vec::new(),
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

    /// Calls a function while preserving volatile Windows-x64 registers.
    ///
    /// `argument_setup` runs after volatile state is saved and immediately
    /// before the call. It may modify volatile registers to prepare callback
    /// arguments, but must not change `RSP` or non-volatile registers.
    ///
    /// `result_handling` runs immediately after the call, before return
    /// registers are restored. It may inspect or dereference return values and
    /// leave state in flags or memory, but has the same register restrictions
    /// as `argument_setup`.
    ///
    /// Every control-flow path in both byte sequences must eventually fall
    /// through to the following generated instruction with `RSP` unchanged.
    /// Branching out of either sequence can bypass the call or register
    /// restoration and leave the trampoline's stack frame corrupted.
    ///
    /// `allow_return` selects a return register that remains available after
    /// this operation. [`ReturnType::None`] restores every volatile register.
    pub fn preserved_call(
        &mut self,
        function: *const (),
        argument_setup: &[u8],
        result_handling: &[u8],
        allow_return: ReturnType,
    ) -> &mut Self {
        push_preserved_call(
            &mut self.code,
            function,
            argument_setup,
            result_handling,
            allow_return,
        );
        self
    }

    /// Applies every address-dependent fixup for an allocation at `address`.
    pub fn build(&self, address: usize) -> Result<Vec<u8>, PatchError> {
        let mut code = self.code.clone();

        for fixup in &self.relative_fixups {
            let target = match fixup.target {
                Target::Address(target) => target,
                Target::Label(label) => {
                    let Some(position) = self.labels.get(label.0) else {
                        return Err(PatchError::InvalidLabel { label: label.0 });
                    };
                    let position = position.ok_or(PatchError::UnboundLabel { label: label.0 })?;
                    address
                        .checked_add(position)
                        .ok_or(PatchError::AddressOverflow)?
                }
            };
            let next_instruction = address
                .checked_add(fixup.next_instruction_offset)
                .ok_or(PatchError::AddressOverflow)?;
            let displacement = relative_offset(next_instruction, target)?;
            code[fixup.displacement_offset..fixup.displacement_offset + 4]
                .copy_from_slice(&displacement.to_le_bytes());
        }

        Ok(code)
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
