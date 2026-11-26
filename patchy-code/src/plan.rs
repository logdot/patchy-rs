use crate::{PatchError, relative_offset};

/// A placement-dependent operation on a compiled trampoline template.
///
/// For relative fixups, `offset` is the start of the four-byte displacement
/// field, which must end the instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrampolineFixup {
    /// Fill `size` bytes from the detour's source snapshot.
    Replay { offset: usize, size: usize },
    /// Fill a four-byte relative displacement to a runtime address.
    Relative { offset: usize, destination: usize },
    /// Fill a four-byte relative displacement to the detour's continuation.
    Resume { offset: usize },
}

impl TrampolineFixup {
    fn span(self) -> (usize, usize) {
        match self {
            Self::Replay { offset, size } => (offset, size),
            Self::Relative { offset, .. } | Self::Resume { offset } => (offset, 4),
        }
    }
}

/// A trampoline template with only placement-dependent fixups remaining.
///
/// Internal labels are already encoded. An installer may transport the
/// template and fixups separately and reconstruct the plan using `new`.
/// Validation here checks fixup bounds, not whether the bytes are safe to run.
#[derive(Clone, Debug)]
pub struct TrampolinePlan {
    template: Vec<u8>,
    fixups: Vec<TrampolineFixup>,
}

impl TrampolinePlan {
    /// Validates the template's fixup ranges. The fixups may arrive in any order.
    pub fn new(template: Vec<u8>, mut fixups: Vec<TrampolineFixup>) -> Result<Self, PatchError> {
        fixups.sort_unstable_by_key(|fixup| fixup.span().0);
        let mut last_end = 0;
        for fixup in &fixups {
            let (offset, size) = fixup.span();
            let Some(end) = offset.checked_add(size) else {
                return Err(PatchError::InvalidTrampolineFixup { offset });
            };
            if size == 0 || offset < last_end || end > template.len() {
                return Err(PatchError::InvalidTrampolineFixup { offset });
            }
            last_end = end;
        }
        Ok(Self { template, fixups })
    }

    /// Returns the encoded bytes before placement and the remaining fixups.
    pub fn parts(&self) -> (&[u8], &[TrampolineFixup]) {
        (&self.template, &self.fixups)
    }

    /// Checks that each replay slot can hold this detour's complete source span.
    pub fn validate_replay_size(&self, source_size: usize) -> Result<(), PatchError> {
        for &fixup in &self.fixups {
            if let TrampolineFixup::Replay { offset, size } = fixup {
                if size != source_size {
                    return Err(replay_size_mismatch(offset, size, source_size));
                }
            }
        }
        Ok(())
    }

    /// Builds a plan that doesn't require a detour site.
    pub fn build(&self, address: usize) -> Result<Vec<u8>, PatchError> {
        self.build_with_site(address, None)
    }

    /// Builds with the installer-owned source snapshot and continuation.
    pub fn build_for_site(
        &self,
        address: usize,
        overwritten: &[u8],
        continuation: usize,
    ) -> Result<Vec<u8>, PatchError> {
        self.build_with_site(address, Some((overwritten, continuation)))
    }

    fn build_with_site(
        &self,
        address: usize,
        site: Option<(&[u8], usize)>,
    ) -> Result<Vec<u8>, PatchError> {
        let mut code = self.template.clone();
        for &fixup in &self.fixups {
            let (offset, size) = fixup.span();
            let end = offset + size; // Checked by `new`.
            let destination = match fixup {
                TrampolineFixup::Replay { .. } => {
                    let (overwritten, _) = site.ok_or(PatchError::MissingDetourSite)?;
                    if overwritten.len() != size {
                        return Err(replay_size_mismatch(offset, size, overwritten.len()));
                    }
                    code[offset..end].copy_from_slice(overwritten);
                    continue;
                }
                TrampolineFixup::Relative { destination, .. } => destination,
                TrampolineFixup::Resume { .. } => site.ok_or(PatchError::MissingDetourSite)?.1,
            };
            let next = address
                .checked_add(end)
                .ok_or(PatchError::AddressOverflow)?;
            let displacement = relative_offset(next, destination)?;
            code[offset..end].copy_from_slice(&displacement.to_le_bytes());
        }
        Ok(code)
    }
}

fn replay_size_mismatch(offset: usize, reserved: usize, source_size: usize) -> PatchError {
    PatchError::ReplaySizeMismatch {
        offset,
        reserved,
        source_size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixup_cannot_extend_past_the_template() {
        assert!(matches!(
            TrampolinePlan::new(vec![0; 5], vec![TrampolineFixup::Resume { offset: 2 }]),
            Err(PatchError::InvalidTrampolineFixup { offset: 2 })
        ));
    }

    #[test]
    fn transported_fixups_cannot_overlap() {
        let overlaps = vec![
            TrampolineFixup::Resume { offset: 4 },
            TrampolineFixup::Replay { offset: 0, size: 5 },
        ];
        assert!(matches!(
            TrampolinePlan::new(vec![0; 8], overlaps),
            Err(PatchError::InvalidTrampolineFixup { offset: 4 })
        ));
    }

    #[test]
    fn a_replay_fixup_must_match_the_captured_span() {
        let plan = TrampolinePlan::new(
            vec![0; 5],
            vec![TrampolineFixup::Replay { offset: 0, size: 5 }],
        )
        .unwrap();
        assert!(matches!(
            plan.build_for_site(0x1000, &[0x90; 6], 0x2006),
            Err(PatchError::ReplaySizeMismatch {
                offset: 0,
                reserved: 5,
                source_size: 6
            })
        ));
    }
}
