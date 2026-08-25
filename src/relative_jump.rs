use std::ops::Range;

use crate::PatchError;

pub(crate) const NEAR_JUMP: u8 = 0xe9;
pub(crate) const NEAR_JUMP_SIZE: usize = 5;

const TRAMPOLINE_ALIGNMENT: usize = 16;

pub(crate) fn build_near_jump(
    source: usize,
    destination: usize,
    size: usize,
) -> Result<Vec<u8>, PatchError> {
    if size < NEAR_JUMP_SIZE {
        return Err(PatchError::UnexpectedTrampolineSize {
            expected: NEAR_JUMP_SIZE,
            actual: size,
        });
    }

    let next_instruction = source
        .checked_add(NEAR_JUMP_SIZE)
        .ok_or(PatchError::AddressOverflow)?;
    let displacement = relative_offset(next_instruction, destination)?;
    let mut patch = Vec::with_capacity(size);
    patch.push(NEAR_JUMP);
    patch.extend_from_slice(&displacement.to_le_bytes());
    patch.resize(size, 0x90);
    Ok(patch)
}

/// Calculates a signed 32-bit relative displacement.
///
/// `next_instruction` is the address immediately after the instruction that
/// will contain the displacement.
pub fn relative_offset(next_instruction: usize, destination: usize) -> Result<i32, PatchError> {
    let displacement = destination as i128 - next_instruction as i128;
    i32::try_from(displacement).map_err(|_| PatchError::RelativeJumpOutOfRange {
        next_instruction,
        destination,
    })
}

pub(crate) fn slot_range(used: usize, size: usize, capacity: usize) -> Option<Range<usize>> {
    let start = align_up(used, TRAMPOLINE_ALIGNMENT)?;
    let end = start.checked_add(size)?;
    (end <= capacity).then_some(start..end)
}

pub(crate) fn align_down(value: usize, alignment: usize) -> usize {
    value - value % alignment
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

pub(crate) struct CandidateAddresses {
    hook: usize,
    minimum: usize,
    maximum: usize,
    granularity: usize,
    lower: Option<usize>,
    upper: Option<usize>,
}

impl CandidateAddresses {
    pub(crate) fn new(
        hook: usize,
        minimum: usize,
        maximum: usize,
        granularity: usize,
    ) -> Result<Self, PatchError> {
        let lower = align_down(hook.min(maximum), granularity);
        let lower = (lower >= minimum).then_some(lower);
        let upper = align_up(hook.max(minimum), granularity).ok_or(PatchError::AddressOverflow)?;
        let mut upper = (upper <= maximum).then_some(upper);

        if upper == lower {
            upper = upper
                .and_then(|candidate| candidate.checked_add(granularity))
                .filter(|candidate| *candidate <= maximum);
        }

        Ok(Self {
            hook,
            minimum,
            maximum,
            granularity,
            lower,
            upper,
        })
    }
}

impl Iterator for CandidateAddresses {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let take_lower = match (self.lower, self.upper) {
            (Some(lower), Some(upper)) => lower.abs_diff(self.hook) <= upper.abs_diff(self.hook),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };

        if take_lower {
            let candidate = self.lower?;
            self.lower = candidate
                .checked_sub(self.granularity)
                .filter(|next| *next >= self.minimum);
            Some(candidate)
        } else {
            let candidate = self.upper?;
            self.upper = candidate
                .checked_add(self.granularity)
                .filter(|next| *next <= self.maximum);
            Some(candidate)
        }
    }
}

pub(crate) fn candidate_bounds(
    next_instruction: usize,
    page_size: usize,
    granularity: usize,
) -> Result<(usize, usize), PatchError> {
    let minimum = (next_instruction as i128 + i32::MIN as i128).max(0) as usize;
    let maximum_mapping_base = usize::MAX
        .checked_sub(page_size.saturating_sub(1))
        .ok_or(PatchError::AddressOverflow)?;
    let maximum =
        (next_instruction as i128 + i32::MAX as i128).min(maximum_mapping_base as i128) as usize;
    let minimum = align_up(minimum, granularity).ok_or(PatchError::AddressOverflow)?;
    let maximum = align_down(maximum, granularity);

    if minimum > maximum {
        Err(PatchError::NoMemoryCave {
            hook: next_instruction.saturating_sub(NEAR_JUMP_SIZE),
            last_error: None,
        })
    } else {
        Ok((minimum, maximum))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel32_boundaries_are_checked() {
        let next_instruction = 0x2_0000_0000usize;

        assert_eq!(
            relative_offset(next_instruction, next_instruction - 0x8000_0000).unwrap(),
            i32::MIN
        );
        assert_eq!(
            relative_offset(next_instruction, next_instruction + 0x7fff_ffff).unwrap(),
            i32::MAX
        );
        assert!(relative_offset(next_instruction, next_instruction - 0x8000_0001).is_err());
        assert!(relative_offset(next_instruction, next_instruction + 0x8000_0000).is_err());
    }

    #[test]
    fn slots_are_aligned_and_do_not_overlap() {
        let first = slot_range(0, 135, 4096).unwrap();
        let second = slot_range(first.end, 129, 4096).unwrap();

        assert_eq!(first, 0..135);
        assert_eq!(second, 144..273);
        assert!(first.end <= second.start);
        assert!(slot_range(4090, 16, 4096).is_none());
    }

    #[test]
    fn mapping_candidates_are_ordered_by_distance_from_hook() {
        let candidates = CandidateAddresses::new(0x1f000, 0, 0x40000, 0x10000)
            .unwrap()
            .collect::<Vec<_>>();

        assert_eq!(candidates, [0x20000, 0x10000, 0x30000, 0, 0x40000]);
    }
}
