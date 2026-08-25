use std::fmt;

/// An error encountered while preparing or installing patches.
#[derive(Debug)]
pub enum PatchError {
    /// An address calculation overflowed.
    AddressOverflow,
    /// The process-wide patch set has already been finalized.
    AlreadyFinalized,
    /// A patch contained no replacement bytes.
    EmptyPatch,
    /// Windows could not flush executable instructions from the CPU cache.
    InstructionCache {
        /// The start of the region that could not be flushed.
        address: usize,
        /// The operating-system error.
        error: String,
    },
    /// Executable memory could not be allocated or sealed.
    Mapping(String),
    /// A loaded process module could not be found.
    ModuleLookup(String),
    /// No executable allocation could be placed within rel32 range of a hook.
    NoMemoryCave {
        /// The source address of the hook.
        hook: usize,
        /// The final allocation error, when one was reported.
        last_error: Option<String>,
    },
    /// Two prepared patches modify overlapping source bytes.
    OverlappingPatch {
        /// The address of the patch that was prepared first.
        first: usize,
        /// The address of the overlapping patch.
        second: usize,
    },
    /// Windows could not change or restore a source page's protection.
    Protection {
        /// The start of the affected page.
        address: usize,
        /// The operating-system error.
        error: String,
    },
    /// A destination cannot be reached with a signed 32-bit relative jump.
    RelativeJumpOutOfRange {
        /// The address immediately after the jump instruction.
        next_instruction: usize,
        /// The requested destination.
        destination: usize,
    },
    /// Source bytes changed after the patch was prepared.
    SourceChanged {
        /// The address whose contents changed.
        address: usize,
    },
    /// A trampoline is larger than one executable page.
    TrampolineTooLarge {
        /// The requested trampoline size.
        size: usize,
        /// The available page capacity.
        capacity: usize,
    },
    /// A trampoline builder returned a different number of bytes than promised.
    UnexpectedTrampolineSize {
        /// The promised size.
        expected: usize,
        /// The returned size.
        actual: usize,
    },
    /// A trampoline label does not belong to the builder using it.
    InvalidLabel {
        /// The invalid label identifier.
        label: usize,
    },
    /// A trampoline label was bound more than once.
    LabelAlreadyBound {
        /// The duplicate label identifier.
        label: usize,
    },
    /// A trampoline was built with an unbound label.
    UnboundLabel {
        /// The unbound label identifier.
        label: usize,
    },
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressOverflow => write!(f, "address calculation overflowed"),
            Self::AlreadyFinalized => write!(f, "patch installation has already been finalized"),
            Self::EmptyPatch => write!(f, "a patch must overwrite at least one byte"),
            Self::InstructionCache { address, error } => write!(
                f,
                "unable to flush the instruction cache at {address:#x}: {error}"
            ),
            Self::Mapping(error) => write!(f, "memory mapping failed: {error}"),
            Self::ModuleLookup(error) => write!(f, "unable to find process module: {error}"),
            Self::NoMemoryCave { hook, last_error } => {
                write!(f, "no usable trampoline page found near {hook:#x}")?;
                if let Some(error) = last_error {
                    write!(f, ": {error}")?;
                }
                Ok(())
            }
            Self::OverlappingPatch { first, second } => write!(
                f,
                "patch at {second:#x} overlaps the patch prepared at {first:#x}"
            ),
            Self::Protection { address, error } => {
                write!(f, "unable to change protection at {address:#x}: {error}")
            }
            Self::RelativeJumpOutOfRange {
                next_instruction,
                destination,
            } => write!(
                f,
                "relative jump from {next_instruction:#x} to {destination:#x} exceeds 32 bits"
            ),
            Self::SourceChanged { address } => write!(
                f,
                "patch source at {address:#x} changed while patches were being prepared"
            ),
            Self::TrampolineTooLarge { size, capacity } => write!(
                f,
                "trampoline requires {size} bytes but a page holds only {capacity}"
            ),
            Self::UnexpectedTrampolineSize { expected, actual } => write!(
                f,
                "trampoline builder produced {actual} bytes instead of {expected}"
            ),
            Self::InvalidLabel { label } => {
                write!(
                    f,
                    "trampoline label {label} does not belong to this builder"
                )
            }
            Self::LabelAlreadyBound { label } => {
                write!(f, "trampoline label {label} was bound more than once")
            }
            Self::UnboundLabel { label } => {
                write!(f, "trampoline label {label} was never bound")
            }
        }
    }
}

impl std::error::Error for PatchError {}
