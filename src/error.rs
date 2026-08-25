use thiserror::Error;

/// An error encountered while preparing or installing patches.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PatchError {
    /// An address calculation overflowed.
    #[error("address calculation overflowed")]
    AddressOverflow,
    /// A patch contained no replacement bytes.
    #[error("a patch must overwrite at least one byte")]
    EmptyPatch,
    /// A detour contained no trampoline instructions.
    #[error("a detour trampoline cannot be empty")]
    EmptyTrampoline,
    /// Windows could not flush executable instructions from the CPU cache.
    #[error("unable to flush the instruction cache at {address:#x}: {error}")]
    InstructionCache {
        /// The start of the region that could not be flushed.
        address: usize,
        /// The operating-system error.
        error: String,
    },
    /// Executable memory could not be allocated or sealed.
    #[error("memory mapping failed: {0}")]
    Mapping(String),
    /// A loaded process module could not be found.
    #[error("unable to find process module: {0}")]
    ModuleLookup(String),
    /// No executable allocation could be placed within rel32 range of a hook.
    #[error(
        "no usable trampoline page found near {hook:#x}{details}",
        details = last_error
            .as_ref()
            .map(|error| format!(": {error}"))
            .unwrap_or_default()
    )]
    NoMemoryCave {
        /// The source address of the hook.
        hook: usize,
        /// The final allocation error, when one was reported.
        last_error: Option<String>,
    },
    /// A patch source is too small for its replacement instruction.
    #[error("patch requires at least {minimum} source bytes, but received {size}")]
    PatchTooSmall {
        /// The provided source size.
        size: usize,
        /// The minimum required source size.
        minimum: usize,
    },
    /// Two prepared patches modify overlapping source bytes.
    #[error("patch at {second:#x} overlaps the patch prepared at {first:#x}")]
    OverlappingPatch {
        /// The address of the patch that was prepared first.
        first: usize,
        /// The address of the overlapping patch.
        second: usize,
    },
    /// Windows could not change or restore a source page's protection.
    #[error("unable to change protection at {address:#x}: {error}")]
    Protection {
        /// The start of the affected page.
        address: usize,
        /// The operating-system error.
        error: String,
    },
    /// A destination cannot be reached with a signed 32-bit relative jump.
    #[error("relative jump from {next_instruction:#x} to {destination:#x} exceeds 32 bits")]
    RelativeJumpOutOfRange {
        /// The address immediately after the jump instruction.
        next_instruction: usize,
        /// The requested destination.
        destination: usize,
    },
    /// Source bytes changed after the patch was prepared.
    #[error("patch source at {address:#x} changed while patches were being prepared")]
    SourceChanged {
        /// The address whose contents changed.
        address: usize,
    },
    /// A trampoline is larger than one executable page.
    #[error("trampoline requires {size} bytes but a page holds only {capacity}")]
    TrampolineTooLarge {
        /// The requested trampoline size.
        size: usize,
        /// The available page capacity.
        capacity: usize,
    },
    /// A trampoline builder returned a different number of bytes than promised.
    #[error("trampoline builder produced {actual} bytes instead of {expected}")]
    UnexpectedTrampolineSize {
        /// The promised size.
        expected: usize,
        /// The returned size.
        actual: usize,
    },
    /// A trampoline label does not belong to the builder using it.
    #[error("trampoline label {label} does not belong to this builder")]
    InvalidLabel {
        /// The invalid label identifier.
        label: usize,
    },
    /// A trampoline label was bound more than once.
    #[error("trampoline label {label} was bound more than once")]
    LabelAlreadyBound {
        /// The duplicate label identifier.
        label: usize,
    },
    /// A trampoline was built with an unbound label.
    #[error("trampoline label {label} was never bound")]
    UnboundLabel {
        /// The unbound label identifier.
        label: usize,
    },
}
