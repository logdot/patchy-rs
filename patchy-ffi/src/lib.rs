//! C ABI adapter for Patchy.

use std::{
    cell::RefCell,
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use patchy::{Condition, Label, PatchError, PatchSession, ProcessModule, ReturnType, Trampoline};

/// Version of the ABI declared by `include/patchy.h`.
pub const PATCHY_ABI_VERSION: u32 = 1;

/// Status returned by every fallible Patchy C function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PatchyStatus {
    /// The operation completed successfully.
    Ok = 0,
    /// A pointer, length, enum value, or other argument was invalid.
    InvalidArgument = 1,
    /// An address calculation overflowed.
    AddressOverflow = 2,
    /// A patch had no replacement bytes.
    EmptyPatch = 3,
    /// A detour had no trampoline instructions.
    EmptyTrampoline = 4,
    /// Source bytes changed after patch preparation.
    SourceChanged = 5,
    /// A patch overlapped an existing patch.
    OverlappingPatch = 6,
    /// A relative branch destination was out of range.
    RelativeJumpOutOfRange = 7,
    /// Executable memory could not be allocated or sealed.
    AllocationFailed = 8,
    /// Source-page protection could not be changed or restored.
    ProtectionFailed = 9,
    /// Windows could not flush the instruction cache.
    InstructionCacheFailed = 10,
    /// The main process module could not be found.
    ModuleLookupFailed = 11,
    /// A patch source was too small.
    PatchTooSmall = 12,
    /// A trampoline label was invalid, duplicated, or unbound.
    InvalidLabel = 13,
    /// A trampoline builder produced an unexpected number of bytes.
    UnexpectedTrampolineSize = 14,
    /// Rust panicked while handling the call.
    Panic = 254,
    /// An error had no more specific stable ABI representation.
    InternalError = 255,
}

/// Opaque pending patch session used by the C ABI.
pub struct PatchySession {
    inner: PatchSession,
}

/// Opaque trampoline builder used by the C ABI.
pub struct PatchyTrampoline {
    inner: Trampoline,
    labels: Vec<Label>,
}

struct FfiError {
    status: PatchyStatus,
    message: String,
}

impl FfiError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: PatchyStatus::InvalidArgument,
            message: message.into(),
        }
    }
}

impl From<PatchError> for FfiError {
    fn from(error: PatchError) -> Self {
        let status = match &error {
            PatchError::AddressOverflow => PatchyStatus::AddressOverflow,
            PatchError::EmptyPatch => PatchyStatus::EmptyPatch,
            PatchError::EmptyTrampoline => PatchyStatus::EmptyTrampoline,
            PatchError::InstructionCache { .. } => PatchyStatus::InstructionCacheFailed,
            PatchError::Mapping(_)
            | PatchError::NoMemoryCave { .. }
            | PatchError::TrampolineTooLarge { .. } => PatchyStatus::AllocationFailed,
            PatchError::ModuleLookup(_) => PatchyStatus::ModuleLookupFailed,
            PatchError::PatchTooSmall { .. } => PatchyStatus::PatchTooSmall,
            PatchError::OverlappingPatch { .. } => PatchyStatus::OverlappingPatch,
            PatchError::Protection { .. } => PatchyStatus::ProtectionFailed,
            PatchError::RelativeJumpOutOfRange { .. } => PatchyStatus::RelativeJumpOutOfRange,
            PatchError::SourceChanged { .. } => PatchyStatus::SourceChanged,
            PatchError::UnexpectedTrampolineSize { .. } => PatchyStatus::UnexpectedTrampolineSize,
            PatchError::InvalidLabel { .. }
            | PatchError::LabelAlreadyBound { .. }
            | PatchError::UnboundLabel { .. } => PatchyStatus::InvalidLabel,
            _ => PatchyStatus::InternalError,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

const ERROR_MESSAGE_UNAVAILABLE: &[u8] = b"Patchy error message unavailable\0";

fn set_last_error(message: &str) {
    let message = message.replace('\0', "\\0");
    let message = CString::new(message).unwrap_or_default();
    LAST_ERROR.with(|last_error| *last_error.borrow_mut() = message);
}

fn try_set_last_error(message: &str) {
    let _ = catch_unwind(AssertUnwindSafe(|| set_last_error(message)));
}

fn ffi_call(operation: impl FnOnce() -> Result<(), FfiError>) -> PatchyStatus {
    try_set_last_error("");
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => PatchyStatus::Ok,
        Ok(Err(error)) => {
            try_set_last_error(&error.message);
            error.status
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown Rust panic");
            try_set_last_error(message);
            PatchyStatus::Panic
        }
    }
}

unsafe fn require_session<'a>(
    session: *mut PatchySession,
) -> Result<&'a mut PatchySession, FfiError> {
    // SAFETY: The caller promises that a non-null pointer refers to a live,
    // uniquely borrowed Patchy session.
    unsafe { session.as_mut() }.ok_or_else(|| FfiError::invalid("session must not be null"))
}

unsafe fn require_trampoline<'a>(
    trampoline: *mut PatchyTrampoline,
) -> Result<&'a mut PatchyTrampoline, FfiError> {
    // SAFETY: The caller promises that a non-null pointer refers to a live,
    // uniquely borrowed Patchy trampoline.
    unsafe { trampoline.as_mut() }.ok_or_else(|| FfiError::invalid("trampoline must not be null"))
}

unsafe fn require_bytes<'a>(
    bytes: *const u8,
    length: usize,
    name: &'static str,
) -> Result<&'a [u8], FfiError> {
    if length == 0 {
        return Ok(&[]);
    }
    if bytes.is_null() {
        return Err(FfiError::invalid(format!(
            "{name} must not be null when length is nonzero"
        )));
    }
    // SAFETY: The caller promises that `bytes` points to `length` readable
    // bytes. Non-nullness and the zero-length case were handled above.
    Ok(unsafe { slice::from_raw_parts(bytes, length) })
}

unsafe fn write_required<T>(output: *mut T, value: T, name: &'static str) -> Result<(), FfiError> {
    if output.is_null() {
        return Err(FfiError::invalid(format!("{name} must not be null")));
    }
    // SAFETY: The caller promises that the non-null output points to writable,
    // properly aligned storage for `T`.
    unsafe { output.write(value) };
    Ok(())
}

fn parse_return_type(value: u32) -> Result<ReturnType, FfiError> {
    match value {
        0 => Ok(ReturnType::None),
        1 => Ok(ReturnType::Rax),
        2 => Ok(ReturnType::Xmm0),
        _ => Err(FfiError::invalid("invalid patchy_return_type value")),
    }
}

fn parse_condition(value: u32) -> Result<Condition, FfiError> {
    match value {
        0 => Ok(Condition::Overflow),
        1 => Ok(Condition::NotOverflow),
        2 => Ok(Condition::Below),
        3 => Ok(Condition::AboveOrEqual),
        4 => Ok(Condition::Equal),
        5 => Ok(Condition::NotEqual),
        6 => Ok(Condition::BelowOrEqual),
        7 => Ok(Condition::Above),
        8 => Ok(Condition::Sign),
        9 => Ok(Condition::NotSign),
        10 => Ok(Condition::Parity),
        11 => Ok(Condition::NotParity),
        12 => Ok(Condition::Less),
        13 => Ok(Condition::GreaterOrEqual),
        14 => Ok(Condition::LessOrEqual),
        15 => Ok(Condition::Greater),
        _ => Err(FfiError::invalid("invalid patchy_condition value")),
    }
}

fn lookup_label(trampoline: &PatchyTrampoline, label: u32) -> Result<Label, FfiError> {
    trampoline
        .labels
        .get(label as usize)
        .copied()
        .ok_or_else(|| FfiError::invalid("label does not belong to this trampoline"))
}

/// Returns the supported C ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn patchy_abi_version() -> u32 {
    PATCHY_ABI_VERSION
}

/// Returns the current thread's most recent Patchy error message.
///
/// The pointer remains valid until the next status-returning Patchy call on
/// this thread.
#[unsafe(no_mangle)]
pub extern "C" fn patchy_last_error_message() -> *const c_char {
    catch_unwind(AssertUnwindSafe(|| {
        LAST_ERROR.with(|last_error| last_error.borrow().as_ptr())
    }))
    .unwrap_or(ERROR_MESSAGE_UNAVAILABLE.as_ptr().cast())
}

/// Creates an empty patch session.
///
/// # Safety
///
/// `output` must point to writable storage for one session pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_create(output: *mut *mut PatchySession) -> PatchyStatus {
    ffi_call(|| {
        if output.is_null() {
            return Err(FfiError::invalid("output session must not be null"));
        }
        let session = Box::into_raw(Box::new(PatchySession {
            inner: PatchSession::new(),
        }));
        // SAFETY: The output pointer was validated above and is writable by
        // contract.
        unsafe { output.write(session) };
        Ok(())
    })
}

/// Destroys a pending patch session. A null pointer is accepted.
///
/// # Safety
///
/// `session` must be null or a pointer returned by `patchy_session_create`
/// which has not already been destroyed or consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_destroy(session: *mut PatchySession) -> PatchyStatus {
    ffi_call(|| {
        if !session.is_null() {
            // SAFETY: Ownership of this live allocation is returned by the
            // caller and consumed exactly once.
            drop(unsafe { Box::from_raw(session) });
        }
        Ok(())
    })
}

/// Adds an in-place overwrite to a pending session.
///
/// # Safety
///
/// The session and byte range must be valid, and the destination address must
/// satisfy `PatchSession::overwrite`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_overwrite(
    session: *mut PatchySession,
    address: usize,
    bytes: *const u8,
    length: usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: Raw arguments are validated according to the function
        // contract before use.
        let session = unsafe { require_session(session)? };
        // SAFETY: The caller supplies the readable byte range.
        let bytes = unsafe { require_bytes(bytes, length, "bytes")? };
        // SAFETY: The caller is responsible for the target process address.
        unsafe { session.inner.overwrite(address, bytes)? };
        Ok(())
    })
}

/// Adds a callback trampoline to a pending session.
///
/// `replay_overwritten` must be zero or one. `output_trampoline` may be null.
///
/// # Safety
///
/// The session, source address, callback address, and callback ABI must satisfy
/// `PatchSession::patch_call`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_patch_call(
    session: *mut PatchySession,
    address: usize,
    function: usize,
    size: usize,
    replay_overwritten: u8,
    return_type: u32,
    output_trampoline: *mut usize,
) -> PatchyStatus {
    ffi_call(|| {
        if function == 0 {
            return Err(FfiError::invalid("function must not be null"));
        }
        let replay_overwritten = match replay_overwritten {
            0 => false,
            1 => true,
            _ => {
                return Err(FfiError::invalid("replay_overwritten must be zero or one"));
            }
        };
        let return_type = parse_return_type(return_type)?;
        // SAFETY: The raw session pointer is valid by contract.
        let session = unsafe { require_session(session)? };
        // SAFETY: The caller is responsible for the source and callback.
        let patch = unsafe {
            session.inner.patch_call(
                address,
                function as *const (),
                size,
                replay_overwritten,
                return_type,
            )?
        };
        if !output_trampoline.is_null() {
            // SAFETY: A non-null optional output is writable by contract.
            unsafe { output_trampoline.write(patch.trampoline_address().unwrap_or_default()) };
        }
        Ok(())
    })
}

/// Adds a raw byte trampoline detour to a pending session.
///
/// # Safety
///
/// All pointers, the source address, and the machine code must satisfy
/// `PatchSession::detour`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_detour(
    session: *mut PatchySession,
    address: usize,
    size: usize,
    trampoline_bytes: *const u8,
    trampoline_length: usize,
    output_trampoline: *mut usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: Raw arguments are validated according to the contract.
        let session = unsafe { require_session(session)? };
        // SAFETY: The caller supplies the readable trampoline bytes.
        let trampoline =
            unsafe { require_bytes(trampoline_bytes, trampoline_length, "trampoline bytes")? };
        // SAFETY: The caller is responsible for the source and machine code.
        let patch = unsafe { session.inner.detour(address, size, trampoline)? };
        if !output_trampoline.is_null() {
            // SAFETY: A non-null optional output is writable by contract.
            unsafe { output_trampoline.write(patch.trampoline_address().unwrap_or_default()) };
        }
        Ok(())
    })
}

/// Adds a detour using a Patchy trampoline builder.
///
/// The trampoline is borrowed and remains owned by the caller.
///
/// # Safety
///
/// Both handles and the source address must satisfy
/// `PatchSession::detour_trampoline`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_detour_trampoline(
    session: *mut PatchySession,
    address: usize,
    size: usize,
    trampoline: *mut PatchyTrampoline,
    output_trampoline: *mut usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: Both opaque pointers are valid by contract.
        let session = unsafe { require_session(session)? };
        // SAFETY: The trampoline pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        // SAFETY: The caller is responsible for the source and generated code.
        let patch = unsafe {
            session
                .inner
                .detour_trampoline(address, size, trampoline.inner.clone())?
        };
        if !output_trampoline.is_null() {
            // SAFETY: A non-null optional output is writable by contract.
            unsafe { output_trampoline.write(patch.trampoline_address().unwrap_or_default()) };
        }
        Ok(())
    })
}

/// Permanently installs and consumes a pending patch session.
///
/// The caller's pointer is set to null before installation begins and is
/// consumed even when installation returns an error.
///
/// # Safety
///
/// `session` must point to a live session pointer. Patch sources must satisfy
/// `PatchSession::install_permanently`, including its thread-synchronization
/// requirements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_session_install_permanently(
    session: *mut *mut PatchySession,
) -> PatchyStatus {
    ffi_call(|| {
        if session.is_null() {
            return Err(FfiError::invalid("session pointer must not be null"));
        }
        // SAFETY: The outer pointer is readable and writable by contract.
        let session_value = unsafe { session.read() };
        if session_value.is_null() {
            return Err(FfiError::invalid("session must not be null"));
        }
        // Clear the caller's pointer before any fallible operation consumes the
        // allocation.
        // SAFETY: The outer pointer is writable by contract.
        unsafe { session.write(ptr::null_mut()) };
        // SAFETY: Ownership of this live allocation is consumed exactly once.
        let session = unsafe { Box::from_raw(session_value) };
        // SAFETY: The caller supplies the installation synchronization
        // guarantees documented by the core API.
        unsafe { session.inner.install_permanently()? };
        Ok(())
    })
}

/// Returns the current process's main module base address.
///
/// # Safety
///
/// `output_base` must point to writable storage for one address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_main_module_base(output_base: *mut usize) -> PatchyStatus {
    ffi_call(|| {
        let base = ProcessModule::main()?.base_address();
        // SAFETY: The caller provides the output storage.
        unsafe { write_required(output_base, base, "output base") }
    })
}

/// Resolves an RVA against a supplied module base.
///
/// # Safety
///
/// `output_address` must point to writable storage for one address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_resolve_rva(
    module_base: usize,
    rva: usize,
    output_address: *mut usize,
) -> PatchyStatus {
    ffi_call(|| {
        let address = ProcessModule::from_base(module_base).resolve_rva(rva)?;
        // SAFETY: The caller provides the output storage.
        unsafe { write_required(output_address, address, "output address") }
    })
}

/// Creates an empty trampoline builder.
///
/// # Safety
///
/// `output` must point to writable storage for one trampoline pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_create(
    output: *mut *mut PatchyTrampoline,
) -> PatchyStatus {
    ffi_call(|| {
        if output.is_null() {
            return Err(FfiError::invalid("output trampoline must not be null"));
        }
        let trampoline = Box::into_raw(Box::new(PatchyTrampoline {
            inner: Trampoline::new(),
            labels: Vec::new(),
        }));
        // SAFETY: The output pointer was validated above.
        unsafe { output.write(trampoline) };
        Ok(())
    })
}

/// Destroys a trampoline builder. A null pointer is accepted.
///
/// # Safety
///
/// `trampoline` must be null or a live pointer returned by
/// `patchy_trampoline_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_destroy(
    trampoline: *mut PatchyTrampoline,
) -> PatchyStatus {
    ffi_call(|| {
        if !trampoline.is_null() {
            // SAFETY: Ownership of this live allocation is consumed once.
            drop(unsafe { Box::from_raw(trampoline) });
        }
        Ok(())
    })
}

/// Returns a trampoline builder's encoded length.
///
/// # Safety
///
/// The trampoline and output pointer must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_length(
    trampoline: *mut PatchyTrampoline,
    output_length: *mut usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        // SAFETY: The caller provides the output storage.
        unsafe { write_required(output_length, trampoline.inner.len(), "output length") }
    })
}

/// Appends uninterpreted machine-code bytes.
///
/// # Safety
///
/// The trampoline and byte range must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_add_bytes(
    trampoline: *mut PatchyTrampoline,
    bytes: *const u8,
    length: usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: Raw arguments are valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        // SAFETY: The caller supplies the readable byte range.
        let bytes = unsafe { require_bytes(bytes, length, "bytes")? };
        trampoline.inner.bytes(bytes);
        Ok(())
    })
}

/// Creates an unbound trampoline label.
///
/// # Safety
///
/// The trampoline and output pointer must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_new_label(
    trampoline: *mut PatchyTrampoline,
    output_label: *mut u32,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        let index = u32::try_from(trampoline.labels.len())
            .map_err(|_| FfiError::invalid("too many trampoline labels"))?;
        let label = trampoline.inner.new_label();
        trampoline.labels.push(label);
        // SAFETY: The caller provides the output storage.
        unsafe { write_required(output_label, index, "output label") }
    })
}

/// Binds a label to the trampoline's current end.
///
/// # Safety
///
/// The trampoline must be valid and `label` must belong to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_bind(
    trampoline: *mut PatchyTrampoline,
    label: u32,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        let label = lookup_label(trampoline, label)?;
        trampoline.inner.bind(label)?;
        Ok(())
    })
}

/// Appends an address-independent absolute call.
///
/// # Safety
///
/// The trampoline and function address must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_absolute_call(
    trampoline: *mut PatchyTrampoline,
    function: usize,
) -> PatchyStatus {
    ffi_call(|| {
        if function == 0 {
            return Err(FfiError::invalid("function must not be null"));
        }
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        trampoline.inner.absolute_call(function as *const ());
        Ok(())
    })
}

/// Appends an address-independent absolute jump.
///
/// # Safety
///
/// The trampoline and destination address must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_absolute_jump(
    trampoline: *mut PatchyTrampoline,
    destination: usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        trampoline.inner.absolute_jump(destination);
        Ok(())
    })
}

/// Appends a relative jump to an absolute address.
///
/// # Safety
///
/// The trampoline and destination address must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_relative_jump(
    trampoline: *mut PatchyTrampoline,
    destination: usize,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        trampoline.inner.relative_jump(destination);
        Ok(())
    })
}

/// Appends a relative jump to an internal label.
///
/// # Safety
///
/// The trampoline must be valid and `label` must belong to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_jump_to(
    trampoline: *mut PatchyTrampoline,
    label: u32,
) -> PatchyStatus {
    ffi_call(|| {
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        let label = lookup_label(trampoline, label)?;
        trampoline.inner.jump_to(label);
        Ok(())
    })
}

/// Appends a conditional relative jump to an internal label.
///
/// # Safety
///
/// The trampoline must be valid and `label` must belong to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_jump_if(
    trampoline: *mut PatchyTrampoline,
    condition: u32,
    label: u32,
) -> PatchyStatus {
    ffi_call(|| {
        let condition = parse_condition(condition)?;
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        let label = lookup_label(trampoline, label)?;
        trampoline.inner.jump_if(condition, label);
        Ok(())
    })
}

/// Appends a preserved Windows-x64 callback invocation.
///
/// # Safety
///
/// The trampoline, callback address, and both byte ranges must satisfy
/// `Trampoline::preserved_call`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patchy_trampoline_preserved_call(
    trampoline: *mut PatchyTrampoline,
    function: usize,
    argument_setup: *const u8,
    argument_setup_length: usize,
    result_handling: *const u8,
    result_handling_length: usize,
    return_type: u32,
) -> PatchyStatus {
    ffi_call(|| {
        if function == 0 {
            return Err(FfiError::invalid("function must not be null"));
        }
        let return_type = parse_return_type(return_type)?;
        // SAFETY: The opaque pointer is valid by contract.
        let trampoline = unsafe { require_trampoline(trampoline)? };
        // SAFETY: The caller supplies both readable byte ranges.
        let argument_setup =
            unsafe { require_bytes(argument_setup, argument_setup_length, "argument setup")? };
        // SAFETY: The caller supplies both readable byte ranges.
        let result_handling =
            unsafe { require_bytes(result_handling, result_handling_length, "result handling")? };
        trampoline.inner.preserved_call(
            function as *const (),
            argument_setup,
            result_handling,
            return_type,
        );
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CStr, ptr};

    #[test]
    fn creates_and_destroys_opaque_builders() {
        unsafe {
            let mut session = ptr::null_mut();
            assert_eq!(patchy_session_create(&mut session), PatchyStatus::Ok);
            assert!(!session.is_null());
            assert_eq!(patchy_session_destroy(session), PatchyStatus::Ok);

            let mut trampoline = ptr::null_mut();
            assert_eq!(patchy_trampoline_create(&mut trampoline), PatchyStatus::Ok);
            let mut label = u32::MAX;
            assert_eq!(
                patchy_trampoline_new_label(trampoline, &mut label),
                PatchyStatus::Ok
            );
            assert_eq!(label, 0);
            assert_eq!(
                patchy_trampoline_jump_to(trampoline, label),
                PatchyStatus::Ok
            );
            assert_eq!(patchy_trampoline_bind(trampoline, label), PatchyStatus::Ok);
            assert_eq!(patchy_trampoline_destroy(trampoline), PatchyStatus::Ok);
        }
    }

    #[test]
    fn invalid_arguments_return_status_and_message() {
        unsafe {
            assert_eq!(
                patchy_session_create(ptr::null_mut()),
                PatchyStatus::InvalidArgument
            );
            let message = CStr::from_ptr(patchy_last_error_message())
                .to_str()
                .unwrap();
            assert!(message.contains("output session"));
        }
    }
}
