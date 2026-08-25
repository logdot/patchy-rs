#ifndef PATCHY_H
#define PATCHY_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(PATCHY_STATIC)
#define PATCHY_API __declspec(dllimport)
#else
#define PATCHY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PATCHY_ABI_VERSION 1u

typedef struct patchy_session patchy_session;
typedef struct patchy_trampoline patchy_trampoline;
typedef uint32_t patchy_label;
typedef uint32_t patchy_status;
typedef uint32_t patchy_return_type;
typedef uint32_t patchy_condition;

/*
 * Unless a function explicitly accepts NULL, every pointer must refer to live,
 * properly aligned storage of the documented size. Patch source addresses and
 * machine-code buffers are trusted inputs; passing an invalid non-null pointer
 * or address has undefined behavior.
 */

enum {
    PATCHY_STATUS_OK = 0,
    PATCHY_STATUS_INVALID_ARGUMENT = 1,
    PATCHY_STATUS_ADDRESS_OVERFLOW = 2,
    PATCHY_STATUS_EMPTY_PATCH = 3,
    PATCHY_STATUS_EMPTY_TRAMPOLINE = 4,
    PATCHY_STATUS_SOURCE_CHANGED = 5,
    PATCHY_STATUS_OVERLAPPING_PATCH = 6,
    PATCHY_STATUS_RELATIVE_JUMP_OUT_OF_RANGE = 7,
    PATCHY_STATUS_ALLOCATION_FAILED = 8,
    PATCHY_STATUS_PROTECTION_FAILED = 9,
    PATCHY_STATUS_INSTRUCTION_CACHE_FAILED = 10,
    PATCHY_STATUS_MODULE_LOOKUP_FAILED = 11,
    PATCHY_STATUS_PATCH_TOO_SMALL = 12,
    PATCHY_STATUS_INVALID_LABEL = 13,
    PATCHY_STATUS_UNEXPECTED_TRAMPOLINE_SIZE = 14,
    PATCHY_STATUS_PANIC = 254,
    PATCHY_STATUS_INTERNAL_ERROR = 255
};

enum {
    PATCHY_RETURN_NONE = 0,
    PATCHY_RETURN_RAX = 1,
    PATCHY_RETURN_XMM0 = 2
};

enum {
    PATCHY_CONDITION_OVERFLOW = 0,
    PATCHY_CONDITION_NOT_OVERFLOW = 1,
    PATCHY_CONDITION_BELOW = 2,
    PATCHY_CONDITION_ABOVE_OR_EQUAL = 3,
    PATCHY_CONDITION_EQUAL = 4,
    PATCHY_CONDITION_NOT_EQUAL = 5,
    PATCHY_CONDITION_BELOW_OR_EQUAL = 6,
    PATCHY_CONDITION_ABOVE = 7,
    PATCHY_CONDITION_SIGN = 8,
    PATCHY_CONDITION_NOT_SIGN = 9,
    PATCHY_CONDITION_PARITY = 10,
    PATCHY_CONDITION_NOT_PARITY = 11,
    PATCHY_CONDITION_LESS = 12,
    PATCHY_CONDITION_GREATER_OR_EQUAL = 13,
    PATCHY_CONDITION_LESS_OR_EQUAL = 14,
    PATCHY_CONDITION_GREATER = 15
};

/* Returns the ABI version implemented by the loaded Patchy library. */
PATCHY_API uint32_t patchy_abi_version(void);

/*
 * Returns the current thread's most recent error message. The returned pointer
 * remains valid until the next status-returning Patchy call on the same thread
 * and must not be freed by the caller.
 */
PATCHY_API const char *patchy_last_error_message(void);

PATCHY_API patchy_status patchy_session_create(patchy_session **output);
PATCHY_API patchy_status patchy_session_destroy(patchy_session *session);

PATCHY_API patchy_status patchy_session_overwrite(
    patchy_session *session,
    uintptr_t address,
    const uint8_t *bytes,
    size_t length
);

/*
 * output_trampoline may be NULL. replay_overwritten must be zero or one.
 * function must use the Windows x64 ABI expected at the patch site.
 */
PATCHY_API patchy_status patchy_session_patch_call(
    patchy_session *session,
    uintptr_t address,
    uintptr_t function,
    size_t size,
    uint8_t replay_overwritten,
    patchy_return_type return_type,
    uintptr_t *output_trampoline
);

/* output_trampoline may be NULL. */
PATCHY_API patchy_status patchy_session_detour(
    patchy_session *session,
    uintptr_t address,
    size_t size,
    const uint8_t *trampoline_bytes,
    size_t trampoline_length,
    uintptr_t *output_trampoline
);

/*
 * The trampoline is borrowed and remains owned by the caller.
 * output_trampoline may be NULL.
 */
PATCHY_API patchy_status patchy_session_detour_trampoline(
    patchy_session *session,
    uintptr_t address,
    size_t size,
    patchy_trampoline *trampoline,
    uintptr_t *output_trampoline
);

/*
 * Permanently installs every prepared patch. This function always consumes
 * *session and sets it to NULL, including when installation returns an error.
 * No other thread may execute a patch source while installation replaces its
 * instructions. Patch destinations, callbacks, the Patchy dynamic library,
 * and their containing modules must remain loaded until process exit.
 */
PATCHY_API patchy_status patchy_session_install_permanently(
    patchy_session **session
);

PATCHY_API patchy_status patchy_main_module_base(
    uintptr_t *output_base
);

PATCHY_API patchy_status patchy_resolve_rva(
    uintptr_t module_base,
    uintptr_t rva,
    uintptr_t *output_address
);

PATCHY_API patchy_status patchy_trampoline_create(
    patchy_trampoline **output
);

PATCHY_API patchy_status patchy_trampoline_destroy(
    patchy_trampoline *trampoline
);

PATCHY_API patchy_status patchy_trampoline_length(
    patchy_trampoline *trampoline,
    size_t *output_length
);

PATCHY_API patchy_status patchy_trampoline_add_bytes(
    patchy_trampoline *trampoline,
    const uint8_t *bytes,
    size_t length
);

PATCHY_API patchy_status patchy_trampoline_new_label(
    patchy_trampoline *trampoline,
    patchy_label *output_label
);

PATCHY_API patchy_status patchy_trampoline_bind(
    patchy_trampoline *trampoline,
    patchy_label label
);

PATCHY_API patchy_status patchy_trampoline_absolute_call(
    patchy_trampoline *trampoline,
    uintptr_t function
);

PATCHY_API patchy_status patchy_trampoline_absolute_jump(
    patchy_trampoline *trampoline,
    uintptr_t destination
);

PATCHY_API patchy_status patchy_trampoline_relative_jump(
    patchy_trampoline *trampoline,
    uintptr_t destination
);

PATCHY_API patchy_status patchy_trampoline_jump_to(
    patchy_trampoline *trampoline,
    patchy_label label
);

PATCHY_API patchy_status patchy_trampoline_jump_if(
    patchy_trampoline *trampoline,
    patchy_condition condition,
    patchy_label label
);

/*
 * argument_setup and result_handling are uninterpreted x86-64 instruction
 * bytes. A NULL pointer is accepted only when its corresponding length is zero.
 */
PATCHY_API patchy_status patchy_trampoline_preserved_call(
    patchy_trampoline *trampoline,
    uintptr_t function,
    const uint8_t *argument_setup,
    size_t argument_setup_length,
    const uint8_t *result_handling,
    size_t result_handling_length,
    patchy_return_type return_type
);

#ifdef __cplusplus
}
#endif

#endif
