#include "patchy.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace {

bool report_error(const char *operation, patchy_status status) {
    if (status == PATCHY_STATUS_OK) {
        return true;
    }

    std::fprintf(
        stderr,
        "%s failed with Patchy status %u: %s\n",
        operation,
        static_cast<unsigned>(status),
        patchy_last_error_message()
    );
    return false;
}

} // namespace

// This function is intended to run inside an injected module while no other
// thread can execute the patch source. Installed patches, this module, and the
// Patchy dynamic library must remain loaded until process exit.
bool install_overwrite(
    std::uintptr_t patch_rva,
    const std::uint8_t *replacement,
    std::size_t replacement_size
) {
    std::uintptr_t module_base = 0;
    if (!report_error(
            "patchy_main_module_base",
            patchy_main_module_base(&module_base))) {
        return false;
    }

    std::uintptr_t patch_address = 0;
    if (!report_error(
            "patchy_resolve_rva",
            patchy_resolve_rva(module_base, patch_rva, &patch_address))) {
        return false;
    }

    patchy_session *session = nullptr;
    if (!report_error(
            "patchy_session_create",
            patchy_session_create(&session))) {
        return false;
    }

    patchy_status status = patchy_session_overwrite(
        session,
        patch_address,
        replacement,
        replacement_size
    );
    if (!report_error("patchy_session_overwrite", status)) {
        patchy_session_destroy(session);
        return false;
    }

    // This consumes `session` and sets it to nullptr, even on failure.
    status = patchy_session_install_permanently(&session);
    return report_error("patchy_session_install_permanently", status);
}
