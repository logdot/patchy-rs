# patchy-rs

Runtime executable patching for 64-bit Windows processes.

Patchy provides:

- an idiomatic Rust API in the root `patchy-rs` package;
- a stable C ABI adapter in the `patchy-ffi` package;
- the public C/C++ header at `include/patchy.h`;
- a minimal injected-module example at
  `examples/cpp/install_overwrite.cpp`.

## Lifetime

Patches are prepared in a session and installed permanently as one batch.
Dropping a session before installation cancels its pending work. Once installed,
source modifications and executable trampolines remain live until process exit.
Any module containing a callback or destination referenced by a patch must
remain loaded for that duration. When using the dynamic C ABI library,
`patchy_ffi.dll` must remain loaded as well.

All mods in one process should share the same `patchy_ffi.dll` instance.
Separately loaded or statically linked copies have independent permanent-patch
registries and cannot detect overlaps with one another. Disjoint patches may
work, but overlapping patches could corrupt each other's sources. A modloader
should therefore provide one common Patchy dynamic library and keep it loaded
until process exit.

Patchy does not provide an uninstall operation because an injected module
generally cannot prove that no thread is executing or will return through a
patched source or trampoline.

## Rust

Rust projects can depend on a tagged Git release without using crates.io:

```toml
patchy = {
    package = "patchy-rs",
    git = "https://github.com/logdot/patchy-rs.git",
    tag = "v0.1.0"
}
```

## C and C++

Build the C ABI library with:

```text
cargo build --release -p patchy-ffi
```

The Windows build produces dynamic and static Patchy libraries. Include
`include/patchy.h` and link the appropriate artifact. Define `PATCHY_STATIC`
when linking the static library.

Every fallible C function returns a `patchy_status`. A descriptive
thread-local message is available through `patchy_last_error_message()` until
the next status-returning Patchy call on that thread. Rust panics are caught and
reported as `PATCHY_STATUS_PANIC`; they never unwind across the C boundary.

The C ABI validates null pointers, lengths, and fixed-value arguments where
possible. It cannot validate arbitrary non-null pointers, process addresses, or
machine code. Those inputs remain the caller's responsibility.

CMake integration and downloadable release artifacts will be added separately.
