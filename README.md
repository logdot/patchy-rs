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
    tag = "v0.2.0"
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

### CMake from a release archive

Extract a `patchy-v*-windows-x86_64.zip` release and point CMake at its root:

```text
cmake -S . -B build -DCMAKE_PREFIX_PATH=C:/path/to/patchy
```

Then link the shared process-wide runtime:

```cmake
find_package(Patchy CONFIG REQUIRED)
target_link_libraries(your_mod PRIVATE Patchy::ffi)
```

`Patchy::ffi` provides the include path, DLL import library, and DLL location.
Copy `$<TARGET_FILE:Patchy::ffi>` beside the consuming module or into the
modloader's common runtime directory. All mods in a process should resolve this
target to the same DLL.

`Patchy::ffi_static` is also available and defines `PATCHY_STATIC`
automatically. It is intended for a process with one static Patchy consumer.
Linking Patchy statically into several mods creates independent registries that
cannot detect one another's patches.

### CMake from source

Projects that have Cargo and the Windows Rust target installed can build Patchy
directly:

```cmake
add_subdirectory(path/to/patchy-rs)
target_link_libraries(your_mod PRIVATE Patchy::ffi)
```

The source CMake build invokes Cargo and exposes the same `Patchy::ffi` and
`Patchy::ffi_static` targets. `PATCHY_CARGO_PROFILE`, `PATCHY_CARGO_TARGET`, and
`PATCHY_CARGO_TARGET_DIR` are cache variables for customizing that build.

Tagged GitHub releases contain the dynamic library, import library, static
library, optional debug symbols, header, CMake package files, C++ example,
license, README, and a SHA-256 checksum.
