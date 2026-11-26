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

Callbacks are called through a `CallBridge`, which saves the volatile
Windows-x64 registers, reserves the callee's shadow space, and describes the
stack alignment (`StackAlignment`), flag handling (`FlagPolicy`) and kept return
register (`KeepReturn`) explicitly. Use `PatchSession::patch_call` to replace a
span with a bridge, or `Trampoline::call` to place one inside a larger
trampoline. The `CallBridge` documentation lists the registers saved and the
requirements on its `before_call` and `after_call` bytes.

To assemble `before_call` or `after_call` machine code in your mod, opt into
`iced-x86`'s `code_asm` feature in your own `Cargo.toml` (the `CallBridge` API
is newer than the `v0.2.0` example above, so target a revision that includes
it):

```toml
[dependencies]
patchy = { package = "patchy-rs", git = "https://github.com/logdot/patchy-rs.git" }
iced-x86 = { version = "1.21", features = ["code_asm"] }
```

Use `CodeAssembler` directly and pass the assembled bytes to `CallBridge`:

```rust
use iced_x86::code_asm::{CodeAssembler, rcx, rdx};
use patchy::{CallBridge, FlagPolicy, KeepReturn, StackAlignment};

extern "win64" fn on_hit(_value: u64) {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut asm = CodeAssembler::new(64)?;
    asm.mov(rcx, rdx)?;
    let before_call = asm.assemble(0)?;

    let _bridge = CallBridge {
        callback: on_hit as *const (),
        incoming_stack: StackAlignment::Aligned16,
        flags: FlagPolicy::Preserve,
        keep_return: KeepReturn::Neither,
        before_call: &before_call,
        after_call: &[],
    };

    Ok(())
}
```

Passing `0` to `assemble(0)` is valid for a position-independent instruction
such as `mov rcx, rdx`, because register-to-register moves encode no
instruction-pointer-relative offset and produce the same bytes at any address.
Address-dependent instructions (such as `RIP`-relative operands or relative
branches) depend on their runtime address and must be assembled at their actual
placement; `CallBridge` copies `before_call` and `after_call` verbatim without
relocating them, so those slices must remain position-independent.

To replay instructions displaced by a detour, build the trampoline with
`PatchSession::detour_trampoline_with`. Call `site.replay_verbatim(&mut trampoline)`
where the original instructions should run, and `site.resume(&mut trampoline)`
where control should return to the game after the patched span. Replay uses the
same bytes that Patchy checks during installation. It does not relocate
instructions: only replay complete instructions that still work at the new
address and at that point in the trampoline.

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
