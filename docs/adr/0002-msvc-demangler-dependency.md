# ADR-0002: Use the `msvc-demangler` crate for MSVC symbol demangling

**Date**: 2026-06-19 **Status**: accepted **Deciders**: UncleSp1d3r

## Context

`SymbolDemangler` already demangles Rust (`rustc-demangle`) and C++ Itanium ABI (`cpp_demangle`) symbols, but had no handling for `?`-prefixed MSVC symbols, which dominate Windows PE import/export tables. We needed a Rust library to demangle MSVC names into readable form (e.g. `?printf@@YAHPEBDZZ` -> `int __cdecl printf(...)`). The crate had to integrate cleanly with the existing per-format helper pattern and pass `cargo deny` license/advisory checks.

## Decision

Add `msvc-demangler = "0.11"` and call it from a new `try_msvc_demangle` helper using `DemangleFlags::llvm()`, mirroring the structure of `try_rust_demangle` / `try_cpp_demangle`. Allow the `NCSA` license in `deny.toml` to satisfy the crate's `MIT/NCSA` dual license.

## Alternatives Considered

### Alternative 1: Hand-roll an MSVC demangler

- **Pros**: No new dependency; full control.
- **Why not**: MSVC mangling is complex and error-prone; reimplementing it is far more risk and maintenance than it is worth when a maintained crate exists. Violates the "prefer battle-tested libraries" principle.

### Alternative 2: Shell out to `undname.exe` / external tooling

- **Pros**: Authoritative MSVC output.
- **Why not**: Windows-only, requires a subprocess and an external toolchain at runtime, breaks the in-process, cross-platform model. Unworkable for a portable CLI.

### Alternative 3: A different MSVC-demangling crate

- **Pros**: Possible alternatives exist.
- **Why not**: `msvc-demangler` is the de-facto Rust choice (LLVM-lineage output via `DemangleFlags::llvm()`), is actively published (0.11.0 latest as of 2026-06-19), and pulls only `bitflags` + `itoa` transitively -- no new duplicate versions under the repo's `multiple-versions = "deny"` policy.

### Alternative 4: Broaden `deny.toml` instead of adding only NCSA

- **Why not**: We add exactly the one license the crate needs (`NCSA`, the OSI-approved University of Illinois/NCSA license) and nothing else. Broadening ban/advisory settings would weaken supply-chain hygiene for no reason.

## Consequences

### Positive

- Closes the MSVC gap with a maintained, conventional library; keeps the three demangle helpers structurally parallel.
- Minimal dependency footprint (`bitflags` + `itoa`), no new duplicate versions.
- `DemangleFlags::llvm()` keeps demangled output consistent with the C++/Itanium path.

### Negative

- Adds a third-party crate that parses untrusted input; its unbounded recursion required a mitigation (see [ADR-0001](0001-msvc-demangler-length-cap.md)).
- `deny.toml` now permits the `NCSA` license, a small expansion of the allow-list.

### Risks

- Upstream crate bugs (e.g. a known `i32` shift overflow in `read_number`) flow into Stringy. Mitigated by the [ADR-0001](0001-msvc-demangler-length-cap.md) length cap and the pipeline's graceful `None`/`Err` fallback, and bounded by `cargo deny`/`cargo audit` in CI.
