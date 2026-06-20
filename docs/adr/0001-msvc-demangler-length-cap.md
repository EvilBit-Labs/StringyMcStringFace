# ADR-0001: Length-cap guard for the MSVC symbol demangler

**Date**: 2026-06-19 **Status**: accepted **Deciders**: UncleSp1d3r

## Context

Stringy analyzes untrusted and potentially malicious binaries. The `msvc-demangler` crate parses `?`-prefixed MSVC symbols with unbounded recursive descent. A crafted symbol with deeply nested type modifiers (~18 KB of repeated `PEA`/`Q` pointer/array decorators) overflows the stack and aborts the process. A stack overflow aborts rather than unwinds, so the pipeline's `catch_unwind` does not contain it -- and thread isolation does not help either, because Rust aborts the whole process on a thread stack overflow. Extraction's `max_length` (default 200) is only a scoring penalty, not a hard truncation, and import/export names bypass that path, so the malicious string can reach the demangler. This is an in-threat-model denial of service for a malware-analysis tool.

## Decision

Reject `?`-prefixed symbols longer than `MSVC_MAX_SYMBOL_LEN` (4096 bytes) in `try_msvc_demangle` before invoking the crate. Real MSVC symbols are far shorter than this even when heavily templated, so the cap rejects no legitimate input while bounding the worst-case recursion depth.

## Alternatives Considered

### Alternative 1: Thread isolation with a small explicit stack

- **Pros**: Would catch a stack overflow as a `JoinError` rather than letting it propagate.
- **Cons**: Does not actually work in Rust.
- **Why not**: Empirically verified that a thread stack overflow aborts the entire process; `catch_unwind` and `JoinError` do not catch it. Stack overflow is not a panic.

### Alternative 2: Upstream recursion-depth limit in `msvc-demangler`

- **Pros**: Fixes the root cause for all consumers.
- **Cons**: Out of our control; slow to land; we still ship vulnerable until then.
- **Why not**: Cannot gate our release on an upstream change. Worth pursuing in parallel as a follow-up, but not the primary mitigation.

### Alternative 3: Source restriction (only demangle ImportName/ExportName)

- **Pros**: Shrinks the input surface that reaches the demangler.
- **Cons**: Inconsistent with the existing `_Z`/`_R` paths, which do not restrict by source; does not bound recursion depth on its own.
- **Why not**: Restricting only the MSVC path would diverge from the Rust/C++ paths for no clear safety gain, and a long Import/Export name would still overflow. The length cap is the higher-value mitigation.

### Alternative 4: Do nothing

- **Pros**: Less code.
- **Cons**: Leaves an exploitable process-abort DoS.
- **Why not**: Unacceptable for a tool whose entire purpose is processing adversarial binaries.

## Consequences

### Positive

- Cheap O(1) length check eliminates the stack-overflow DoS.
- Rejects no legitimate symbol -- real MSVC mangled names are far below 4096 bytes.
- Consistent with defensive parsing of untrusted input; the guard is documented at the constant and covered by a regression test using a 60 KB nested-pointer symbol.

### Negative

- A pathological-but-legitimate symbol over 4096 bytes would silently not demangle (extremely unlikely in practice).
- The cap is a length heuristic, not a true recursion-depth limit, so it is correct only as long as recursion depth stays roughly proportional to symbol length.

### Risks

- If `msvc-demangler`'s recursion-per-byte ratio changes in a future version, 4096 may need revisiting. Mitigated by the wide margin: the observed overflow threshold is ~18 KB, about 4.4x the cap.
