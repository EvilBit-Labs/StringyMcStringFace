# Extend FoundString data model for demangling and debug support

## Objective

Update the `FoundString` struct in file:src/types.rs to support symbol demangling preservation and optional score breakdown for debugging.

## Scope

**In Scope:**

- Add `original_text: Option<String>` field to preserve mangled symbols
- Add optional breakdown fields: `section_weight: Option<i32>`, `semantic_boost: Option<i32>`, `noise_penalty: Option<i32>`
- Update serde serialization to handle new fields correctly
- Update existing tests to account for new fields
- Update documentation with field descriptions

**Out of Scope:**

- Actual demangling logic (handled in separate ticket)
- Score calculation logic (handled in separate ticket)
- CLI --debug flag implementation (handled in pipeline ticket)

## Acceptance Criteria

- [x] FoundString struct includes original_text field
- [x] FoundString struct includes optional breakdown fields (section_weight, semantic_boost, noise_penalty)
- [x] All fields properly serialize/deserialize with serde
- [x] Existing tests updated and passing
- [x] Documentation updated with field descriptions and usage examples
- [x] No breaking changes to existing code that creates FoundString instances

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Data Model section)
- file:src/types.rs (FoundString definition)

## Dependencies

None - this is the foundational ticket that other work depends on.
