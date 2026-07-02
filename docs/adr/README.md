# Architecture Decision Records

This directory records significant architectural and technical decisions for Stringy using the lightweight [Michael Nygard ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions). Each ADR captures the context, the decision, the alternatives that were rejected, and the consequences -- so future contributors understand *why* the code is shaped the way it is.

Use [template.md](template.md) when adding a new record. Number ADRs sequentially and never renumber an existing one; mark superseded decisions with a link to their replacement.

| ADR                                                     | Title                                                                 | Status   | Date       |
| ------------------------------------------------------- | --------------------------------------------------------------------- | -------- | ---------- |
| [0001](0001-msvc-demangler-length-cap.md)               | Length-cap guard for the MSVC symbol demangler                        | accepted | 2026-06-19 |
| [0002](0002-msvc-demangler-dependency.md)               | Use the `msvc-demangler` crate for MSVC symbol demangling             | accepted | 2026-06-19 |
| [0003](0003-encoding-confidence-via-confidence-path.md) | Encoding confidence feeds the confidence path, not a new ranking term | accepted | 2026-07-01 |
