# ADR-0003: Encoding confidence feeds the confidence path, not a new ranking term

**Date**: 2026-07-01 **Status**: accepted **Deciders**: UncleSp1d3r

## Context

GitHub issue 22 specified `Score = SectionWeight + EncodingConfidence + SemanticBoost - NoisePenalty` (from a `concept.md` that no longer exists in the repo) and proposed a new `src/scoring/` module with a 0-10 encoding-confidence scale. The shipped ranking system (`src/classification/ranking.rs`) already computes `score = section_weight + semantic_boost - noise_penalty`, where the noise penalty is driven by `FoundString.confidence` (0.0-1.0) from extraction-layer noise filters. UTF-16 extraction additionally computes an encoding-specific confidence and min-combines it into that same field. An additive `EncodingConfidence` term would re-score printability and control-character density the noise penalty already covers.

## Decision

Encoding-quality signals influence ranking exclusively through the existing `FoundString.confidence` -> noise-penalty path. Issue 22's requirement 5.1 is delivered by enriching narrow-string (ASCII/UTF-8) confidence with a null-termination signal -- mirroring UTF-16's existing pattern -- not by adding a fourth ranking term or a `src/scoring/` module. The shipped formula in `docs/src/ranking.md` remains authoritative.

## Alternatives Considered

### Alternative 1: Additive `EncodingConfidence` term per the issue's formula

- **Pros**: Matches the original architecture document verbatim; encoding quality visible as a discrete score component.
- **Why not**: Double-penalizes signals the noise penalty already covers (printability, control-character density), contradicts the shipped docs formula, and bolts a parallel scoring module onto a ranking engine that already owns the job. Would also force retuning the 0-100 display-score normalization bands.

### Alternative 2: Docs update and close the issue with zero code

- **Pros**: Smallest possible close-out; no snapshot churn.
- **Why not**: Leaves a real asymmetry unaddressed -- narrow strings get only generic noise-filter confidence while UTF-16 gets encoding-specific confidence. The null-termination signal is cheap and the terminating byte is already in scope at `FoundString` construction.

## Consequences

### Positive

- No formula change, no new module, no normalizer retuning; the ranking engine is untouched.
- Narrow and wide strings gain parity in how encoding quality reaches the score.
- Rejecting the additive term is recorded, so the issue's formula cannot silently resurface.

### Negative

- Confidence shifts change scores: insta snapshots need regeneration and fixture rankings may reorder.
- UTF-16 termination-byte quality remains unevaluated (`has_null_terminator` informs byte trimming only) -- an accepted, documented limitation.

### Risks

- A null-termination bonus can deprioritize strings malware authors deliberately leave unterminated (length-prefixed, packed data). Mitigated by keeping the signal's magnitude small and never letting it raise confidence above the noise-filter verdict (plan R2, `docs/plans/2026-07-01-001-feat-encoding-confidence-close-out-plan.md`).
