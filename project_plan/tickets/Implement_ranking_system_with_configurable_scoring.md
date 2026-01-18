# Implement ranking system with configurable scoring

## Objective

Create the ranking system that calculates relevance scores for strings based on section weights, semantic tags, and noise penalties.

## Scope

**In Scope:**
- Create file:src/classification/ranking.rs with RankingEngine
- Define RankingConfig with hardcoded defaults:
  - Section weight mappings (SectionType -> i32)
  - Tag boost mappings (Tag -> i32)
  - Noise penalty configuration
- Implement score calculation algorithm:
  - Apply section weights from ContainerInfo
  - Apply semantic boosts based on tags
  - Calculate noise penalties from confidence scores
  - Populate score breakdown fields when debug mode enabled
- Implement rank_strings() to sort by score
- Add comprehensive unit tests with known scoring scenarios
- Split into submodules if exceeds 500 lines (section_weights.rs, semantic_boosts.rs, noise_penalties.rs)

**Out of Scope:**
- User-configurable ranking (hardcoded defaults only)
- CLI integration (separate ticket)
- Output formatting (separate ticket)

## Acceptance Criteria

- [ ] RankingEngine struct implemented with new() and rank_strings() methods
- [ ] RankingConfig with sensible hardcoded defaults
- [ ] Score calculation populates final score and breakdown fields
- [ ] Strings sorted by score in descending order
- [ ] Breakdown fields populated only when debug mode enabled
- [ ] Comprehensive unit tests covering various scoring scenarios
- [ ] File size under 500 lines (split if needed)
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/24940fed-1cc7-4d17-bc4b-fb5558c6f827 (Epic Brief - Problem 3: No Prioritization)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/dbfae449-b832-46a9-8fe7-748d7c5f5a20 (Core Flows - Score Range)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Component 1)
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 11)

## Dependencies

- Ticket: "Extend FoundString data model" (needs breakdown fields)
- Ticket: "Complete semantic classification" (needs tags for semantic boosts)