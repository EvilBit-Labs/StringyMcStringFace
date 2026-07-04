<!--
Thanks for contributing to Stringy. Keep PRs focused and small when possible.
See CONTRIBUTING.md for coding standards and the review process.
-->

## Summary

<!-- What does this change do, and why? -->

## Related issues

<!-- Link issues this closes or relates to, e.g. "Closes #123". Large changes should
     have a discussion issue opened first. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation only
- [ ] Refactor / internal change (no user-facing behavior change)

## Checklist

- [ ] Commits are signed off (`git commit -s`) per the DCO
- [ ] `cargo fmt` produces no changes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] Tests added or updated for behavior changes (`just test`)
- [ ] No `unsafe` code, and no new `unwrap()`/`panic!` in library code
- [ ] ASCII-only in code and docs (no emoji, em-dashes, or smart quotes)
- [ ] Docs updated when behavior changed (README/docs), and AGENTS.md updated if architecture changed
- [ ] `just ci-check` passes locally (or the relevant subset)

## Notes for reviewers

<!-- Anything reviewers should focus on, trade-offs, or follow-ups deferred to later PRs. -->
