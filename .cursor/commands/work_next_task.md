# Work Next Task

## Description

Work on the next unchecked task in the current task list.

## Steps

1. Read the entire currently open task list document before beginning. Do not skip this step.
2. **Gather Context**: Before starting work on the task:
   - If the task list is in a folder, check for `requirements.md` and `design.md` files in the same directory and read them for essential context
   - If the task item contains a link to a GitHub issue, examine the issue thoroughly for additional context, acceptance criteria, and potential solutions
   - Review any referenced documentation or specifications
3. Identify the next unchecked task in the checklist. The task will typically have an associated github issue linked to it with additional context and a potential solution that should be reviewed as well.

> ⚠️ Important: Some tasks may appear implemented but are still unchecked. You must verify that each task meets all project standards. "Complete" means the code is fully implemented, idiomatic, tested, lint-free, follows Stringy's architecture, and aligns with all coding and architectural rules.

### Task Execution Process

- Review the codebase to determine whether the task is already complete **according to project standards**.
- If the task is not fully compliant:
  - Make necessary code changes using idiomatic, maintainable approaches following Stringy's patterns.
  - Run `just fmt` to apply formatting rules.
  - Add or update tests to ensure correctness.
  - Run the test suites:
    - `just test`
  - Fix any failing tests.
  - Run the linters:
    - `just lint`
  - Fix all linter issues.
- Run `just ci-check` to confirm the full codebase passes comprehensive CI validation (format, lint, test, build, audit).

## Completion Checklist

- [ ] Code conforms to Stringy project rules and standards
- [ ] Tests pass (`just test`)
- [ ] Linting is clean (`just lint`)
- [ ] Full CI validation passes (`just ci-check`)
- [ ] Task is marked complete in the checklist
- [ ] A short summary of what was done is reported

> Update the current task list with any items that are implemented and need test coverage, checking off items that have implemented tests. ❌ Do **not** commit or check in any code ⏸️ Do **not** begin another task ✅ Stop and wait for further instruction after completing this task
