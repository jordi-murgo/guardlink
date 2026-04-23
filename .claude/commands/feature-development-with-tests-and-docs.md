---
name: feature-development-with-tests-and-docs
description: Workflow command scaffold for feature-development-with-tests-and-docs in guardlink.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /feature-development-with-tests-and-docs

Use this workflow when working on **feature-development-with-tests-and-docs** in `guardlink`.

## Goal

Implements a new feature or major enhancement, including code changes, test coverage, and documentation updates.

## Common Files

- `src/**/*.ts`
- `src/types/**/*.ts`
- `tests/**/*.test.ts`
- `docs/**/*.md`
- `README.md`
- `AGENTS.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Implement feature logic in relevant src/ files (e.g., parser, review, diff, agents, cli, etc.)
- Update or add new types in src/types/
- Update or add test suites in tests/ (e.g., parser.test.ts, review.test.ts, agents.test.ts, prompts.test.ts)
- Update documentation files (e.g., docs/SPEC.md, docs/GUARDLINK_REFERENCE.md, README.md, AGENTS.md)
- Update templates or agent instruction files if needed

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.