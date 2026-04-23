---
name: mode-or-configuration-expansion
description: Workflow command scaffold for mode-or-configuration-expansion in guardlink.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /mode-or-configuration-expansion

Use this workflow when working on **mode-or-configuration-expansion** in `guardlink`.

## Goal

Adds or refactors support for new operational modes or configuration options, including CLI, server, and TUI integration, with corresponding tests.

## Common Files

- `src/cli/index.ts`
- `src/mcp/server.ts`
- `src/agents/**/*.ts`
- `src/tui/commands.ts`
- `tests/**/*.test.ts`
- `docs/**/*.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Update CLI and server logic to recognize new mode or flag (e.g., src/cli/index.ts, src/mcp/server.ts)
- Update agents and prompts to support the new mode (e.g., src/agents/)
- Update TUI commands/help text if applicable
- Add or update tests to cover new mode values
- Update documentation to reflect new options

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.