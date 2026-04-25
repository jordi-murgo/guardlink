```markdown
# guardlink Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you how to contribute to the `guardlink` TypeScript codebase, following its established conventions and workflows. You'll learn the project's file organization, coding style, testing approach, and the step-by-step processes for adding new features or expanding operational modes. This guide ensures consistency, reliability, and maintainability across all contributions.

## Coding Conventions

**File Naming**
- Use `camelCase` for file names.
  - Example: `parserUtils.ts`, `agentManager.ts`

**Import Style**
- Use relative imports.
  - Example:
    ```typescript
    import { parseDiff } from './parserUtils';
    ```

**Export Style**
- Use named exports.
  - Example:
    ```typescript
    // In src/parserUtils.ts
    export function parseDiff(...) { ... }
    export const DIFF_PATTERN = /.../;
    ```

**Commit Messages**
- Follow [Conventional Commits](https://www.conventionalcommits.org/) with the prefix `feat` for new features.
  - Example: `feat: add support for multi-agent review mode`

## Workflows

### Feature Development with Tests and Docs
**Trigger:** When adding a significant new capability or enhancement  
**Command:** `/new-feature`

1. Implement the feature logic in relevant `src/` files (e.g., `src/parserUtils.ts`, `src/review/`, `src/agents/`, `src/cli/`).
    ```typescript
    // src/agents/newAgent.ts
    export function newAgent(...) { ... }
    ```
2. Update or add new types in `src/types/`.
    ```typescript
    // src/types/agentTypes.ts
    export type AgentMode = 'single' | 'multi';
    ```
3. Write or update test suites in `tests/` (e.g., `parser.test.ts`, `agents.test.ts`).
    ```typescript
    // tests/agents.test.ts
    import { describe, it, expect } from 'vitest';
    import { newAgent } from '../src/agents/newAgent';

    describe('newAgent', () => {
      it('should initialize correctly', () => {
        expect(newAgent(...)).toBe(...);
      });
    });
    ```
4. Update documentation files (e.g., `docs/SPEC.md`, `README.md`, `AGENTS.md`) to reflect the new feature.
5. Update templates or agent instruction files if needed.
6. Bump the package version and update lock files (`package.json`, `package-lock.json`, `bun.lock`).

### Mode or Configuration Expansion
**Trigger:** When introducing a new operational mode or configuration flag  
**Command:** `/add-mode`

1. Update CLI and server logic to recognize the new mode or flag (e.g., `src/cli/index.ts`, `src/mcp/server.ts`).
    ```typescript
    // src/cli/index.ts
    if (args.includes('--experimental-mode')) {
      // handle new mode
    }
    ```
2. Update agents and prompts to support the new mode (e.g., `src/agents/`).
3. Update TUI commands/help text if applicable (`src/tui/commands.ts`).
4. Add or update tests to cover new mode values (`tests/`).
5. Update documentation to reflect new options (`docs/`, `README.md`).

## Testing Patterns

- Use [vitest](https://vitest.dev/) for all tests.
- Place test files alongside or mirroring source files, named as `*.test.ts`.
  - Example: `tests/agents.test.ts`
- Structure tests with `describe` and `it` blocks.
  - Example:
    ```typescript
    import { describe, it, expect } from 'vitest';
    import { parseDiff } from '../src/parserUtils';

    describe('parseDiff', () => {
      it('parses unified diffs', () => {
        expect(parseDiff('diff ...')).toEqual(...);
      });
    });
    ```

## Commands

| Command      | Purpose                                                      |
|--------------|--------------------------------------------------------------|
| /new-feature | Start a new feature with tests and documentation             |
| /add-mode    | Add or expand a mode/configuration with code and documentation|
```
