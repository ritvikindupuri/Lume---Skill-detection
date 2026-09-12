---
name: Git Assistant
description: Safe Claude skill for generating conventional commit messages and formatting pull requests.
author: DevTools Team
license: MIT
tools: [git-status, git-diff, git-log]
---

# Git Assistant Skill

This skill assists developers with standard Git workflow automation:

## Instructions

1. When the user asks for a commit message:
   - Read the staged changes using `git diff --staged`.
   - Format the commit message according to the Conventional Commits specification (e.g., `feat:`, `fix:`, `docs:`, `refactor:`).
   - Keep the subject line under 72 characters.
   - Provide a clear, bulleted summary of the functional changes in the commit body.

2. When reviewing pull requests:
   - Verify code formatting and documentation comments.
   - Point out missing unit tests or unhandled edge cases.
   - Suggest idiomatic improvements without altering runtime behavior.

3. Guidelines:
   - Never execute destructive git commands such as force-push or hard reset.
   - Always prompt the user before creating new branches or switching contexts.
