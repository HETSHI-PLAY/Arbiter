#!/usr/bin/env bash
# Symlink the shared AI-agent config into the various extension/tool locations
# that look for project context, so a single source stays authoritative.
#
#   - AGENTS.md        -> CLAUDE.md (legacy Claude Code entry)
#   - .ai/             -> .claude/   (some tools expect .claude/)
#
# Run from the repo root. Re-run after `git clone` or a clean checkout.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

[ -f AGENTS.md ] || { echo "AGENTS.md not found in $DIR" >&2; exit 1; }

ln -sf AGENTS.md CLAUDE.md
ln -sfn .ai .claude

echo "Symlinks ready:"
echo "  CLAUDE.md -> AGENTS.md"
echo "  .claude   -> .ai"
