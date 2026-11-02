#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-vuln-skill}"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v git >/dev/null || { echo 'Install Git first.' >&2; exit 1; }
command -v gh >/dev/null || { echo 'Install GitHub CLI from https://cli.github.com/ first.' >&2; exit 1; }
gh auth status || { echo 'Run: gh auth login' >&2; exit 1; }
if [ ! -d .git ]; then git init; fi
git add .
if ! git diff --cached --quiet; then
  git commit -m "Initial Vuln-Skill research prototype"
fi
git branch -M main
if git remote get-url origin >/dev/null 2>&1; then
  echo 'Existing origin found; refusing to overwrite it. Check git remote -v.' >&2
  exit 1
fi
gh repo create "$NAME" --public --source . --remote origin --push
