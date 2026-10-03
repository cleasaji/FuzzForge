#!/usr/bin/env bash
# Publish this repo to GitHub as cleasaji/FuzzForge.
# Needs ONE of: the GitHub CLI logged in (gh auth login), or git already
# configured with credentials for github.com.
set -euo pipefail
OWNER="${GITHUB_OWNER:-cleasaji}"
REPO="${REPO_NAME:-FuzzForge}"
cd "$(dirname "$0")"
[ -d .git ] || { git init -q -b main; git add -A; git commit -q -m "feat: FuzzForge coverage-guided fuzzer"; }
if command -v gh >/dev/null 2>&1; then
  gh repo create "$OWNER/$REPO" --public --source=. --remote=origin --push \
    --description "Coverage-guided fuzzer for Python: edge coverage, power scheduling, crash dedup, minimization" \
    || { git remote add origin "https://github.com/$OWNER/$REPO.git" 2>/dev/null || true; git push -u origin main; }
else
  echo "Create an empty repo named $REPO on github.com first, then:"
  git remote add origin "https://github.com/$OWNER/$REPO.git" 2>/dev/null || true
  git push -u origin main
fi
echo "Pushed: https://github.com/$OWNER/$REPO"
