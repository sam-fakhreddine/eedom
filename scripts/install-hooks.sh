#!/usr/bin/env bash
set -euo pipefail

HOOK=".git/hooks/pre-commit"
mkdir -p "$(dirname "$HOOK")"

cat > "$HOOK" << 'HOOK_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# Auto-fix lint and formatting on staged files before commit.
# Runs ruff --fix + black on staged .py files, re-stages the fixes.

STAGED=$(git diff --cached --name-only --diff-filter=ACM -- '*.py')
if [ -z "$STAGED" ]; then
    exit 0
fi

# shellcheck disable=SC2086
uv run ruff check --fix $STAGED 2>/dev/null || true
# shellcheck disable=SC2086
uv run black --quiet $STAGED 2>/dev/null || true

# Re-stage any auto-fixed files
# shellcheck disable=SC2086
git add $STAGED

# Final check — fail if unfixable issues remain
# shellcheck disable=SC2086
uv run ruff check $STAGED
HOOK_SCRIPT

chmod +x "$HOOK"
echo "Installed pre-commit hook → $HOOK"
