#!/usr/bin/env bash
# Pre-execution validation hook: refuse to run obviously dangerous shell
# patterns that would leak secrets or touch the live database.
set -euo pipefail

input="${1:-}"

# Block reads of secrets / live data.
case "$input" in
  *".env"*|*"secret.key"*)
    echo "validate-bash: blocked — references .env or secret.key" >&2
    exit 1
    ;;
esac

# Block the forbidden live-database test suite.
case "$input" in
  *"tests.test_api"*)
    echo "validate-bash: blocked — tests.test_api hits live PostgreSQL" >&2
    exit 1
    ;;
esac

exit 0
