#!/usr/bin/env bash
# Launch cartographer from its venv, whatever the cwd.
d="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
exec "$d/.venv/bin/python" -m cartographer "$@"
