#!/usr/bin/env bash
# Launch cartographer from its venv, whatever the cwd.
# First run creates the venv; an interactive run offers a system-wide install.
set -u
d="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
name=cartographer
cfg="${XDG_CONFIG_HOME:-$HOME/.config}/$name"
declined="$cfg/no-install-prompt"

setup_venv() {
  echo "$name: first run, creating virtualenv in $d/.venv ..." >&2
  if command -v uv >/dev/null 2>&1; then
    uv venv -q "$d/.venv" && uv pip install -q --python "$d/.venv/bin/python" textual
  else
    python3 -m venv "$d/.venv" && "$d/.venv/bin/pip" install -q textual
  fi || {
    echo "$name: venv setup failed. Needs python3-venv (Debian/Ubuntu: sudo apt install python3-venv) or uv." >&2
    exit 1
  }
}

# Where a system-wide link goes: /usr/local/bin if we can write it (or sudo),
# otherwise ~/.local/bin.
link_target() {
  if [ "$(id -u)" -eq 0 ] || [ -w /usr/local/bin ] || command -v sudo >/dev/null 2>&1; then
    echo /usr/local/bin
  else
    echo "$HOME/.local/bin"
  fi
}

install_link() {
  local dir; dir="$(link_target)"
  if [ "$dir" = /usr/local/bin ] && [ "$(id -u)" -ne 0 ] && [ ! -w "$dir" ]; then
    sudo ln -sf "$d/cartographer.sh" "$dir/$name"
  else
    mkdir -p "$dir" && ln -sf "$d/cartographer.sh" "$dir/$name"
  fi || { echo "$name: install failed." >&2; return 1; }
  echo "Installed: $dir/$name -> $d/cartographer.sh"
  case ":$PATH:" in *":$dir:"*) ;; *) echo "Note: $dir is not on your PATH." ;; esac
}

uninstall_link() {
  local f removed=0
  for f in /usr/local/bin/$name "$HOME/.local/bin/$name"; do
    [ -L "$f" ] && [ "$(readlink -f "$f")" = "$d/cartographer.sh" ] || continue
    if [ -w "$(dirname "$f")" ]; then rm -f "$f"; else sudo rm -f "$f"; fi && echo "Removed $f" && removed=1
  done
  [ "$removed" -eq 1 ] || echo "No installed link found."
}

offer_install() {
  [ -t 0 ] && [ -t 1 ] || return 0
  command -v "$name" >/dev/null 2>&1 && return 0
  [ -e "$declined" ] && return 0
  local dir ans; dir="$(link_target)"
  printf "Install %s system-wide (symlink in %s) so you can just run '%s'? [y/N/never] " "$name" "$dir" "$name"
  read -r ans || return 0
  case "$ans" in
    [yY]|[yY][eE][sS]) install_link ;;
    [nN][eE][vV][eE][rR]) mkdir -p "$cfg" && : > "$declined" && echo "OK, won't ask again. Run '$0 --install' any time." ;;
    *) echo "Skipped. Run '$0 --install' any time." ;;
  esac
}

case "${1:-}" in
  --install)   install_link; exit $? ;;
  --uninstall) uninstall_link; exit $? ;;
esac

[ -x "$d/.venv/bin/python" ] || setup_venv
offer_install
PYTHONPATH="$d" exec "$d/.venv/bin/python" -m cartographer "$@"
