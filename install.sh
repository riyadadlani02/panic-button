#!/bin/sh
# Installs the `panic` command for the current user (macOS; Linux is untested and shows no notifications).
#   curl -LsSf https://raw.githubusercontent.com/riyadadlani02/panic-button/main/install.sh | sh
# It installs uv (https://astral.sh/uv) when missing, then panic-button into uv's own tool folder.
# Nothing needs sudo. Remove it again with: uv tool uninstall panic
set -eu
SOURCE="${PANIC_SOURCE:-git+https://github.com/riyadadlani02/panic-button}"

if ! command -v uv >/dev/null 2>&1; then
    echo "Installing uv, which fetches Python and runs the tool ..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    PATH="$HOME/.local/bin:$PATH"
fi
uv tool install --force --python 3.12 "$SOURCE"
uv tool update-shell >/dev/null 2>&1 || true  # puts the tool folder on PATH for new terminal windows

echo
echo "Installed. Open a new terminal window, then run:"
echo "    panic setup"
