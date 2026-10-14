#!/bin/sh
# phantom installer (Linux / WSL / macOS) — user-scope, no root needed for the core.
#
#   curl -fsSL https://raw.githubusercontent.com/Terminalkid09/Phantom/main/install/install.sh | sh
#
# What it does:
#   1. checks python >= 3.10 (tells you exactly what to install if missing)
#   2. downloads the repository tarball from the BRANCH you chose (github
#      codeload) and checks the archive before touching anything
#   3. installs into ~/.phantom (user scope) — the FILES the framework needs,
#      not the whole working tree
#   4. venv + requirements.txt
#   5. launchers in ~/.local/bin (PATH-checked, user scope)
#   6. prints the follow-up steps (`phantom doctor`, `phantom setup`)
#
# Branch: `dev` by default, because that is the line these docs describe
# (v3.0.0). The released line is `main` (v2.0.0) — install it explicitly with
# `PHANTOM_BRANCH=main`. The installer PRINTS what it installed, so the version
# you get is never a surprise.
#
# Size: the copy is a KEEP-LIST (code, packaging metadata, requirements). The
# old one copied the entire tarball into ~/.phantom — docs, tests, the Electron
# app, `data/` — which is how a "just install it" path grew into ~1 GB. Set
# PHANTOM_FULL_TREE=1 for the old behaviour.
#
# Idempotent: re-running refreshes the install in place.
set -eu

REPO="Terminalkid09/Phantom"
BRANCH="${PHANTOM_BRANCH:-dev}"
DEST="$HOME/.phantom"
BIN_DIR="$HOME/.local/bin"
FULL_TREE="${PHANTOM_FULL_TREE:-0}"

# What a run needs: the package (code + payloads + exploits), the packaging
# metadata `pip install -e .` reads, the requirement list, and the licence/readme.
KEEP="phantom setup.py MANIFEST.in requirements.txt README.md LICENSE"

say()  { printf '  %s\n' "$1"; }
step() { printf '\n[*] %s\n' "$1"; }

printf '\n  Phantom installer (Linux/macOS, user-scope)\n'
printf '  -------------------------------------------\n'

# ── 1. python check
step "Checking python >= 3.10"
PY=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
        if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            PY="$c"; break
        fi
    fi
done
if [ -z "$PY" ]; then
    say "python >= 3.10 not found. Install it with one of:"
    say "  Debian/Ubuntu/Kali : sudo apt-get install -y python3 python3-venv python3-pip"
    say "  Fedora             : sudo dnf install -y python3"
    say "  Arch               : sudo pacman -S python"
    say "  macOS              : brew install python"
    exit 1
fi
say "python found: $($PY --version 2>&1)"

# ── 2. download tarball
step "Downloading phantom (branch: $BRANCH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
URL="https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TMP/phantom.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP/phantom.tar.gz" "$URL"
else
    say "need curl or wget to download — install one and retry"
    exit 1
fi
# integrity, in the order a failure is likely:
#   1. a real tarball is megabytes; a captive-portal HTML page is not;
#   2. it must actually be gzip + tar (a truncated download passes #1);
#   3. it must contain the files this script is about to rely on. Size alone
#      says nothing about WHAT was downloaded — that was the old check.
SIZE=$(wc -c < "$TMP/phantom.tar.gz")
if [ "$SIZE" -lt 100000 ]; then
    say "download looks truncated ($SIZE bytes) — aborting"
    exit 1
fi
if ! gzip -t "$TMP/phantom.tar.gz" 2>/dev/null; then
    say "download is not a gzip archive (captive portal? proxy?) — aborting"
    exit 1
fi
if ! tar -tzf "$TMP/phantom.tar.gz" >/dev/null 2>&1; then
    say "download is not a readable tar archive — aborting"
    exit 1
fi
say "downloaded $((SIZE / 1024)) KiB from branch '$BRANCH'"

# ── 3. extract (contents at the repo root) and install the KEEP-LIST
step "Installing into $DEST"
tar -xzf "$TMP/phantom.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -maxdepth 1 -type d -name 'Phantom-*' | head -n 1)"
if [ -z "$SRC" ]; then
    say "archive layout unexpected — aborting"
    exit 1
fi
for needed in phantom/main.py requirements.txt setup.py; do
    if [ ! -e "$SRC/$needed" ]; then
        say "this archive has no $needed — wrong branch or a partial tag?"
        say "branch '$BRANCH' may not exist; try PHANTOM_BRANCH=main"
        exit 1
    fi
done
mkdir -p "$DEST"
if [ "$FULL_TREE" = "1" ]; then
    say "PHANTOM_FULL_TREE=1: copying the whole tree (old behaviour)"
    cp -a "$SRC/." "$DEST/"
else
    for item in $KEEP; do
        [ -e "$SRC/$item" ] || continue
        cp -a "$SRC/$item" "$DEST/"
    done
fi
say "installed: $(du -sh "$DEST" 2>/dev/null | cut -f1) of files in $DEST (the venv below adds more)"

# ── 4. venv + deps
step "Creating virtualenv"
"$PY" -m venv "$DEST/.venv"
step "Installing dependencies (this can take a few minutes)"
"$DEST/.venv/bin/python" -m pip install --quiet --disable-pip-version-check \
    -r "$DEST/requirements.txt"

# ── 5. launchers (user scope)
step "Writing launchers to $BIN_DIR"
mkdir -p "$BIN_DIR"
for name in phantom phantom.c2 phantom.auto; do
    cat > "$BIN_DIR/$name" <<EOF
#!/bin/sh
exec "$DEST/.venv/bin/python" "$DEST/phantom/main.py" "\$@"
EOF
    chmod +x "$BIN_DIR/$name"
done

# PATH check (user scope only — never touches /etc)
case ":$PATH:" in
    *":$BIN_DIR:"*) say "PATH already contains $BIN_DIR" ;;
    *)
        if [ -f "$HOME/.profile" ] && ! grep -qs "$BIN_DIR" "$HOME/.profile"; then
            printf '\n# added by phantom installer\nexport PATH="$PATH:%s"\n' "$BIN_DIR" >> "$HOME/.profile"
            say "added $BIN_DIR to PATH via ~/.profile (open a new shell)"
        else
            say "NOTE: $BIN_DIR is not in PATH — add it to your shell profile"
        fi
        ;;
esac

printf '\n'
printf '  [OK] phantom installed from branch %s (user scope)\n\n' "$BRANCH"
printf '  %s\n' "$(grep -m1 -E '^version|version=' "$DEST/setup.py" 2>/dev/null | tr -d ' ' || true)"
printf '  next steps:\n'
printf '    phantom doctor      - what is missing (tools, docker)\n'
printf '    phantom setup       - guided toolbox setup (asks once, installs)\n'
printf '    phantom             - manual core | phantom.c2 | phantom.auto\n\n'
printf '  note: on Linux the toolbox step may ask for sudo to apt/dnf/pacman\n'
printf '  install the offensive tools — it always shows the exact list first.\n'
