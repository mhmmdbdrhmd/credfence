#!/usr/bin/env bash
# Install credfence: the `vlt` CLI, and the Claude Code guard that enforces it.
#
# Safe to re-run. It never touches an existing vault, and it backs up any file
# it replaces. `./install.sh --uninstall` reverses everything except your vault,
# which is left alone deliberately — uninstalling a tool should not destroy the
# secrets it was holding.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${VLT_BIN_DIR:-$HOME/.local/bin}"
SHARE="${VLT_HOME:-$HOME/.local/share/vlt}"
CLAUDE="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
STAMP="$(date +%Y%m%d-%H%M%S)"

say()  { printf '  %s\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31mx\033[0m %s\n' "$*" >&2; exit 1; }

backup() {  # backup <file> — keep whatever was there before
  [ -e "$1" ] || return 0
  cp -a "$1" "$1.pre-vlt-$STAMP"
  say "kept your previous $(basename "$1") as $(basename "$1").pre-vlt-$STAMP"
}

# --------------------------------------------------------------- uninstall
if [ "${1:-}" = "--uninstall" ]; then
  head_ "Removing credfence"
  rm -f "$BIN/vlt" "$BIN/vlt-ssh" "$SHARE/vltlib.py" "$SHARE/vltui.py"
  rm -f "$CLAUDE/hooks/vault-guard.py"
  rm -rf "$CLAUDE/skills/vault"
  python3 - "$CLAUDE/settings.json" <<'PY' || true
import json, sys, os
p = sys.argv[1]
if os.path.exists(p):
    d = json.load(open(p))
    pre = d.get("hooks", {}).get("PreToolUse", [])
    keep = [h for h in pre if "vault-guard" not in json.dumps(h)]
    if len(keep) != len(pre):
        d["hooks"]["PreToolUse"] = keep
        if not keep:
            d["hooks"].pop("PreToolUse", None)
        if not d.get("hooks"):
            d.pop("hooks", None)
        json.dump(d, open(p, "w"), indent=2)
        print("  removed the guard hook from settings.json")
PY
  say "removed the CLI, the guard and the skill"
  warn "your vault at $SHARE was NOT deleted — it still holds your secrets"
  say "to destroy it permanently: rm -rf $SHARE   (and clear the keyring entry)"
  exit 0
fi

# ------------------------------------------------------------ requirements
head_ "Checking requirements"

command -v python3 >/dev/null || die "python3 is required"
command -v sshpass >/dev/null \
  || warn "no sshpass: vlt-ssh will log in with keys but not with passwords"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)' \
  || die "python3 >= 3.8 required (found $PYV)"
say "python $PYV"

python3 -c 'import cryptography' 2>/dev/null \
  || die "the 'cryptography' package is required:  pip install cryptography"
say "cryptography present"

KEYRING=no
KEYRING_KIND=none
case "$(uname -s)" in
  Darwin)
    KEYRING_KIND="macOS login keychain"
    # `security list-keychains` is read-only and never prompts.
    if [ -x /usr/bin/security ] && /usr/bin/security list-keychains >/dev/null 2>&1
    then KEYRING=yes; fi
    ;;
  *)
    KEYRING_KIND="Secret Service (gnome-keyring, kwallet, keepassxc)"
    if python3 -c 'import secretstorage' 2>/dev/null; then
      if python3 - <<'PY' 2>/dev/null
import secretstorage
c = secretstorage.dbus_init()
secretstorage.get_default_collection(c)
PY
      then KEYRING=yes; fi
    fi
    ;;
esac

if [ "$KEYRING" = yes ]; then
  say "keyring reachable: $KEYRING_KIND — the master key will not be a file on disk"
else
  warn "NO SYSTEM KEYRING REACHABLE ($KEYRING_KIND)."
  warn "vlt keeps its master key in the keyring precisely so that it is not a"
  warn "readable file. Without one, the key must live at $SHARE/.master.key,"
  warn "mode 0400 — a weaker model: anything running as you can read it."
  warn "vlt will refuse to start until you accept that explicitly:"
  warn "    export VLT_ALLOW_FILE_KEY=1"
  case "$(uname -s)" in
    Darwin) warn "On macOS /usr/bin/security should already be present; check" \
                 "that a login keychain exists (Keychain Access.app)." ;;
    *)      warn "On Linux install gnome-keyring or another Secret Service" \
                 "provider, plus python3-secretstorage." ;;
  esac
fi

# Whatever opens the separate window that a person types credentials into.
case "$(uname -s)" in
  Darwin)
    command -v osascript >/dev/null \
      && say "found osascript (Terminal.app + confirmation dialogs)" \
      || warn "no osascript: 'vlt request' cannot open a window, and human-only
      commands will need a real terminal instead of a dialog"
    ;;
  *)
    for c in zenity gnome-terminal xterm; do
      command -v "$c" >/dev/null && say "found $c" && break
    done
    command -v zenity >/dev/null || command -v gnome-terminal >/dev/null || \
      warn "no zenity or gnome-terminal: 'vlt request' cannot open a window for you,
      and human-only commands will need a real terminal instead of a dialog"
    ;;
esac

# ------------------------------------------------------------------ install
head_ "Installing the CLI"
mkdir -p "$BIN" "$SHARE"
chmod 700 "$SHARE"
backup "$BIN/vlt"
install -m 755 "$REPO/vlt" "$BIN/vlt"
backup "$BIN/vlt-ssh"
install -m 755 "$REPO/vlt-ssh" "$BIN/vlt-ssh"
install -m 600 "$REPO/vltlib.py" "$SHARE/vltlib.py"
install -m 600 "$REPO/vltui.py" "$SHARE/vltui.py"
say "vlt        -> $BIN/vlt"
say "vlt-ssh    -> $BIN/vlt-ssh"
say "vltlib.py  -> $SHARE/"
say "vltui.py   -> $SHARE/"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) warn "$BIN is not on your PATH; add it to your shell profile:"
     warn "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

head_ "Initialising the vault"
if [ -f "$SHARE/index.json" ]; then
  say "an existing vault was found — left untouched"
else
  "$BIN/vlt" init
fi

# ------------------------------------------------------- Claude Code wiring
if [ -d "$CLAUDE" ]; then
  head_ "Wiring Claude Code"
  mkdir -p "$CLAUDE/hooks" "$CLAUDE/skills/vault"
  backup "$CLAUDE/hooks/vault-guard.py"
  install -m 755 "$REPO/integrations/claude-code/vault-guard.py" \
    "$CLAUDE/hooks/vault-guard.py"
  install -m 644 "$REPO/integrations/claude-code/SKILL.md" \
    "$CLAUDE/skills/vault/SKILL.md"
  say "guard hook -> $CLAUDE/hooks/vault-guard.py"
  say "skill      -> $CLAUDE/skills/vault/SKILL.md"

  backup "$CLAUDE/settings.json"
  python3 - "$CLAUDE/settings.json" "$CLAUDE/hooks/vault-guard.py" <<'PY'
import json, os, sys
path, hook = sys.argv[1], sys.argv[2]
d = json.load(open(path)) if os.path.exists(path) else {}
entry = {
    "matcher": "Read|Edit|Write|NotebookEdit|Bash|Grep|Glob",
    "hooks": [{"type": "command", "command": "python3 %s" % hook, "timeout": 10}],
}
pre = d.setdefault("hooks", {}).setdefault("PreToolUse", [])
pre[:] = [h for h in pre if "vault-guard" not in json.dumps(h)]
pre.append(entry)
json.dump(d, open(path, "w"), indent=2)
print("  registered the guard as a PreToolUse hook")
PY
  cat <<EOF

  Add this to $CLAUDE/CLAUDE.md so every session knows the rule
  (the hook enforces it either way; this stops agents wasting turns discovering it):

# credentials — ALWAYS via the vault
NEVER read .env, ~/.ssh, ~/.netrc, *.pem or ~/.aws/credentials. NEVER search for
keys, tokens or passwords. NEVER ask for a credential VALUE in chat. Read
~/.claude/skills/vault/SKILL.md FIRST. Find: \`vlt list\` -> \`vlt peek\`.
Use: \`vlt exec\`, \`vlt file\`, \`vlt render\`. Missing: \`vlt request\`.
EOF
else
  head_ "Claude Code not detected"
  say "no $CLAUDE directory; the CLI is installed and usable on its own."
  say "See integrations/ for how enforcement works and what it needs."
fi

head_ "Done"
say "vlt ui        browse the vault"
say "vlt --help    everything else"
say "vlt doctor    check the install"
echo
warn "BACK UP YOUR MASTER KEY. Without it every secret is unrecoverable:"
warn "    VLT_HUMAN=1 vlt identity export ~/vlt-master-key.txt"
warn "then move that file off this machine and delete the copy."
