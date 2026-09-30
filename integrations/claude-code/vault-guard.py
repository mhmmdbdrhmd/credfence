#!/usr/bin/env python3
"""vault-guard — Claude Code PreToolUse/PostToolUse hook for the vlt vault.

Enforces, mechanically, what an instruction cannot:
  * agents cannot read the vault's encrypted store or its master key
  * agents cannot read credential files anywhere else (~/.ssh, .env, .netrc, ...)
  * agents cannot hunt the filesystem for secret VALUES
  * agents cannot read back a file that `vlt render`/`vlt file` just wrote
  * agents cannot disable this hook or the vlt CLI

Modes (`vlt guard on|warn|off`):
  on   deny + log      warn  allow + log      off  passthrough
"""

import json
import os
import re
import sys
import time

HOME = os.path.expanduser("~")
VLT_HOME = os.environ.get("VLT_HOME", os.path.join(HOME, ".local/share/vlt"))
STORE = os.path.join(VLT_HOME, "store")
GUARD = os.path.join(VLT_HOME, "guard.mode")
AUDIT = os.path.join(VLT_HOME, "audit.log")
RENDERED = os.path.join(VLT_HOME, "rendered.json")
POLICY = os.path.join(VLT_HOME, "policy.json")

USE_VLT = (
    "Use the vault instead:\n"
    "  vlt list                          what credentials exist\n"
    "  vlt peek <name>                   field names + leading chars (structure)\n"
    "  vlt exec <name> -- <command>      run a command with it in the environment\n"
    "  vlt file <name> <field> --out P   write one field straight to a file\n"
    "  vlt render --secret <name> --out F  write a config/.env directly\n"
    "  vlt request <name> --fields a,b   missing? opens a window for the user\n"
    "Never read, print, echo or cat a credential value."
)

# --------------------------------------------------------------- protected paths

SELF_PATHS = [
    os.path.join(HOME, ".claude/hooks/vault-guard.py"),
    os.path.join(HOME, ".local/bin/vlt"),
    os.path.join(HOME, ".local/bin/vlt-ssh"),
    os.path.join(VLT_HOME, "vltlib.py"),
    os.path.join(VLT_HOME, "policy.json"),
    os.path.join(VLT_HOME, "guard.mode"),
]

VAULT_PATHS = [STORE, os.path.join(VLT_HOME, ".master.key"), AUDIT]

# Credential files elsewhere on the machine.
LEGACY_RE = re.compile(
    r"(?:^|/)(?:"
    r"\.ssh/id_[^/]*(?<!\.pub)"
    r"|\.ssh/identity"
    r"|\.netrc|_netrc"
    r"|\.npmrc|\.pypirc|\.git-credentials"
    r"|\.aws/credentials|\.aws/config"
    r"|\.docker/config\.json"
    r"|\.kube/config"
    r"|\.config/gh/hosts\.yml"
    r"|\.claude/\.credentials\.json"
    r"|\.env(?!\.(?:example|sample|template|dist|tpl)$)(?:\.[A-Za-z0-9_.-]+)?"
    r"|[A-Za-z0-9_.-]*\.env"
    r"|credentials(?:\.[A-Za-z0-9]+)?"
    r"|secrets?(?:\.(?:json|ya?ml|env|txt|py|js|ts))"
    r"|[^/]*\.(?:pem|pfx|p12|jks|keystore)"
    r"|id_rsa|id_ecdsa|id_ed25519"
    r")$",
    re.IGNORECASE,
)

# Machine-operational credentials: still denied to agents, but never migrated away.
MACHINE_OPERATIONAL = re.compile(
    r"(?:\.cert/nm-openvpn/|\.config/kdeconnect/|\.mitmproxy/|"
    r"Library/Keychains/|"
    r"\.claude/\.credentials\.json)")

# Reading the keyring directly would bypass the vault entirely.
KEYRING_RE = re.compile(
    r"\b(?:secret-tool|secretstorage|SecretService|gnome-keyring|kwalletcli|"
    r"vlt-master-identity|python[0-9.]*\s+-c[^\n]*keyring"
    # macOS: the login keychain is the same asset by another name.
    r"|security\s+(?:-\w+\s+)*(?:find|add|delete)-(?:generic|internet)-password"
    r"|dump-keychain|login\.keychain(?:-db)?"
    r")\b", re.IGNORECASE)

# vlt subcommands that reveal values.
VLT_DENIED_RE = re.compile(
    r"\bvlt\s+(?:_values|get|show|export|add|edit|set|rm|identity|import|"
    r"hide|unhide|rename|ui|keyring)\b")

# `vlt exec ... -- env` injects the secret and then prints the environment.
# The CLI refuses this too; blocking it here as well means neither layer is
# the only thing standing between the secret and the transcript.
VLT_EXEC_DUMP_RE = re.compile(
    r"\bvlt\s+exec\b[^\n]*?(?:^|[\s|;&(])"
    r"(?:env|printenv|set|export|declare|typeset|compgen)\b"
    r"|\bvlt\s+exec\b[^\n]*/proc/(?:self|[0-9]+)/environ"
    r"|\bvlt\s+exec\b[^\n]*--allow-interpolation")

# Hunting for secret VALUES (as opposed to grepping source for the word).
VALUE_HUNT_RE = re.compile(
    r"(?:BEGIN\s+(?:RSA|OPENSSH|EC|PGP|DSA)?\s*PRIVATE\s+KEY"
    r"|\bghp_|\bgithub_pat_|\bgho_|\bsk-[A-Za-z0-9]|\bxox[baprs]-"
    r"|\bAKIA[A-Z0-9]|\bASIA[A-Z0-9]|\bAIza[A-Za-z0-9]"
    r"|\bglpat-|\bshpat_|\bBearer\s+[A-Za-z0-9._-]{12}"
    r"|(?:api[_-]?key|secret|passwo?rd|token)\s*[=:]\s*['\"][^'\"]{6,}"
    r")", re.IGNORECASE)

# Verb obfuscation: c""at, c\at, 'c'at all spell `cat`. Strip quoting before
# any verb match so the spelling cannot matter.
OBFUSC_RE = re.compile(r"""['"\\]""")

# A credential file named without any directory: `cd ~/.ssh && cat id_rsa`.
CRED_BASENAME_RE = re.compile(
    r"^(?:\.env(?!\.(?:example|sample|template|dist|tpl)$)(?:\..*)?"
    r"|[A-Za-z0-9_.-]*\.env"
    r"|\.netrc|_netrc|\.npmrc|\.pypirc|\.git-credentials"
    r"|credentials(?:\..*)?|secrets?\.(?:json|ya?ml|env|txt|py|js|ts)"
    r"|id_rsa|id_dsa|id_ecdsa|id_ed[0-9]+"
    r"|.*\.(?:pem|pfx|p12|jks|keystore))$", re.IGNORECASE)

# Decode-then-execute hides the payload from every static check above.
DECODER_EXEC_RE = re.compile(
    r"(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r|openssl\s+enc\s+-d|uudecode|"
    r"gunzip|zcat)[^|]*\|\s*(?:ba|z|k|da)?sh\b"
    r"|\|\s*(?:ba|z|k|da)?sh\s*$"
    r"|\beval\s"
    r"|(?:curl|wget)[^|]*\|\s*(?:ba|z|k|da)?sh\b",
    re.IGNORECASE | re.MULTILINE)

# Interpreter one-liners that open files. The path may be built at runtime, so
# the only safe move is to refuse file reads from inline interpreter code.
INTERP_RE = re.compile(
    r"\b(?:python[0-9.]*|perl|ruby|node|php)\b[^\n]*?(?:\s-c|\s-e|\s--eval|\s-p)\b",
    re.IGNORECASE)

# A file-opening call of any flavour.
INTERP_OPEN_RE = re.compile(
    r"(?:\bopen\s*\(|\bfile_get_contents\s*\(|\breadFileSync\s*\(|"
    r"\bFile\.(?:read|open)\s*\(|\bIO\.read\s*\(|\bPath\s*\(|"
    r"\bfopen\s*\(|\bslurp\b)", re.IGNORECASE)

# ...whose argument is a single plain literal, e.g. open('/etc/hosts')
INTERP_LITERAL_RE = re.compile(
    r"(?:open|file_get_contents|readFileSync|fopen)\s*\(\s*"
    r"(['\"])([^'\"]*)\1\s*[,)]", re.IGNORECASE)

# Anything that means the path is assembled at run time.
INTERP_DYNAMIC_RE = re.compile(
    r"expanduser|expandvars|environ|getenv|os\.sep|Path\.home|"
    r"\bf['\"]|\+\s*['\"]|['\"]\s*\+|%\s*\(|\.format\s*\(|"
    r"\bglob\b|\blistdir\b|\bwalk\b|\bargv\b|\binput\s*\(",
    re.IGNORECASE)


def interp_violation(cmd):
    """Return a reason if inline interpreter code may read an unknown file."""
    if not INTERP_RE.search(cmd) or not INTERP_OPEN_RE.search(cmd):
        return None
    if INTERP_DYNAMIC_RE.search(cmd):
        return ("BLOCKED: inline interpreter code that builds a file path at "
                "runtime — the guard cannot tell what it would read. Put the "
                "code in a script file, or use `vlt exec`.")
    literals = [m.group(2) for m in INTERP_LITERAL_RE.finditer(cmd)]
    opens = len(INTERP_OPEN_RE.findall(cmd))
    if len(literals) < opens:
        return ("BLOCKED: inline interpreter code opens a file whose path is not "
                "a plain literal, so the guard cannot check it. Put the code in a "
                "script file, or use `vlt exec`.")
    for lit in literals:
        if _is_cred_path_static(lit):
            return ("BLOCKED: that inline code opens %s, a credential file." % lit)
    return None


def _is_cred_path_static(t):
    q = os.path.normpath(os.path.expanduser(os.path.expandvars(t)))
    if LEGACY_RE.search(q) or MACHINE_OPERATIONAL.search(q):
        return True
    for vp in VAULT_PATHS:
        if under(q, vp):
            return True
    return bool(CRED_BASENAME_RE.match(os.path.basename(t.rstrip("/"))))


# Commands that read file contents.
READER_RE = re.compile(
    r"\b(?:cat|bat|less|more|head|tail|strings|xxd|od|hexdump|base64|"
    r"nl|tac|awk|sed|cut|sort|uniq|wc|cp|mv|scp|rsync|tar|zip|gzip|"
    r"install|dd|shred|truncate|tee|source|python[0-9.]*|node|perl|ruby)\b")

SEARCHER_RE = re.compile(r"\b(?:grep|rg|ag|ack|find|fd|locate|fgrep|egrep)\b")

CRED_WORD_RE = re.compile(
    r"\b(?:api[_-]?key|apikey|passwo?rd|passwd|secret|token|credential|"
    r"private[_-]?key|access[_-]?key)\b", re.IGNORECASE)


# -------------------------------------------------------------------- helpers

def mode():
    try:
        with open(GUARD) as fh:
            m = fh.read().strip()
        return m if m in ("on", "warn", "off") else "on"
    except Exception:
        return "on"


def _rotate():
    try:
        if os.path.getsize(AUDIT) > 5 * 1024 * 1024:
            os.replace(AUDIT, AUDIT + ".1")
    except OSError:
        pass


def log(action, detail, allowed):
    try:
        _rotate()
        with open(AUDIT, "a") as fh:
            fh.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "who": "hook", "action": action, "secret": "-",
                "ok": allowed, "detail": detail[:400],
                "cwd": os.getcwd(),
                "session": os.environ.get("CLAUDE_CODE_SESSION_ID", ""),
            }) + "\n")
    except Exception:
        pass


def rendered_paths():
    try:
        with open(RENDERED) as fh:
            return set(json.load(fh))
    except Exception:
        return set()


def policy_extra():
    try:
        with open(POLICY) as fh:
            return json.load(fh)
    except Exception:
        return {}


def norm(p):
    if not p:
        return ""
    p = os.path.expanduser(os.path.expandvars(str(p)))
    if not os.path.isabs(p):
        p = os.path.join(os.getcwd(), p)
    return os.path.normpath(p)


def under(path, root):
    root = os.path.normpath(root)
    return path == root or path.startswith(root + os.sep)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def allow():
    sys.exit(0)


# ------------------------------------------------------------------ path checks

def check_path(path, verb):
    """Return a denial reason for touching `path`, or None."""
    p = norm(path)
    if not p:
        return None

    for sp in SELF_PATHS:
        if p == os.path.normpath(sp) and verb != "read":
            return ("BLOCKED: %s is part of the credential guard itself.\n"
                    "Modifying it would disable the protection. Ask the user to "
                    "change it themselves." % sp)

    for vp in VAULT_PATHS:
        if under(p, vp):
            return ("BLOCKED: %s is vault internals (encrypted records / master "
                    "key / audit log). Agents never touch these directly.\n\n%s"
                    % (p, USE_VLT))

    if p in rendered_paths():
        return ("BLOCKED: %s was written by `vlt` and contains live credential "
                "values. It was created for a program to consume, not for you to "
                "read. Run the program that needs it, or use "
                "`vlt exec` instead.\n\n%s" % (p, USE_VLT))

    if MACHINE_OPERATIONAL.search(p):
        return ("BLOCKED: %s is a machine credential (VPN / device identity / "
                "Claude's own token). It stays where the OS needs it and is not "
                "readable by agents.\n\n%s" % (p, USE_VLT))

    if LEGACY_RE.search(p):
        return ("BLOCKED: %s is a credential file. Agents do not read credential "
                "files — not this one, not .env, not ~/.ssh.\n\n%s" % (p, USE_VLT))

    return None


# ------------------------------------------------------------------ bash checks

def _strip_heredocs(cmd):
    """Remove heredoc bodies.

    A heredoc body is data — a config file, a script for a remote host. It is
    not an operation on this filesystem, and scanning it turns prose and
    comments into false denials. Piping a heredoc to a shell is refused
    separately, so nothing is opened up by ignoring the body.
    """
    lines = cmd.split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        i += 1
        if not m:
            continue
        end = m.group(2)
        while i < len(lines) and lines[i].strip() != end:
            i += 1
        if i < len(lines):
            out.append(lines[i])          # keep the terminator
            i += 1
    return "\n".join(out)


def _strip_comments(cmd):
    """Drop unquoted `# ...` tails. Quoted text is left alone."""
    out = []
    for line in cmd.split("\n"):
        q = None
        cut = None
        for i, ch in enumerate(line):
            if q:
                if ch == q:
                    q = None
            elif ch in "'\"":
                q = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                cut = i
                break
        out.append(line[:cut] if cut is not None else line)
    return "\n".join(out)


def _segments(cmd):
    """Split a compound command so one segment's verb cannot taint another."""
    cmd = _strip_comments(_strip_heredocs(cmd))
    parts = re.split(r"(?:\|\||&&|[;\n|]|\$\(|`)", cmd)
    return [p for p in (x.strip() for x in parts) if p]


def _tokens(seg, with_quoting=False):
    """Tokens of a segment. With `with_quoting`, each is (text, was_quoted)."""
    raw = re.findall(r"""['"]([^'"]*)['"]|(\S+)""", seg)
    out = []
    for a, b in raw:
        if not (a or b):
            continue
        text = (a or b).strip("<>|;&()")
        if text:
            out.append((text, bool(a)) if with_quoting else text)
    return out


def _looks_like_path(t):
    """Does this token claim to be a path at all?

    A bare word in prose — `credentials` in a comment, or `.env` in a sentence
    about .env files — is not a path, and resolving it against the cwd invents
    a file nobody named. Writing `./.env` is a path claim; writing `.env` in
    English is not.
    """
    return ("/" in t) or t.startswith("~")


def _resolve(t, base):
    # Expand first: a tilde only means "home" at the start of a path. Joining
    # before expanding buries it mid-path, where it means nothing — the denial
    # then reports a path that cannot exist, and the existence check runs
    # against that nonsense instead of the real file.
    t = os.path.expanduser(os.path.expandvars(t))
    cand = t if os.path.isabs(t) else os.path.join(base, t)
    return os.path.normpath(cand)


# Directories whose whole purpose is holding credentials. A credential-shaped
# bare name resolved inside one is an operation even before the file exists —
# writing a key there is as much a concern as reading one.
CRED_DIR_RE = re.compile(
    r"(?:^|/)(?:\.ssh|\.gnupg|\.aws|\.docker|\.kube|\.config/gh"
    r"|\.local/share/vlt|Library/Keychains)/?$")


def _cred_match(t, base):
    """Why `t` counts as naming a credential file, or None.

    Returns (resolved_path, verified_exists) so the caller can describe the
    match honestly instead of asserting that a file exists.
    """
    if not t:
        return None
    cand = _resolve(t, base)

    if _looks_like_path(t):
        # An explicit path: the pattern alone is enough. A file that does not
        # exist yet still must not be written or read.
        if (LEGACY_RE.search(cand) or MACHINE_OPERATIONAL.search(cand)
                or CRED_BASENAME_RE.match(os.path.basename(t.rstrip("/")))):
            return (cand, os.path.exists(cand))
        return None

    # A bare word. Two things can make it an operation rather than prose: the
    # file is really there, or the directory it resolves in is one that exists
    # to hold credentials. Prose satisfies neither — it names no real file, and
    # it never `cd`s into ~/.ssh first.
    if not CRED_BASENAME_RE.match(os.path.basename(t.rstrip("/"))):
        return None
    if os.path.exists(cand):
        return (cand, True)
    if CRED_DIR_RE.search(os.path.dirname(cand)):
        return (cand, False)
    return None


def _is_cred_path(p, base):
    """Kept for callers that only need a yes/no."""
    return _cred_match(p, base) is not None


def _describe(t, resolved, exists, seg):
    """Say what matched and where. Never assert a file that was not checked."""
    where = (" in: %s" % seg.strip()[:70]) if seg else ""
    if exists:
        return ("BLOCKED: %s is a credential file, and this command names it%s"
                % (resolved, where))
    # Only a BARE name leans on the directory. An explicit path is refused on
    # the pattern alone, and saying otherwise would misdescribe why.
    parent = os.path.dirname(resolved)
    if not _looks_like_path(t) and CRED_DIR_RE.search(parent):
        return ("BLOCKED: `%s` resolves to %s, inside a directory that exists "
                "to hold credentials%s\n"
                "         (no file is there right now — the directory is what "
                "makes this an operation, not prose)"
                % (t, resolved, where))
    return ("BLOCKED: this command contains the token `%s`, which matches a "
            "credential-file pattern%s\n"
            "         (it would resolve to %s — not checked for existence, and "
            "no claim is made that it exists)"
            % (t, where, resolved))


# A quoted span containing whitespace is prose: a commit message, an echo, a
# --body. A quoted span WITHOUT whitespace is how verbs get obfuscated —
# `c""at`, `'c'at` — so those are left alone for OBFUSC_RE to collapse.
PROSE_SPAN_RE = re.compile(r"'[^'\n]*\s[^'\n]*'"
                           r'|"[^"\n]*\s[^"\n]*"')

# Constructs that hand a quoted string to something which will run it. When one
# is present, quoted text is no longer prose and is checked in full.
SHELL_EXEC_RE = re.compile(
    r"\b(?:sh|bash|zsh|dash|ksh|ash|busybox)\b[^\n]*?\s-c\b"
    r"|\benv\b[^\n]*?\s(?:sh|bash|zsh)\b"
    r"|\beval\b|\bxargs\b|\bsudo\b|\bnohup\b|\bwatch\b"
    r"|\bssh\b|\bdocker\b[^\n]*\bexec\b|\bsu\b\s")


def _verb_probes(seg):
    """Texts to match verb patterns against, prose excluded where it is prose."""
    flat = OBFUSC_RE.sub("", seg)
    if SHELL_EXEC_RE.search(flat) or INTERP_RE.search(flat):
        # `python3 -c '...'` and `sh -c '...'` both run what is inside the
        # quotes, so this segment has no prose to protect.
        return (seg, flat)
    bare = PROSE_SPAN_RE.sub(" ", seg)
    return (bare, OBFUSC_RE.sub("", bare))


def _snippet(seg, width=70):
    seg = " ".join(seg.split())
    return seg if len(seg) <= width else seg[:width - 1] + "\u2026"


def check_bash(cmd):
    # Heredoc bodies and comments are data, not commands — drop them before any
    # verb match, exactly as the path walk already does.
    stripped = _strip_comments(_strip_heredocs(cmd))
    flat = OBFUSC_RE.sub("", stripped)

    # These two match a pipeline or secret-shaped content rather than a verb, so
    # they see the whole command: splitting on `|` would hide `... | sh`, and a
    # hunted VALUE is normally quoted on purpose.
    for probe in (stripped, flat):
        if VALUE_HUNT_RE.search(probe):
            return ("BLOCKED: that command searches for credential VALUES.\n\n%s"
                    % USE_VLT)
        if DECODER_EXEC_RE.search(probe):
            return ("BLOCKED: that command decodes or fetches something and pipes "
                    "it to a shell. The guard cannot see what it would run, so it "
                    "cannot allow it. Run the command directly instead.\n\n%s"
                    % USE_VLT)

    # Verb-shaped checks, per segment, ignoring prose inside quotes.
    for seg in _segments(cmd):
        probes = _verb_probes(seg)
        for probe in probes:
            if VLT_DENIED_RE.search(probe):
                return ("BLOCKED: that `vlt` subcommand reveals secret values or "
                        "changes what is masked, and is human-only.\n"
                        "         (matched in: %s)\n\n%s"
                        % (_snippet(seg), USE_VLT))
            if VLT_EXEC_DUMP_RE.search(probe):
                return ("BLOCKED: that would inject the secret and then print the "
                        "environment it was injected into, putting the value in "
                        "your output. Run the program that consumes the "
                        "credential instead.\n\n%s" % USE_VLT)
            if KEYRING_RE.search(probe):
                return ("BLOCKED: that command reaches the system keyring, where "
                        "the vault master key lives.\n"
                        "         (matched in: %s)\n\n%s"
                        % (_snippet(seg), USE_VLT))

    # Only against the original text: `flat` has had its quotes removed, which
    # would make every string literal look like a runtime-built path.
    iv = interp_violation(cmd)
    if iv:
        return "%s\n\n%s" % (iv, USE_VLT)

    # Walk segments in order, tracking `cd` so relative paths still resolve.
    # The ORIGINAL text is walked, because quoting is structure and `flat` has
    # had all of it removed; each segment is de-obfuscated only to look for
    # verbs.
    base = os.getcwd()
    for seg in _segments(cmd):
        seg_flat = OBFUSC_RE.sub("", seg)
        m = re.match(r"cd\s+(\S+)", seg_flat)
        if m:
            target = os.path.expanduser(os.path.expandvars(m.group(1)))
            base = target if os.path.isabs(target) else os.path.normpath(
                os.path.join(base, target))
            continue

        seg_acts_on_files = bool(READER_RE.search(seg_flat)
                                 or SEARCHER_RE.search(seg_flat))
        for t, quoted in _tokens(seg, with_quoting=True):
            if "$" in t:
                continue          # unexpanded variable — judged via the raw text
            if quoted and not seg_acts_on_files:
                # Inside quotes with nothing in this segment that reads files:
                # a commit message, an echo, a --description. Prose, not an
                # operation. Unquoted tokens are still matched unconditionally.
                continue
            full = _resolve(t, base)
            for vp in VAULT_PATHS:
                if under(full, vp):
                    return ("BLOCKED: %s is vault internals.\n\n%s"
                            % (full, USE_VLT))
            if full in rendered_paths():
                return ("BLOCKED: %s holds live credential values written by "
                        "`vlt`.\n\n%s" % (full, USE_VLT))
            # No verb list: naming a credential file at all is enough —
            # but a bare word must resolve to a real file to count.
            hit = _cred_match(t, base)
            if hit:
                resolved, exists = hit
                return ("%s\n         Agents do not read, copy, move or open "
                        "credential files.\n\n%s"
                        % (_describe(t, resolved, exists, seg), USE_VLT))

        if SEARCHER_RE.search(seg_flat):
            for t in _tokens(seg):
                if "$" in t:
                    continue
                q = _resolve(t, base)
                if (under(q, os.path.join(HOME, ".ssh"))
                        or under(q, os.path.join(HOME, ".aws"))
                        or under(q, os.path.join(HOME, ".cert"))):
                    return ("BLOCKED: %s is a credential directory; agents do not "
                            "search it.\n\n%s" % (q, USE_VLT))

    # A credential path hidden in a variable assignment still shows up as text.
    for m in re.finditer(r"=\s*([~/][^\s;|&\"\']*)", flat):
        if _is_cred_path(m.group(1), os.getcwd()):
            return ("BLOCKED: that command puts a credential file path into a "
                    "variable. Agents do not handle credential files.\n\n%s"
                    % USE_VLT)

    if SEARCHER_RE.search(flat) and CRED_WORD_RE.search(flat) and re.search(
            r"(?:^|\s)(?:-r|-R|--recursive|-rn|-rl|-ri)\b", flat):
        log("cred-search", cmd, True)

    return None


# ---------------------------------------------------------------- search checks

def check_search(tool, inp):
    pattern = str(inp.get("pattern", ""))
    path = inp.get("path") or ""
    if VALUE_HUNT_RE.search(pattern):
        return ("BLOCKED: that %s pattern hunts for credential VALUES. Agents do "
                "not search this machine for secrets.\n\n%s" % (tool, USE_VLT))
    p = norm(path) if path else ""
    if p:
        for root in (os.path.join(HOME, ".ssh"), os.path.join(HOME, ".aws"),
                     os.path.join(HOME, ".cert"), STORE):
            if under(p, root):
                return ("BLOCKED: %s is a credential directory.\n\n%s"
                        % (p, USE_VLT))
    if re.search(r"\.env|\.pem$|id_rsa|id_ed25519|credentials", pattern,
                 re.IGNORECASE):
        return ("BLOCKED: that %s pattern targets credential files. If you need a "
                "credential, get it from the vault.\n\n%s" % (tool, USE_VLT))
    if CRED_WORD_RE.search(pattern):
        log("cred-search", "%s pattern=%s path=%s" % (tool, pattern, path), True)
    return None


# ------------------------------------------------------------------------ main

def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        allow()

    m = mode()
    if m == "off":
        allow()

    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}
    reason = None

    if tool in ("Read", "NotebookRead"):
        reason = check_path(inp.get("file_path"), "read")
    elif tool in ("Edit", "Write", "NotebookEdit"):
        reason = check_path(inp.get("file_path"), "write")
        if not reason and tool == "Write":
            # writing a settings.json that strips this hook
            fp = norm(inp.get("file_path"))
            if fp.endswith(".claude/settings.json") and \
                    "vault-guard" not in str(inp.get("content", "")):
                reason = ("BLOCKED: that would rewrite ~/.claude/settings.json "
                          "without the vault-guard hook, disabling credential "
                          "protection. Ask the user to make this change.")
    elif tool == "Bash":
        reason = check_bash(str(inp.get("command", "")))
    elif tool in ("Grep", "Glob"):
        reason = check_search(tool, inp)

    if reason:
        if m == "warn":
            log("warn", "%s: %s" % (tool, reason.split("\n")[0]), True)
            allow()
        log("deny", "%s: %s" % (tool, reason.split("\n")[0]), False)
        deny(reason)

    allow()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # never break the user's session because of a guard bug
        sys.exit(0)
