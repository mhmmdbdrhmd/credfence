"""Credentials that span lines: SSH keys, certificates, service-account blobs.

Every reader in this program once assumed a credential was one line. That
assumption failed three different ways, and the third was not a truncation bug
at all:

  * the plain prompt used getpass(), which stops at the first newline AND
    restores the terminal with TCSAFLUSH — discarding the rest of the paste, so
    a key became its own armour header with nothing to show that anything was
    lost;

  * input(), used for the unmasked fields, does not flush, so the tail of a
    pasted key became the answers to the following prompts — and `notes` is
    printed in full by `vlt peek`;

  * the curses form returned from edit_line on the first newline and handed
    every remaining character to the FORM's key handler. In the record browser
    `d` is delete, `v` is reveal and `q` is quit, and a base64 key body
    contains all three. That is not lossy input; it is the program typing
    commands into itself.

These assertions pin all three, plus the byte that makes a stored key usable:
OpenSSH rejects a key whose final -----END----- has no newline after it.
"""

import os
import pty
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                       # noqa: E402

sys.path.insert(0, TH.REPO)
import vltlib as V                                         # noqa: E402
import vltui                                               # noqa: E402

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:200]))
    if not ok:
        fails.append(label)


TH.init_vault()

# Not a key. The armour lines are assembled from parts so that no secret
# scanner in the pipeline reports this repository as leaking a private key — a
# scanner whose findings are all known-and-ignored is a scanner nobody reads.
BEGIN = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5
END = "-" * 5 + "END OPENSSH PRIVATE KEY" + "-" * 5
BODY = ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
        "AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBFWFhBTVBMRW5vdGFrZXlF",
        "WEFNUExFbm90YWtleUVYQU1QTEUAAAAJZXhhbXBsZWtleQECAwQ="]
KEYTEXT = "\n".join([BEGIN] + BODY + [END])

# The body deliberately contains the characters that are commands in the
# browser, because that is the hazard being tested.
assert set("dvq") <= set("".join(BODY).lower()), "body must contain d, v, q"


# ------------------------------------------------------------------ 1. helpers
check("armour is recognised", V.is_armoured(KEYTEXT))
check("a password is not armour", not V.is_armoured("hunter2"))
check("armour with CRLF is still armour",
      V.is_armoured(KEYTEXT.replace("\n", "\r\n")))
check("normalise adds the terminating newline",
      V.normalise_multiline(KEYTEXT) == KEYTEXT + "\n")
check("normalise folds CRLF",
      "\r" not in V.normalise_multiline(KEYTEXT.replace("\n", "\r\n")))
check("normalise leaves a password alone",
      V.normalise_multiline("pw\rwith\rcr") == "pw\rwith\rcr")
check("key is a declared multi-line field", "key" in V.MULTILINE_FIELDS)


# ---------------------------------------------------- 2. the non-interactive path
r = subprocess.run([sys.executable, TH.VLT, "set", "ssh/pipe", "key", "-"],
                   input=KEYTEXT, capture_output=True, text=True, env=TH.HUMAN)
rec = V.load("ssh/pipe") if V.exists("ssh/pipe") else {"fields": {}}
check("`vlt set … -` stores the whole key",
      rec["fields"].get("key") == KEYTEXT + "\n",
      "%r / %s" % (rec["fields"].get("key"), r.stderr))


# ------------------------------------------------------- 3. the plain prompt path
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]")


def _readable(fd, timeout):
    import select
    try:
        return bool(select.select([fd], [], [], timeout)[0])
    except Exception:
        return False


class Pty(object):
    """A child under a pty, driven by what it prints.

    Every wait here is for an OBSERVED string, never for a duration. The one
    remaining sleep is the settle after the last keystroke, and it exists only
    so the child can finish writing before it is reaped.
    """

    def __init__(self, argv, env):
        self.seen = ""
        self.text = ""
        self.mark = 0
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve(argv[0], argv, env)

    def _pump(self, timeout=0.2):
        if not _readable(self.fd, timeout):
            return False
        try:
            chunk = os.read(self.fd, 65536)
        except (OSError, BlockingIOError):
            return False
        if not chunk:
            return False
        self.seen += chunk.decode("utf-8", "replace")
        self.text = ANSI_RE.sub("", self.seen)
        return True

    def expect(self, pattern, timeout=45):
        """Wait for the child to print something matching, SINCE the last wait.

        A curses screen redraws the same footer every frame, so searching the
        whole buffer would match the previous frame and return before the
        child had done anything. Matching from a high-water mark means each
        step waits for its own evidence.
        """
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while True:
            m = rx.search(self.text, self.mark)
            if m:
                self.mark = m.end()
                return True
            if time.time() >= deadline:
                return False
            self._pump(0.2)

    def send(self, data):
        os.write(self.fd, data)

    def finish(self, settle=2.0):
        deadline = time.time() + settle
        while time.time() < deadline:
            self._pump(0.1)
        try:
            os.kill(self.pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        return self.seen


def prompt_paste(name, fields, script, plain=True, wait=2.0, ready=None):
    """Drive `vlt _prompt` and return everything it printed.

    `script` is a list of (pattern-to-wait-for, bytes-to-send). A pattern of
    None sends immediately — used only for keystrokes that follow one the
    child has already acknowledged.
    """
    import json
    payload = os.path.join(TH.VLT_HOME, "spec-%s.json" % name.replace("/", "-"))
    with open(payload, "w") as fh:
        json.dump({"name": name, "type": "ssh", "fields": fields}, fh)
    env = dict(TH.HUMAN)
    env["TERM"] = "xterm-256color"
    env["LINES"], env["COLUMNS"] = "40", "100"
    if plain:
        env["VLT_PLAIN_PROMPT"] = "1"
    else:
        env.pop("VLT_PLAIN_PROMPT", None)

    child = Pty([sys.executable, TH.VLT, "_prompt", payload], env)
    # Nothing is typed until the child says it is listening. This is the whole
    # difference between a suite that passes everywhere and one that passes
    # where it was written.
    if ready and not child.expect(ready):
        child.finish(0.5)
        return child.seen
    for pattern, chunk in script:
        if pattern and not child.expect(pattern):
            break
        child.send(chunk)
    return child.finish(wait)


screen = prompt_paste("ssh/prompt", ["key"],
                      [(None, (KEYTEXT + "\n").encode()),
                       (r"account\s+\(opt", b"\n"),
                       (r"notes\s+\(opt", b"\n")],
                      ready=r"key\s+\(hidden")
rec = V.load("ssh/prompt") if V.exists("ssh/prompt") else {"fields": {},
                                                           "notes": "?"}
check("the prompt keeps every line of a pasted key",
      rec["fields"].get("key") == KEYTEXT + "\n",
      "stored %d chars, pasted %d" % (len(rec["fields"].get("key") or ""),
                                      len(KEYTEXT)))
check("no part of the key leaked into `notes`",
      not (rec.get("notes") or "").strip(), repr(rec.get("notes")))
check("no part of the key leaked into `account`",
      not (rec.get("account") or "").strip(), repr(rec.get("account")))
check("the pasted key was never echoed to the screen",
      BODY[0] not in screen)

# A plain one-line value must still finish on one Enter — a reader that waits
# for an -----END----- that is never coming is a hang, not a fix.
started = time.time()
screen = prompt_paste("token/plain", ["token"],
                      [(None, b"EXAMPLEtokenAAAABBBBCCCCDDDD\n"),
                       (r"account\s+\(opt", b"\n"),
                       (r"notes\s+\(opt", b"\n")],
                      ready=r"token\s+\(hidden")
took = time.time() - started
rec = V.load("token/plain") if V.exists("token/plain") else {"fields": {}}
check("a one-line value still commits on Enter, promptly (%.1fs)" % took,
      rec["fields"].get("token") == "EXAMPLEtokenAAAABBBBCCCCDDDD" and took < 8,
      repr(rec["fields"].get("token")))


# --------------------------------------------------- 4. what `vlt file` writes
out = os.path.join(TH.VLT_HOME, "written.key")
subprocess.run([sys.executable, TH.VLT, "file", "ssh/pipe", "key",
                "--out", out, "--mode", "0600"],
               capture_output=True, text=True, env=TH.HUMAN)
written = open(out).read() if os.path.exists(out) else ""
check("`vlt file` terminates an armoured value", written.endswith("\n"))
check("`vlt file` writes the key unchanged otherwise",
      written == KEYTEXT + "\n")
check("the written key file is 0600",
      os.path.exists(out) and (os.stat(out).st_mode & 0o777) == 0o600)

TH.vlt(["set", "test/pw", "password", "no-newline-please"], env=TH.HUMAN)
out2 = os.path.join(TH.VLT_HOME, "written.txt")
subprocess.run([sys.executable, TH.VLT, "file", "test/pw", "password",
                "--out", out2], capture_output=True, text=True, env=TH.HUMAN)
check("`vlt file` does NOT add a newline to a password",
      open(out2).read() == "no-newline-please")


# ------------------------------------------------- 5. the paste parser, in units
class StubWin(object):
    """A window that plays back a scripted byte stream to getch()."""

    def __init__(self, data):
        self.q = list(data)
        self.blocking = True

    def getch(self):
        if self.q:
            return self.q.pop(0)
        return -1 if not self.blocking else -1

    def nodelay(self, v):
        self.blocking = not v

    def timeout(self, v):
        pass

    def keypad(self, v):
        pass

    def getmaxyx(self):
        return (40, 100)


def seq(text):
    return [27, 91, 50, 48, 48, 126] + list(text.encode()) + \
           [27, 91, 50, 48, 49, 126]


w = StubWin(seq(KEYTEXT))
k = vltui.read_key(w)
check("a bracketed paste is recognised as one event", k == vltui.PASTE_KEY)
check("the paste carries its whole text", vltui.take_paste() == KEYTEXT)

w = StubWin([ord("d")])
check("an ordinary keypress is still an ordinary keypress",
      vltui.read_key(w) == ord("d"))

w = StubWin([27])
check("a bare ESC is still ESC", vltui.read_key(w) == 27)

w = StubWin(list(b"AAAA\nBBBB"))
check("drain_pending returns what is already queued",
      vltui.drain_pending(w) == "AAAA\nBBBB")

w = StubWin([])
check("drain_pending returns nothing when nobody pasted",
      vltui.drain_pending(w) == "")


# ------------------------------------------- 6. the form, driven through a pty
screen = prompt_paste(
    "ssh/form", ["key"],
    [(None, b"\x1b[B" * 3),         # down to the `key` row
     (None, b"\n"),                 # start editing it
     (r"value for key", (KEYTEXT + "\n").encode()),
     # No ^D here: an armoured value commits itself at its -----END----- line,
     # so the next thing the child prints is the form redrawing its footer.
     (r"row\s+ENTER", b"\x1b[B" * 2),   # the redrawn footer; down to [Save]
     (None, b"\n")],
    plain=False, wait=4.0, ready=r"ssh/form")
rec = V.load("ssh/form") if V.exists("ssh/form") else None
check("the form saves a pasted key whole",
      rec is not None and rec["fields"].get("key") == KEYTEXT + "\n",
      "saved=%s stored=%r" % (rec is not None,
                              (rec or {}).get("fields", {}).get("key")))
check("the form never echoed the key body", BODY[0] not in screen)


# ------------------- 6b. a multi-line paste into a field that is NOT multi-line
# The realistic accident: a key pasted into `password`, or a value that simply
# wraps. There is no armour to detect here, so the only thing standing between
# the second line and the `notes` field is the drain-on-Enter fallback.
TWOLINE = "EXAMPLEfirstlineAAAA\nEXAMPLEsecondlineBBBB"

screen = prompt_paste("test/wrapped", ["password"],
                      [(None, (TWOLINE + "\n").encode()),
                       (r"account\s+\(opt", b"\n"),
                       (r"notes\s+\(opt", b"\n")],
                      ready=r"password\s+\(hidden")
rec = V.load("test/wrapped") if V.exists("test/wrapped") else {"fields": {}}
check("an unarmoured multi-line paste is kept whole",
      rec["fields"].get("password") == TWOLINE,
      repr(rec["fields"].get("password")))
check("its second line did not become `account`",
      not (rec.get("account") or "").strip(), repr(rec.get("account")))
check("its second line did not become `notes`",
      not (rec.get("notes") or "").strip(), repr(rec.get("notes")))

# And the same through the form, where `token` is a single-line field: the
# paste arrives as bare keystrokes because a pty does not bracket anything.
screen = prompt_paste(
    "test/formwrapped", ["token"],
    [(None, b"\x1b[B" * 3),
     (None, b"\n"),
     (r"value for token", (TWOLINE + "\n").encode()),
     # NOT anchored on the "<N" prefix: curses repositions the cursor and
     # rewrites only the part of the field that changed, so the summary never
     # crosses the wire as one contiguous string.
     (r"lines, [1-9]\d* chars", b"\x04"),
     (r"row\s+ENTER", b"\x1b[B" * 2),
     (None, b"\n")],
    plain=False, wait=4.0, ready=r"test/formwrapped")
rec = V.load("test/formwrapped") if V.exists("test/formwrapped") else None
check("the form keeps a multi-line paste in a single-line field",
      rec is not None and rec["fields"].get("token") == TWOLINE,
      "saved=%s stored=%r" % (rec is not None,
                              (rec or {}).get("fields", {}).get("token")))
check("the form did not run the tail of that paste as commands",
      rec is not None and rec["name"] == "test/formwrapped",
      "name is %r" % ((rec or {}).get("name"),))


# ------------------------------- 7. a paste in the BROWSER must not run as keys
def browse_paste(payload_bytes):
    """Open `vlt ui`, paste into the tree view, then quit. Returns the screen."""
    env = dict(TH.HUMAN)
    env["TERM"] = "xterm-256color"
    env["LINES"], env["COLUMNS"] = "40", "100"
    child = Pty([sys.executable, TH.VLT, "ui"], env)
    if not child.expect(r"add a credential|ssh|vault"):
        return child.finish(0.5)
    child.send(payload_bytes)
    # Wait for the browser to SAY it ignored the paste rather than assuming it
    # had time to. If it never says so, the assertion below reports that.
    child.expect(r"ignored here", timeout=15)
    child.send(b"q")
    return child.finish(1.5)


before = sorted(V.index().keys()) if hasattr(V, "index") else None
marked = ("\x1b[200~" + KEYTEXT + "\x1b[201~").encode()
screen = browse_paste(marked)
after = sorted(V.index().keys()) if before is not None else None
check("a paste into the browser deletes nothing",
      before is None or before == after,
      "%s -> %s" % (before, after))
check("a paste into the browser reveals nothing", BODY[0] not in screen)
clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen)
check("the browser says it ignored the paste",
      "ignored here" in clean or "paste" in clean.lower(), clean[-300:])

# ------------------------------------ 8. echo is off BEFORE the prompt appears
# The prompt used to be written first and echo turned off after it. Whatever
# arrived in between was echoed: on a phone under proot the gap was long enough
# for a paste sent the moment the prompt appeared to land on the screen every
# time, and on a fast machine too short to ever see. Timing cannot pin that
# down, so this makes turning echo off slow on purpose. Written in the right
# order, the prompt only appears once echo is already off, however long that
# takes; in the wrong order, the paste arrives during the delay and is echoed.
SLOW = os.path.join(TH.VLT_HOME, "slow_echo_off.py")
with open(SLOW, "w") as fh:
    fh.write(
        "import importlib.machinery, importlib.util, sys, termios, time\n"
        "real = termios.tcsetattr\n"
        "def slow(*a):\n"
        "    time.sleep(0.5)\n"
        "    return real(*a)\n"
        "termios.tcsetattr = slow\n"
        "loader = importlib.machinery.SourceFileLoader('vltcli', %r)\n"
        "spec = importlib.util.spec_from_loader('vltcli', loader)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "loader.exec_module(mod)\n"
        "v = mod._read_field('secret (hidden): ', hidden=True)\n"
        "sys.stdout.write('\\nlength=%%d\\n' %% len(v))\n" % TH.VLT)

pid, fd = pty.fork()
if pid == 0:
    os.execvpe(sys.executable, [sys.executable, SLOW], TH.HUMAN)
seen = b""
deadline = time.time() + 20
while b"secret (hidden): " not in seen and time.time() < deadline:
    if _readable(fd, 0.2):
        try:
            seen += os.read(fd, 4096)
        except OSError:
            break
os.write(fd, b"EXAMPLEechoProbe42\n")          # at once, as a paste would
while time.time() < deadline:
    if not _readable(fd, 0.5):
        if b"length=" in seen:
            break
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    seen += chunk
os.waitpid(pid, 0)
check("a value sent the instant the prompt appears still arrives",
      b"length=18" in seen, seen[-120:])
check("and is not echoed, even when turning echo off is slow",
      b"EXAMPLEechoProbe42" not in seen, seen[-120:])

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
