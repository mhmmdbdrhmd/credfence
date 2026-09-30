#!/usr/bin/env python3
"""Run every suite against an isolated vault. Exit non-zero if any fails.

    python3 tests/run_all.py            # everything
    python3 tests/run_all.py --fast     # skip the pty UI tests
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# (name, needs a pseudo-terminal, seconds)
SUITES = [
    ("evasion_test", False, 90),   # adversarial bypasses of the bash guard
    ("hooktest",     False, 90),   # allow/deny, including false positives
    ("regress",      False, 60),   # compound commands
    ("prose_test",   False, 90),   # English is not a filesystem path
    ("exec_test",    False, 90),   # no `vlt exec` path prints a secret
    ("bypass_test",  False, 60),   # VLT_HUMAN=1 inside a script is refused
    ("hide_test",    False, 90),   # per-record masking
    ("masking_test", False, 90),   # unknown fields are masked, not printed
    ("rename_test",  False, 90),   # rename re-encrypts and cleans up
    ("edit_test",    False, 90),   # editing semantics
    ("form_test",    False, 30),   # type defaults, Save/Cancel
    ("layout_test",  False, 30),   # form geometry
    ("ui_test",      True, 180),   # the UI, driven through a pty
    ("multiline_test", True, 300),  # keys and certs span lines; pastes
                                   # must not become keystrokes
    ("scan_test",    False, 90),   # the inventory report, and its silence
    ("sshkey_test",  False, 90),   # a real OpenSSH key, judged by OpenSSH
    ("vltssh_test",  False, 120),  # vlt-ssh: key and password logins, and
                                   # a real one against a local sshd
    ("notes_test",   True, 180),   # a note that spans lines must not
                                   # write over the pane next door
    ("keyring_test", False, 60),   # real keychain / Secret Service round trip
]


def count():
    """Assertions actually executed, per suite. Prints the README's number."""
    total = 0
    for name, _, timeout in SUITES:
        path = os.path.join(HERE, name + ".py")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, timeout=timeout)
        n = sum(1 for l in r.stdout.splitlines() if l.startswith("ok "))
        state = "" if r.returncode == 0 else "  (FAILED)"
        if not n and any(l.startswith("skipped:") for l in r.stdout.splitlines()):
            state = "  (not run here)"
        print("  %-14s %4d%s" % (name, n, state))
        total += n
    print("\n  %-14s %4d" % ("total", total))
    return 0


def main():
    if "--count" in sys.argv:
        return count()
    fast = "--fast" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    failed, skipped, declined = [], [], []

    for name, needs_pty, timeout in SUITES:
        if only and name not in only:
            continue
        if fast and needs_pty:
            skipped.append(name)
            continue
        path = os.path.join(HERE, name + ".py")
        if not os.path.exists(path):
            failed.append((name, "missing"))
            continue
        started = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print("  %-14s TIMEOUT after %ss" % (name, timeout))
            failed.append((name, "timeout"))
            continue
        took = time.time() - started
        if r.returncode == 0:
            # A suite may decline to run (keyring_test needs a real keyring).
            # Saying "pass" would claim it checked something it did not.
            why = next((l for l in r.stdout.splitlines()
                        if l.startswith("skipped:")), None)
            if why:
                declined.append((name, why[len("skipped:"):].strip()))
                print("  %-14s SKIP   %s" % (name, why[len("skipped:"):].strip()))
            else:
                print("  %-14s pass   (%.1fs)" % (name, took))
        else:
            print("  %-14s FAIL   (%.1fs)" % (name, took))
            # Print what the suite actually said, not a keyword grep of it.
            # Filtering here once turned a CI failure into six identical
            # "FAILED" lines with no reason attached, and the log is the only
            # thing a remote runner leaves behind.
            body = (r.stdout + r.stderr).rstrip().splitlines()
            head, tail = body[:8], body[-25:]
            shown = head + (["      ..."] if len(body) > 33 else []) + tail \
                if len(body) > 33 else body
            for line in shown:
                print("      %s" % line[:200])
            failed.append((name, "failed"))

    print()
    if skipped:
        print("skipped (--fast): %s" % ", ".join(skipped))
    if declined:
        for name, why in declined:
            print("not run: %s — %s" % (name, why))
    if failed:
        print("%d SUITE(S) FAILED: %s"
              % (len(failed), ", ".join(n for n, _ in failed)))
        return 1
    print("all suites passed%s"
          % (" (%d not run)" % len(declined) if declined else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
