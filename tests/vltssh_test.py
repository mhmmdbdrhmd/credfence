"""`vlt-ssh`: log in with a key or a password from the vault, and never show it.

Two halves. The first runs `vlt-ssh` against a stand-in `ssh` placed first on
PATH, which records what it was given and, for a password record, asks for the
password on its terminal exactly as OpenSSH does — so the real `sshpass` has
to answer it. The second starts an unprivileged `sshd` on 127.0.0.1 and logs
in with a key through the real OpenSSH client; that half is skipped, and says
so, where no sshd can be started.

Every credential here is generated or synthetic, and every assertion also
checks that the value appeared in no output.
"""

import getpass
import os
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                       # noqa: E402

T = TH.Report("vlt-ssh")
TOOL = os.path.join(TH.REPO, "vlt-ssh")
WORK = os.path.join(TH.VLT_HOME, "vltssh")
os.makedirs(WORK, mode=0o700, exist_ok=True)

PASSWORD = "EXAMPLE-pass-7f3a91c2"
WRONG = "EXAMPLE-not-the-password"

if not shutil.which("ssh-keygen"):
    print("skipped: ssh-keygen is not installed")
    sys.exit(0)


def keygen(path):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "credfence-test", "-f", path], check=True)
    with open(path) as fh:
        return fh.read()


KEY = keygen(os.path.join(WORK, "userkey"))
with open(os.path.join(WORK, "userkey.pub")) as fh:
    PUB = fh.read().split()[1]


def record(name, fields, prefix):
    for field, value in fields.items():
        r = subprocess.run(
            [sys.executable, TH.VLT, "set", name, field, "-",
             "--env", "%s_%s" % (prefix, field.upper())],
            input=value, capture_output=True, text=True, env=TH.HUMAN)
        assert r.returncode == 0, r.stderr


record("ssh/withkey", {"host": "keyhost.invalid", "port": "2201",
                       "username": "keyuser", "key": KEY}, "KH")
record("ssh/withpass", {"host": "passhost.invalid", "port": "2202",
                        "username": "passuser", "password": PASSWORD}, "PH")
record("ssh/wrongpass", {"host": "passhost.invalid",
                         "password": WRONG}, "WP")
record("ssh/nohost", {"password": PASSWORD}, "NH")

SECRETS = [PASSWORD, WRONG] + [l for l in KEY.splitlines()
                               if l and not l.startswith("-----")]

# ------------------------------------------------------------ the stand-in ssh
SHIM_DIR = os.path.join(WORK, "bin")
os.makedirs(SHIM_DIR, exist_ok=True)
REPORT = os.path.join(WORK, "shim-report")
SHIM = r'''#!%s
import json, os, stat, subprocess, sys
argv = sys.argv[1:]
rep = {"argv": argv, "env": sorted(os.environ)}
if "-i" in argv:
    k = argv[argv.index("-i") + 1]
    rep["key_path"] = k
    rep["key_mode"] = oct(stat.S_IMODE(os.stat(k).st_mode))
    rep["dir_mode"] = oct(stat.S_IMODE(os.stat(os.path.dirname(k)).st_mode))
    r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", k],
                       capture_output=True, text=True)
    rep["pub"] = r.stdout.split()[1] if r.returncode == 0 else r.stderr
rc = 255 if os.environ.get("SHIM_FAIL") else 0
if os.environ.get("SHIM_WANT"):
    # What OpenSSH does: prompt on the terminal, not on stdout.
    tty = os.open("/dev/tty", os.O_RDWR)
    for attempt in range(2):
        os.write(tty, b"passuser@passhost's password: ")
        got = b""
        while not got.endswith(b"\n"):
            c = os.read(tty, 1)
            if not c:
                break
            got += c
        if got.rstrip(b"\r\n").decode() == os.environ["SHIM_WANT"]:
            break
    else:
        rc = 255
    rep["password_ok"] = rc == 0
json.dump(rep, open(os.environ["SHIM_REPORT"], "w"))
print("shim-connected")
sys.exit(rc)
''' % sys.executable
with open(os.path.join(SHIM_DIR, "ssh"), "w") as fh:
    fh.write(SHIM)
os.chmod(os.path.join(SHIM_DIR, "ssh"), 0o755)


def run(args, shim=True, want=None, extra_env=None):
    env = dict(TH.AGENT, VLT=TH.VLT, SHIM_REPORT=REPORT)
    if shim:
        env["PATH"] = SHIM_DIR + os.pathsep + env["PATH"]
    if want:
        env["SHIM_WANT"] = want
    env.update(extra_env or {})
    if os.path.exists(REPORT):
        os.remove(REPORT)
    r = subprocess.run(["bash", TOOL] + args, capture_output=True, text=True,
                       env=env, stdin=subprocess.DEVNULL, timeout=60)
    rep = None
    if os.path.exists(REPORT):
        import json
        with open(REPORT) as fh:
            rep = json.load(fh)
    return r, rep


def no_leak(label, r, rep=None):
    blob = r.stdout + r.stderr + (repr(rep["argv"]) if rep else "")
    T.check(label + ": no secret in output or on ssh's command line",
            not any(s in blob for s in SECRETS))


# ------------------------------------------------------------------ key record
r, rep = run(["-p", "2299", "-vT", "ssh/withkey", "set -e; uname", "-a"])
T.check("key: ssh ran", r.returncode == 0 and rep is not None,
        r.stderr.strip()[-200:])
if rep:
    a = rep["argv"]
    T.check("key: the host is the record's", "keyhost.invalid" in a, a)
    T.check("key: the user is the record's", "User=keyuser" in a, a)
    T.check("key: the record's port is passed", "Port=2201" in a, a)
    T.check("key: a -p given by the caller comes first, so it wins",
            a.index("-p") < a.index("Port=2201") and a[a.index("-p") + 1]
            == "2299", a)
    T.check("key: a clustered option (-vT) is kept whole", "-vT" in a, a)
    T.check("key: the remote command is passed through verbatim",
            a[-2:] == ["set -e; uname", "-a"], a[-3:])
    T.check("key: 'set -e' in a remote command is not refused as an "
            "environment dump", r.returncode == 0)
    T.check("key: only that key is offered", "IdentitiesOnly=yes" in a, a)
    T.check("key: no tty, so BatchMode stops it waiting on a prompt",
            "BatchMode=yes" in a, a)
    T.check("key: the key file is 0600", rep.get("key_mode") == "0o600",
            rep.get("key_mode"))
    T.check("key: its directory is 0700", rep.get("dir_mode") == "0o700",
            rep.get("dir_mode"))
    T.check("key: OpenSSH accepts the file and derives the same public key",
            rep.get("pub") == PUB, rep.get("pub"))
    T.check("key: the file is gone once ssh exits",
            not os.path.exists(rep.get("key_path", "")))
    T.check("key: ssh inherits none of the injected variables",
            not [v for v in rep["env"] if v.startswith("KH_")],
            [v for v in rep["env"] if v.startswith("KH_")])
    no_leak("key", r, rep)

r, rep = run(["ssh/withkey"], extra_env={"SHIM_FAIL": "1"})
T.check("key: the key file is removed even when ssh fails",
        rep is not None and not os.path.exists(rep.get("key_path", "x")))

# ------------------------------------------------------------- password record
have_sshpass = shutil.which("sshpass") is not None
if not have_sshpass:
    print("skip  password half: sshpass is not installed here")
else:
    r, rep = run(["ssh/withpass", "hostname"], want=PASSWORD)
    T.check("password: sshpass answered ssh's prompt with the right password",
            r.returncode == 0 and rep and rep.get("password_ok"),
            (r.stdout + r.stderr).strip()[-200:])
    if rep:
        a = rep["argv"]
        T.check("password: host, user and port are the record's",
                {"passhost.invalid", "User=passuser", "Port=2202"} <= set(a), a)
        T.check("password: no key file is involved", "-i" not in a, a)
        T.check("password: asked for before any agent key is tried",
                "PreferredAuthentications=keyboard-interactive,password" in a,
                a)
        T.check("password: ssh inherits none of the injected variables",
                not [v for v in rep["env"] if v.startswith("PH_")])
        no_leak("password", r, rep)

    r, rep = run(["ssh/wrongpass", "true"], want=PASSWORD)
    T.check("password: a refused password fails, and says so",
            r.returncode != 0 and "password was refused" in r.stderr,
            (r.returncode, r.stderr.strip()[-160:]))
    no_leak("wrong password", r, rep)

    empty = os.path.join(WORK, "nosshpass")
    os.makedirs(empty, exist_ok=True)
    for tool in ("bash", "python3", "mktemp", "rm", "readlink"):
        src = shutil.which(tool)
        if src and not os.path.exists(os.path.join(empty, tool)):
            os.symlink(src, os.path.join(empty, tool))
    r, _ = run(["ssh/withpass", "true"], shim=False,
               extra_env={"PATH": SHIM_DIR + os.pathsep + empty})
    T.check("password: without sshpass it stops and names what is missing",
            r.returncode != 0 and "sshpass" in r.stderr, r.stderr[-200:])

# ------------------------------------------------------------ what it refuses
r, rep = run(["ssh/does-not-exist"])
T.check("an unknown record is an error, and ssh is never run",
        r.returncode != 0 and rep is None and "no vault record" in r.stderr,
        r.stderr[-160:])
r, rep = run(["ssh/nohost"])
T.check("a record with no host is an error",
        r.returncode != 0 and "no host" in r.stderr and rep is None,
        r.stderr[-160:])
r, rep = run(["-p"])
T.check("an option missing its argument is an error",
        r.returncode != 0 and rep is None)
r, _ = run(["--help"])
T.check("--help describes the tool", r.returncode == 0
        and "vault-name" in r.stdout, r.stdout[:120])

# ------------------------------------------------ a real login, by a real sshd
SSHD = shutil.which("sshd") or next(
    (p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd")
     if os.path.exists(p)), None)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def real_sshd():
    if not SSHD:
        return None, "no sshd on this machine"
    keygen(os.path.join(WORK, "hostkey"))
    auth = os.path.join(WORK, "authorized_keys")
    with open(os.path.join(WORK, "userkey.pub")) as src, open(auth, "w") as fh:
        fh.write(src.read())
    os.chmod(auth, 0o600)
    port = free_port()
    conf = os.path.join(WORK, "sshd_config")
    with open(conf, "w") as fh:
        fh.write("Port %d\nListenAddress 127.0.0.1\nHostKey %s\n"
                 "AuthorizedKeysFile %s\nStrictModes no\nUsePAM no\n"
                 "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                 "PidFile %s\n"
                 % (port, os.path.join(WORK, "hostkey"), auth,
                    os.path.join(WORK, "sshd.pid")))
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", conf],
                            stdout=subprocess.DEVNULL,
                            stderr=open(os.path.join(WORK, "sshd.log"), "w"))
    for _ in range(50):
        if proc.poll() is not None:
            return None, "sshd exited: see its log"
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return (proc, port), None
        except OSError:
            time.sleep(0.1)
    proc.kill()
    return None, "sshd never listened"


# The caller's own ~/.ssh is never consulted: OpenSSH finds it through the
# password database, not $HOME, so it is named away explicitly.
ISOLATE = ["-F", "/dev/null", "-o", "UserKnownHostsFile=%s"
           % os.path.join(WORK, "known_hosts"), "-o", "IdentityAgent=none",
           "-o", "ConnectTimeout=10"]

started, why = real_sshd()
if not started:
    print("skip  real-sshd half: %s" % why)
else:
    proc, port = started
    try:
        # Can this machine log in to itself at all, with the key used plainly?
        # If not, the environment is at fault, not vlt-ssh.
        plain = subprocess.run(
            ["ssh"] + ISOLATE + ["-o", "BatchMode=yes", "-o",
                                 "StrictHostKeyChecking=no", "-i",
                                 os.path.join(WORK, "userkey"), "-p",
                                 str(port), getpass.getuser() + "@127.0.0.1",
                                 "echo plain-ok"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=30)
        if "plain-ok" not in plain.stdout:
            print("skip  real-sshd half: a plain key login to this machine "
                  "fails too (%s)" % plain.stderr.strip()[-120:])
        else:
            record("ssh/local", {"host": "127.0.0.1", "port": str(port),
                                 "username": getpass.getuser(), "key": KEY},
                   "LOC")
            r, _ = run(ISOLATE + ["ssh/local", "echo real-login-ok"],
                       shim=False)
            T.check("real sshd: vlt-ssh logs in with the vault's key",
                    r.returncode == 0 and "real-login-ok" in r.stdout,
                    (r.stderr or r.stdout).strip()[-200:])
            no_leak("real sshd", r)
            with open(os.path.join(WORK, "known_hosts")) as fh:
                T.check("real sshd: a first connection records the host key "
                        "instead of stopping on a prompt",
                        "[127.0.0.1]:%d" % port in fh.read())
    finally:
        proc.kill()
        proc.wait()

sys.exit(T.done())
