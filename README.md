<h1 align="center">credfence</h1>
<p align="center"><i>Let coding agents use your credentials without ever seeing them</i></p>
<p align="center"><a href="https://github.com/mhmmdbdrhmd/credfence/actions"><img alt="CI" src="https://github.com/mhmmdbdrhmd/credfence/actions/workflows/tests.yml/badge.svg"></a> <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-6E7681?style=flat-square"> <img alt="python" src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white"> <img alt="crypto" src="https://img.shields.io/badge/AES--256--GCM-per%20record-E7352C?style=flat-square"> <img alt="tests" src="https://img.shields.io/badge/tests-456%20assertions-58A6FF?style=flat-square"> <img alt="license" src="https://img.shields.io/badge/license-MIT-3FB950?style=flat-square"></p>

> An agent can find out that a GitHub token exists, confirm it starts `ghp_` and
> is 40 characters, and run `gh` with it in the environment — **without the value
> entering the conversation, a log, or any file the agent can read back.**

> [!IMPORTANT]
> **The guard is enforced only under Claude Code.** It runs as a `PreToolUse`
> hook, which is what makes the restrictions mechanical rather than advisory.
> The `vlt` CLI and the whole protocol work under any agent, but without a
> pre-tool hook nothing stops that agent reading `~/.ssh` directly, and none of
> the guarantees below hold. → [Integrations](#9-integrations)
>
> **This is not a sandbox.** → [Known issues and limits](#13-known-issues-and-limits)

<details open>
<summary><b>Contents</b></summary>
<br>

- [1. Why an instruction is not enough](#1-why-an-instruction-is-not-enough)
- [2. Install](#2-install)
- [3. The protocol an agent follows](#3-the-protocol-an-agent-follows)
- [4. One record shape for everything](#4-one-record-shape-for-everything)
- [5. Masking is fail-closed](#5-masking-is-fail-closed)
- [6. The terminal UI](#6-the-terminal-ui)
- [7. What agents can and cannot do](#7-what-agents-can-and-cannot-do)
- [8. Related work, and when to use something else](#8-related-work-and-when-to-use-something-else)
- [9. Integrations](#9-integrations)
- [10. Recovering without this tool](#10-recovering-without-this-tool)
- [11. Testing](#11-testing)
- [12. Verification status](#12-verification-status)
- [13. Known issues and limits](#13-known-issues-and-limits)
- [14. Future development](#14-future-development)
- [License](#license)
- [Author](#author)

</details>

---

Credentials end up in one of two places when an agent needs them: pasted into
the chat, where they stay in the transcript for ever, or in a `.env` the agent
can read — plaintext on disk, and every agent can read all of it. Both get worse
the more projects you have.

`credfence` replaces both with one encrypted store, **one AES-256-GCM file per
secret**, and a tool that moves a value from that store into the place it is
needed without the value passing through anything the agent can see.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/figures/architecture-dark.svg">
    <img alt="How a tool call reaches the guard, and how vlt reaches the vault around it" src="docs/figures/architecture-light.svg" width="96%">
  </picture>
</p>


<table>
<tr><td><b>Storage</b></td><td>one AES-256-GCM file per secret, with a per-record subkey</td></tr>
<tr><td><b>Master key</b></td><td>the OS keyring — Secret Service or macOS keychain — never a file on disk</td></tr>
<tr><td><b>Enforcement</b></td><td>a Claude Code <code>PreToolUse</code> hook, plus the CLI's own refusals</td></tr>
<tr><td><b>An agent sees</b></td><td>names, field names, length, charset, leading characters</td></tr>
<tr><td><b>An agent never sees</b></td><td>a value, on any path</td></tr>
<tr><td><b>Needs</b></td><td>Python 3.8+ and <code>cryptography</code>. Nothing else.</td></tr>
</table>


**Contents** · [Why](#1-why-an-instruction-is-not-enough) ·
[Install](#2-install) · [Protocol](#3-the-protocol-an-agent-follows) ·
[Records](#4-one-record-shape-for-everything) ·
[Masking](#5-masking-is-fail-closed) · [UI](#6-the-terminal-ui) ·
[Permissions](#7-what-agents-can-and-cannot-do) ·
[Related work](#8-related-work-and-when-to-use-something-else) ·
[Integrations](#9-integrations) · [Recovery](#10-recovering-without-this-tool) ·
[Testing](#11-testing) · [Verification](#12-verification-status) ·
[Limits](#13-known-issues-and-limits) · [Future](#14-future-development)

---

## 1. Why an instruction is not enough

Telling an agent not to read `.env` does not stop it reading `.env`.
[claude-code#44868](https://github.com/anthropics/claude-code/issues/44868) is
Claude Code doing exactly that, via `grep -n`, **while a `CLAUDE.md` rule
forbade it**. Under `"defaultMode": "auto"` an agent approves its own tool
calls, so the only thing between the instruction and the credential is the
model's compliance.

An instruction is not a control. This ships a control: a `PreToolUse` hook that
refuses the tool call before it runs, and a CLI that independently refuses
value-revealing subcommands, so neither layer is the only thing standing there.

What the guard enforces is narrow and blunt:

| | |
|---|---|
| **Refused** | reading `.env`, `~/.ssh/id_*`, `~/.netrc`, `~/.aws/credentials`, `*.pem`, `~/Library/Keychains/`, the vault's own files, and anything `vlt` has just rendered |
| **Refused** | searching the disk for key material or secret-shaped assignments |
| **Refused** | reaching the keyring — `secret-tool`, `secretstorage`, `security find-generic-password`, `dump-keychain` |
| **Refused** | `vlt get`, `show`, `export`, `add`, `edit`, `set`, `rm`, `hide`, `unhide`, `rename`, `identity`, `ui` |
| **Allowed** | everything else, including *writing about* all of the above — see [the hard part](#the-hard-part-is-not-blocking-things) |

You stay in control of it: `vlt guard warn` logs instead of denying, `vlt guard
off` disables it, `vlt guard on` puts it back.

---

## 2. Install

Python ≥ 3.8, the `cryptography` package, and a system keyring — a Secret
Service provider on Linux (gnome-keyring, kwallet, keepassxc), or the login
keychain on macOS.

```bash
git clone https://github.com/mhmmdbdrhmd/credfence
cd credfence
./install.sh
```

The installer checks requirements, installs the `vlt` and `vlt-ssh` commands
(the latter needs `sshpass` for password logins), creates the
vault, and — if it finds `~/.claude` — registers the guard hook and the agent
skill. Re-running is safe: it never touches an existing vault, and it backs up
anything it replaces. `./install.sh --uninstall` reverses all of that and leaves
your vault alone, because uninstalling a tool should not destroy the secrets it
was holding.

> **Back up the master key before you put anything in.** Losing it loses every
> secret, permanently. There is no recovery path, and that is the point.
>
> ```bash
> VLT_HUMAN=1 vlt identity export ~/vlt-master-key.txt   # then move it offline
> ```

### Where the master key lives

Not in a file. It is held in the OS keyring, which unlocks with your login
session — which is why `vlt` never asks for a passphrase.

| | Linux | macOS |
|---|---|---|
| Store | Secret Service over D-Bus | login keychain via `/usr/bin/security` |
| Stored as | the 32 raw bytes | base64 of the same bytes — the keychain CLI carries text, not bytes |
| Readable by | any process running as you, no prompt | the same, via `-A` on the item |

If no keyring is reachable, `vlt` **refuses to start** rather than quietly
writing the key to disk. `VLT_ALLOW_FILE_KEY=1` accepts the weaker model
explicitly, and `vlt doctor` keeps reporting it as a problem for as long as it
is in use.

---

## 3. The protocol an agent follows

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/figures/protocol-dark.svg">
    <img alt="vlt list, then peek, then exec or file or render, and request when it is missing" src="docs/figures/protocol-light.svg" width="96%">
  </picture>
</p>

Four steps, and the agent holds a value in none of them.

**Find out what exists.** No decryption happens at all — this reads a plaintext
index of names, types and field names, and no values:

```
NAME                               TYPE      FIELDS                       TAGS
cloudflare/example                 token     token
github.com/example                 token     username,token
openai.com/example                 apikey    key
vps/alpha/panel                    service   username,token,url
vps/alpha/ssh                      ssh       username,password,host,port
vps/beta/ssh                       ssh       username,password,host,port
```

**Check the shape before spending a run on it.** `vlt peek` is what makes the
whole thing workable: an agent can confirm a credential is the right *kind* of
thing without being handed it.

```
name     : github.com/example
type     : token
hidden   : token
------------------------------------------------------------
username:    exampleuser   [11 chars, base62]
token:       ghp_••••••••••••   [39 chars, base64url]
------------------------------------------------------------
structure only. To use it:  vlt exec github.com/example -- <command>
```

**Use it, three ways** — whichever the consuming program wants:

```bash
vlt exec github.com/example -- gh repo list             # into a child's environment
vlt file vps/alpha/ssh key --out ~/.ssh/k --mode 0600   # one field to one file
vlt render --secret openai.com/example --out ./.env     # a whole config file
```

**SSH, with a key or a password.** `vlt-ssh` takes an `ssh` record's name where
a host would go. The key becomes a 0600 file that is deleted when ssh exits; a
password goes to `sshpass` through its environment, never as an argument:

```bash
vlt-ssh vps/alpha/ssh uptime                            # key, password, or both
vlt-ssh -N -L 8080:localhost:80 vps/alpha/ssh           # ssh options before the name
```

**Ask for what is missing.** The agent never asks you in chat:

```bash
vlt request stripe.com/example --fields key --reason "the deploy needs the live key"
```

That opens a **separate window** — `gnome-terminal` or `xterm` on Linux,
Terminal.app on macOS — where you type the value into a form that also lets you
choose which branch it lands on and which fields are masked. The agent gets back
success or failure and nothing else.

**Everything is recorded** — who read what, when, and from which agent session:

```
2026-09-05T15:23:38Z  3353c681 human  set            github.com/example           field=token
2026-09-05T15:23:38Z  3353c681 human  set            openai.com/example           field=key
2026-09-05T15:23:38Z  3353c681 human  set            cloudflare/example           field=token
2026-09-05T15:23:38Z  3353c681 agent  list           *
2026-09-05T15:23:38Z  3353c681 agent  peek           github.com/example
2026-09-05T15:23:38Z  3353c681 agent  peek           vps/alpha/panel
```

The session column exists because of a real question — *"was that me, or an
agent?"* — that the log recorded the answer to and then did not show.
`vlt audit --session <id>` answers it now.

> Every terminal block and both figures above are generated, not drawn.
> `python3 docs/make_figures.py` writes the SVGs from one layout and two
> palettes; `--check` fails if the committed files have drifted, and CI
> runs it.
>
> Every terminal block is captured, not typed.
> `python3 docs/make_readme_captures.py` builds a throwaway vault of invented
> records and captures the real output; the files are in
> [`docs/captures/`](docs/captures/).

---

## 4. One record shape for everything

An SSH login, a Stripe key and a database password are the same shape, so
anything that consumes them is written once:

```json
{
  "name": "vps/beta/panel",
  "type": "service",
  "fields": {"username": "…", "token": "…", "url": "…"},
  "env_map": {"PANEL_TOKEN": "token", "PANEL_URL": "url"},
  "hidden": ["token", "url"],
  "tags": ["panel"], "notes": ""
}
```

- **Fields are a closed vocabulary**: `username password token key secret host
  port url path region account_id`. Anything else goes into `extra` — and is
  masked, see below.
- **Types** are `login token apikey oauth ssh database cert vpn smtp service`,
  and choosing one changes which fields the entry form asks for.
- **Names** are `<provider>/<account>[/<purpose>]`. With several machines
  running the same service, put the machine second and the service third:
  `vps/alpha/ssh`, `vps/alpha/panel`, `vps/beta/ssh`. Then `vlt list alpha`
  shows one machine and `vlt list panel` shows every panel.
- **`env_map`** is what lets `vlt exec` work identically for every record.

### Notes, and anything else displayed in full

`notes` is the one field printed whole — by `vlt peek`, by the browser's detail
pane, by the form. It may span lines: in the form, **Enter** starts a new line
and **`^D`** finishes. `vlt peek` indents the continuations under the value
column, so a note can never be mistaken for one of peek's own `key : value`
lines however many lines it runs to; the browser draws up to four lines inside
the pane and says how many it did not show.

Values are stripped of control characters before anything draws them —
including `ESC`, so a record cannot repaint, reposition or recolour the
terminal of whoever displays it. That is enforced at `vltui._put`, the single
function everything on screen goes through, rather than at the call sites that
happened to be found.

> **Also broken before `notes_test.py` existed.** A three-line note wrote lines
> two and three at column zero — on top of the tree pane, destroying the
> divider and cutting the last line mid-word. And in `vlt peek` the
> continuations came out flush left with no key in front of them, so a note
> reading `hidden   : (nothing)` was indistinguishable from peek's real
> `hidden` line, in the output an agent is told to trust.

### Credentials that span lines

An SSH private key, a PEM certificate and a service-account blob are not one
line of text, and `key`, `cert`, `certificate`, `private_key`, `ca`, `ca_cert`,
`pubkey` and `public_key` are treated as multi-line fields everywhere.

| where | how it ends |
|---|---|
| the entry form (`vlt add`, `vlt ui`, an agent's `vlt request`) | paste it; **`^D`** commits. An armoured value commits itself at its `-----END …-----` line. |
| the plain prompt (`VLT_PLAIN_PROMPT=1`) | paste it, then **`^D`** or a line holding a single `.` |
| non-interactive | `vlt set ssh/beta key - < ~/.ssh/id_ed25519` |

Two details that matter more than they look:

- **A paste is never read as keystrokes.** The UI asks the terminal for
  bracketed paste, so pasted text arrives as one event and goes into the field
  being edited. On a terminal too old for that, anything still queued when you
  press Enter is folded into the value instead. Both matter because in the
  record browser `d` is delete, `v` is reveal and `q` is quit — and a base64
  key body contains all three.
- **Armoured values are terminated on the way in.** OpenSSH rejects a key whose
  final `-----END …-----` has no newline after it, and reports it as *invalid
  format* rather than as one missing byte. `vlt file` writes that newline
  whether or not `--newline` was passed, and will not add one to a password.

> **None of this worked until `multiline_test.py` existed.** The prompt used
> `getpass()`, which
> stops at the first newline *and* restores the terminal with `TCSAFLUSH` —
> discarding the rest of the paste, so a key became its own header with nothing
> on screen to say anything had been lost. The unmasked fields used `input()`,
> which does not flush, so the tail of a key became the answers to the next
> prompts — and `notes` is printed in full by `vlt peek`. The form was worse
> than either: it handed the remainder of the paste to its own key handler.

---

## 5. Masking is fail-closed

Everything is hidden **except** the fields that merely address a thing:
`username host port region account_id path`.

That direction is deliberate, and it was chosen after getting it the wrong way
round. The first version masked a known list of sensitive names, so a field
called `API_token` — not in the schema, and therefore in `extra` — was printed
in full. A rule that lists what to hide fails open on everything nobody thought
of, and the things nobody thought of are exactly what a generic vault fills up
with.

```
FIELD         VALUE                          STATE
username      admin                          shown
token         EXAM••••••••••••               masked
url           http••••••••••••               masked
```

Per record, you choose: `vlt hide <name> <field>`, `vlt unhide`, or <kbd>Space</kbd>
in the UI. The leading characters stay visible on purpose — that is what makes
`peek` useful for checking a format.

---

## 6. The terminal UI

`vlt ui` — a tree of every record, a detail pane, masking per field, and add and
edit forms. No dependencies beyond the standard library.

```
 vlt — credential vault

▾ cloudflare                   │ vps/alpha/panel
  ● example                    │ type service    account -
▾ github.com                   │
  ● example                    │
▾ openai.com                   │ FIELD         VALUE                          STATE
  ● example                    │ username      admin                          shown
▾ vps                          │ token         EXAM••••••••••••               masked
  ▾ alpha                      │ url           http••••••••••••               masked
    ● panel                    │
    ● ssh                      │ SPACE masks/unmasks the selected field
  ▾ beta                       │ v reveals it on screen   e edits this record
    ● ssh                      │

↑↓ move  TAB pane  SPACE mask  e edit  a add  q quit
```

That is a real screen rather than a mock-up: the curses program is driven
through a pseudo-terminal and the emulator's grid is dumped. The same technique
is how [`tests/ui_test.py`](tests/ui_test.py) checks the UI draws at all —
curses code fails at runtime, not import time, so nothing short of running it is
evidence.

Keys: <kbd>↑</kbd><kbd>↓</kbd> move · <kbd>Tab</kbd> switches pane · <kbd>Space</kbd> masks · <kbd>v</kbd> reveals ·
<kbd>e</kbd> edits · <kbd>a</kbd> adds · <kbd>q</kbd> quits. There is a **Save button** as well as <kbd>Ctrl</kbd>+<kbd>S</kbd>,
because <kbd>Ctrl</kbd>+<kbd>S</kbd> is swallowed by flow control in some terminals.

---

## 7. What agents can and cannot do

| Agents may | Agents may not |
|---|---|
| `list`, `peek`, `audit`, `scan`, `doctor` | `get`, `show`, `export` — anything that prints a value |
| `exec`, `file`, `render` — *use* a value | `add`, `edit`, `set`, `import`, `rm`, `rename` |
| `request` a credential that is missing | `hide` / `unhide` — change what is masked |
| | read `.env`, `~/.ssh`, `~/.netrc`, `*.pem`, keychains |
| | search the disk for key material |
| | read back a file `vlt` has just rendered |
| | edit the guard, the CLI or the policy |

Human-only commands need a **real terminal or a desktop confirmation**. Setting
`VLT_HUMAN=1` is not enough, and never was: an environment variable is not proof
that a person is present, and a script can set one. That was a real hole; it is
now [`tests/bypass_test.py`](tests/bypass_test.py).

`vlt exec X -- env` is refused by both layers, because injecting a secret and
then printing the environment puts the value in the transcript by the back door.

### The hard part is not blocking things

Blocking is easy. Not blocking the wrong things is what took the time.

A session configuring a VPN was refused because the word `credentials` appeared
in **a comment, inside a heredoc, bound for a remote host** — and the refusal
named a file that did not exist, phrased as established fact. The user
reasonably concluded that an agent had gone after their real credentials.

False positives are not a nuisance in a tool like this. They train agents to
work around patterns, which is the exact behaviour the guard exists to suppress,
and they make every denial less believable — a message asserting something it
never checked is worse than no message. So:

- a **bare word** counts if it resolves to a file that exists, **or** if it
  resolves inside a directory whose purpose is credentials — `~/.ssh`,
  `~/.gnupg`, `~/.aws`, `~/Library/Keychains`. Existence alone was not enough:
  it made `cd ~/.ssh && cat id_rsa` depend on whether that file was there, which
  CI caught immediately. Prose satisfies neither test, because prose names no
  real file and never `cd`s anywhere;
- a **quoted path** counts only if something in the same shell segment actually
  reads files, so a commit message mentioning `~/.netrc` is prose while
  `cat "~/.netrc"` is not;
- **heredoc bodies and comments are data**, not commands;
- a denial states **which token matched and in which segment**, and calls
  something a credential file only when existence was actually checked.

[`tests/prose_test.py`](tests/prose_test.py) pins both directions — 47
assertions, roughly half "this English must be allowed" and half "this operation
must still die".

---

## 8. Related work, and when to use something else

**[Infisical's Agent Vault](https://github.com/Infisical/agent-vault)** solves
the adjacent problem, and for HTTP APIs it solves it better. It is a proxy: the
agent holds a placeholder, and real credentials are injected into outbound
requests at the boundary, so the secret never enters the agent's process at all.
That is a stronger guarantee than anything here, and if every credential you
hand an agent is an API key used over HTTPS, **use theirs.**

The two do not overlap as much as the names suggest:

| | Infisical Agent Vault | credfence |
|---|---|---|
| Shape | a proxy daemon, on its own host | a CLI and a tool-layer hook, on yours |
| The agent holds | a placeholder — never the value | the value, inside a child process it cannot read back |
| Covers | anything spoken over HTTP/HTTPS | SSH keys, database passwords, VPN profiles, signing keys, rendered `.env` files — anything local |
| Stops `cat ~/.ssh/id_rsa` | no | yes, before the tool call runs |
| Needs | a daemon, a database, a master password, `HTTPS_PROXY` on every agent | `git clone` and `./install.sh` |
| Maturity | company-backed, hundreds of commits | one author, and this repository's history is all of it |

The distinction that matters: a proxy protects the credentials it brokers.
It does nothing about the credentials already sitting in your home directory,
which is where an agent with a shell will look first. This protects those, and
gives you one place to keep the rest.

Run both if it fits. They interfere with nothing in each other.

---

## 9. Integrations

**Claude Code — fully supported.** The guard runs as a `PreToolUse` hook, which
is what makes any of this mechanical. `integrations/claude-code/` holds the hook
and the agent-facing skill, and `install.sh` wires both.

**Everything else — the CLI works, the enforcement does not port.** Codex CLI,
opencode, Cursor and the rest can run `vlt` and follow the `peek` → `exec` →
`request` protocol, and that is genuinely useful. But without a pre-tool hook,
nothing stops such an agent reading `~/.ssh` directly. Do not assume you are
covered because the CLI runs.
→ [`integrations/README.md`](integrations/README.md)

---

## 10. Recovering without this tool

The format is deliberately plain, so a vault is never hostage to this program:
`b"VLT1"` + a 12-byte nonce + AES-256-GCM ciphertext, with the record name
authenticated as associated data and the subkey derived as
`HKDF-SHA256(master, salt="vlt-record-v1", info=<name>)`.

```python
import base64, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

name   = "github.com/example"
master = base64.b64decode("<the VLT-MASTER-V1 line from your key backup>")
blob   = open("/home/you/.local/share/vlt/store/%s.vlt" % name, "rb").read()

key = HKDF(algorithm=hashes.SHA256(), length=32,
           salt=b"vlt-record-v1", info=name.encode()).derive(master)
print(json.loads(AESGCM(key).decrypt(blob[4:16], blob[16:], name.encode())))
```

There is no custom cryptography anywhere; everything comes from the
`cryptography` package's recipes layer.

---

## 11. Testing

```bash
python3 tests/run_all.py            # everything
python3 tests/run_all.py --fast     # skip the pty-driven UI suites
python3 tests/run_all.py --count    # assertions per suite
```

**456 assertions across 18 suites**, all passing, every one of them against a
throwaway vault in a temp directory — never your real one, and never your
keyring. That isolation is not tidiness: an earlier version ran against the
developer's live vault, and a test that unmasked a field printed a production
credential into the log.

A nineteenth suite, `keyring_test`, runs only where a real keyring is present and
`VLT_KEYRING_TEST=1` is set, because it writes to the machine's own keyring. CI
sets it; your laptop does not, and `run_all.py` reports it as *not run* rather
than as a pass.

The four worth knowing about:

- **`evasion_test.py`** — 20 adversarial bypasses of the bash guard: quote
  splitting (`c""at`), backslash escapes, `cd` then a relative path, `xargs`,
  here-strings, base64 piped to a shell, runtime-constructed paths. All 20 are
  blocked. Any case that flips to ALLOW is a real hole — **add to this file
  rather than weakening it.**
- **`prose_test.py`** — the guard must not fire on English. Built entirely out
  of denials that actually happened.
- **`bypass_test.py`** — `VLT_HUMAN=1` inside a script is refused.
- **`scan_test.py`** — the inventory report finds credential files, and prints
  field *names* while never printing a field *value*.
- **`multiline_test.py`** — a credential that spans lines (an SSH key, a
  certificate) survives every entry path intact, and a paste is never executed
  as keystrokes.
- **`sshkey_test.py`** — generates a real key with `ssh-keygen`, puts it
  through the vault, and asks **`ssh-keygen -y`** to accept what came back. It
  also asserts that OpenSSH *rejects* the same key with its trailing newline
  removed, so the byte is shown to be load-bearing rather than asserted to be.
- **`vltssh_test.py`** — `vlt-ssh` logs in with a key and with a password
  (the real `sshpass` answering a stand-in `ssh`'s prompt), and then for real,
  against an unprivileged `sshd` on 127.0.0.1. It asserts that the key file is
  0600 and gone afterwards, and that no value reaches output or ssh's argv.
- **`notes_test.py`** — renders the browser through `pyte` and asserts the pane
  divider is in the same column on every row. A note that spans lines used to
  write its second line at column zero, over the tree.

---

## 12. Verification status

<details open>
<summary><i>expand</i></summary>
<br>

Being straight about what has been checked and what has not.

**Verified — the suites, on this machine.** `python3 tests/run_all.py` runs 18
suites and 456 assertions, and all pass; `--count`
reproduces that number per suite. The repository also passes from a **bare
clone**, and `install.sh` succeeds from that clone into a sandbox prefix.

**Verified — the guard, against every evasion written down.** 20 in
`evasion_test.py`, 43 allow/deny cases in `hooktest.py`, 40 prose cases, 9
compound-command cases. That is a strong lock on a door, not a wall: the guard
is regex over command text, shell is not a regular language, and no such matcher
is complete. It is stated that way on purpose.

**Verified — no value reaches stdout by any documented path.**
`exec_test.py` walks every injection route, including `vlt exec X -- env`,
`/proc/self/environ`, and `sh -c 'env | grep'`.

**Verified — the linter, which paid for itself immediately.** Wiring pyflakes
into CI found that **`vlt scan` had never worked**: six module constants it
referenced were never defined, so it raised `NameError` on the first directory
it walked — in the initial commit, while this README listed it as agent-safe. It
is fixed, and `scan_test.py` now covers it. The absence of a linter and the
absence of any test touching that command are now statements about the past
only.

**Verified — the macOS keychain, on Apple hardware.** The `macos-latest` job
writes the master key to a real login keychain, reads it back, lists it,
overwrites it and deletes it. The Linux job does the same against gnome-keyring
under `dbus-run-session`. Both pass. That is the claim in §2 settled by a
machine rather than by reasoning.

**Verified — that CI was worth wiring up, on its first run.** Every `suites`
job failed, on both operating systems and all three Python versions, on one
shared assertion:

```
HOLE  cd then relative   ALLOW   cd $HOME/.ssh && cat id_rsa
```

The existence requirement that stops the guard firing on English had made that
case depend on whether `~/.ssh/id_rsa` happened to exist. On the machine the
tests were written on it did, so the suite passed and the hole was invisible.
The fix is the credential-directory rule in §7, and the harness now builds its
own `HOME`, so no assertion can ever again be answered by the author's laptop.
`prose_test.py` pins the new rule against an *empty* `.ssh`, where nothing but
that rule can save it.

**Verified — the full matrix, green.** All ten jobs pass: the suites on Ubuntu
and macOS across Python 3.9, 3.11 and 3.13, both keyring round trips, the secret
scan over full history, and the linter.

It took four runs, and each red one was a real defect rather than a CI quirk:

| | what CI found | why it passed locally |
|---|---|---|
| 1 | `cd ~/.ssh && cat id_rsa` was allowed when that file did not exist | the author owns an `id_rsa` |
| 2 | the macOS keychain job hung for 4 h 44 m | the fake `HOME` that fixed (1) has no login keychain |
| 3 | `exec_test` ran the *installed* `vlt`, not the one in the tree | `~/.local/bin/vlt` exists here |
| 4 | `vlt rename` and `vlt ui` were never denied to agents at all | the confirmation dialog needs a desktop, and CI has one |

Every one of those is a bug that a machine other than the author's had to
find. Three of them are the same mistake in different clothes — a test
answering from the developer's environment instead of the repository — which is
why the harness now builds its own `HOME`, strips any installed `vlt` from
`PATH`, and states `VLT_NO_DESKTOP` rather than inferring it.

**NOT verified — `vlt request` on macOS.** Driving Terminal.app through
`osascript` has no automated coverage, on any platform.

**NOT measured — anything about performance.** No timing claim appears anywhere
in this README, because none has been measured.

</details>

---

## 13. Known issues and limits

<details open>
<summary><i>expand</i></summary>
<br>

**This is not a sandbox, and no amount of hardening here would make it one.** An
adversarial agent with unrestricted `Bash`, running as your user, can eventually
do anything you can — including reading the master key out of the keyring and
writing its own decryptor. What this eliminates is the *realistic* failure mode:
secrets in transcripts, casual reads, credential hunting, scattered plaintext,
and access nobody recorded. It raises the cost and it keeps the receipts.

The gap that would actually close it: run agents under a **separate uid** that
cannot read `~/.local/share/vlt`, exposing only `vlt` through a setgid wrapper.
That moves enforcement into the kernel. Not implemented here.

**The bash guard is regex over command text.** It blocks the 20 evasions that
are written down, which is a claim about those 20 and nothing more.

**Inline interpreter code that builds a path at runtime is refused wholesale**
rather than analysed, because it cannot be analysed. That is a real usability
cost, accepted deliberately: `python3 -c` with a computed path is a denial even
when it is innocent.

**The hook reads command text, not file contents.** An agent can write a script
and then run it. The CLI's own refusals still apply, which is why human-only
commands check for a terminal rather than trusting an environment variable.

**One macOS-specific exposure.** `security` takes the password as a command-line
argument, so the master key is visible to `ps` for the length of that one call.
It happens on `vlt init` and `vlt identity import`, never on a read, and the
keychain CLI offers no way to pass a secret on stdin without a terminal to
prompt at. On Linux the key never touches argv.

**Prompt injection can still cause damage that is not credential theft** —
deleting files, pushing bad code, calling an API destructively. This tool is
about credentials only.

**The vault does not protect you from yourself.** `vlt get` prints values. That
is what it is for.

Full detail, including the assumptions:
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

</details>

---

## 14. Future development

<details>
<summary><i>expand</i></summary>
<br>

None of this is committed to. It is written down because the decisions that make
each one cheap or expensive have already been made, and knowing which is which
is worth more than a wish list.

**Sync across machines.** The store is ciphertext, so it is already safe in a
private git repository — that is how one vault could cover a laptop, a desktop
and a server with no vendor involved. The master key would never be in the repo;
it is hand-carried once per machine with `vlt identity export` / `import`. The
work is conflict handling on `index.json`, not cryptography.

**A second enforcement front-end.** The protocol is portable; only the hook is
not. Codex CLI and opencode would each need their own pre-tool interception, and
the guard is deliberately one file with one entry point so that stays a small
job once those APIs settle.

**Key rotation.** Re-encrypting every record under a new master is
straightforward — the per-record subkey derivation already isolates records from
one another — but doing it *safely* means a two-phase write that survives being
interrupted, and that is the actual work.

**A `pip install`.** Today it is a git clone and `./install.sh`. Packaging is
easy; deciding what `pip install` should do about a guard hook that edits
another program's configuration file is not.

</details>

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Mohammad Badri Ahmadi** — embedded systems & on-device AI

<br><br>

<div align="center"><p align="center">
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <a href="mailto:contact@biss.qzz.io" style="text-decoration: none;" alt="Email">
        <img src="https://raw.githubusercontent.com/mhmmdbdrhmd/Data/main/Icons/ICON%20_Black%20-%20GMail.png" width="6%" />
    </a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <a href="https://github.com/mhmmdbdrhmd" style="text-decoration: none;" alt="GitHub">
        <img src="https://raw.githubusercontent.com/mhmmdbdrhmd/Data/main/Icons/ICON%20_Black-%20Github.png" width="6%" />
    </a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <a href="https://www.linkedin.com/in/mohamad-badri-ahmadi-aa2a1a8a" style="text-decoration: none;" alt="LinkedIn">
        <img src="https://raw.githubusercontent.com/mhmmdbdrhmd/Data/main/Icons/ICON%20_Black%20-%20Linkding.png" width="6%" />
    </a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://twitter.com/mhmmdbdrhmd" style="text-decoration: none;" alt="Twitter">
        <img src="https://raw.githubusercontent.com/mhmmdbdrhmd/Data/main/Icons/ICON%20_Black%20-%20Twitter%20X.png" width="6%"/>
    </a>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://biss.qzz.io" style="text-decoration: none;" alt="Website">
        <img src="https://raw.githubusercontent.com/mhmmdbdrhmd/Data/main/Icons/ICON%20_Black%20-%20Website.png" width="6%"/>
    </a>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</p></div>
