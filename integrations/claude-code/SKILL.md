---
name: vault
description: The ONLY way to obtain any credential — API key, token, password, SSH login, database URL, certificate. Use whenever a task needs to authenticate to anything, whenever you are about to read a .env / ~/.ssh / credentials file, and whenever you are tempted to ask the user for a secret in chat. Covers discovering what exists, injecting a secret without seeing it, and requesting one that is missing.
---

# vault — credentials via `vlt`

Every credential on this machine lives in one encrypted vault. You can find out what
exists and you can put a credential where it needs to go. **You can never see one.**

## The three rules

1. **The vault is the only source.** Never read `.env`, `~/.ssh/*`, `~/.netrc`,
   `credentials*`, `*.pem`, `~/.aws/credentials`. Never grep or find for keys, tokens
   or passwords. A guard hook blocks all of this; working around it is a bug, not a
   solution.
2. **Never see a value.** Do not print, `echo`, `cat`, log, commit or paste a secret.
   Move it with `exec` / `file` / `render` — never through your own eyes.
3. **Missing? Ask the machine, not the chat.** Run `vlt request`. It opens a separate
   window where the user types the value. Never ask the user to paste a secret into
   the conversation.

## Decision tree

```
Need to authenticate to something
        │
        ├─ vlt list <thing>              does a credential exist?
        │        │
        │        ├─ yes ─ vlt peek <name>        confirm fields + format
        │        │            │
        │        │            ├─ logging in by ssh?  vlt-ssh <name> [cmd]
        │        │            ├─ running a command?  vlt exec <name> -- <cmd>
        │        │            ├─ program needs a file? vlt file / vlt render
        │        │            └─ never: vlt get / vlt show   (blocked)
        │        │
        │        └─ no ── vlt request <name> --fields ... --reason "..."
        │                     user types it in a separate window; then continue
        │
        └─ never: read a .env, grep for keys, or ask for the value in chat
```

## Commands

### Discover
```bash
vlt list                       # everything: names, types, field names
vlt list github                # fuzzy match on name or tag
vlt list --json                # machine-readable
```
`list` reads a plaintext index. It contains **no values** — only names, types, which
fields are populated, the env-var mapping and tags.

### Inspect structure (not value)
```bash
vlt peek github.com/example
vlt peek github.com/example --chars 6     # more leading characters
```
**Each record decides which of its own fields are masked.** The user chooses that set;
it is not a fixed list, and it is not yours to change. `peek` prints the set, then shows
masked fields as leading characters + length + charset, and unmasked fields in full:

```
hidden   : key, password, secret, token
token:       ghp_••••••••••••   [40 chars, base64url]
username:    exampleuser   [11 chars, base62]
```

Use this to verify a credential has the shape you expect — that a GitHub token starts
`ghp_`, that a key is 64 hex characters — **before** you spend a run on it.

A field being shown in full does not make it yours to repeat. `peek` output exists to
confirm format; do not copy values out of it into files, commits, logs or messages.

### Use it — three ways, pick the narrowest

**1. Run a command with it (best — the value never touches the filesystem):**
```bash
vlt exec github.com/example -- gh repo list
vlt exec vps/beta -- ssh -p "$SSH_PORT" "$SSH_USERNAME@$SSH_HOST"
vlt exec openai.com/example,github.com/example -- python train.py    # several at once
```
Fields are injected as environment variables per the record's `env_map` (see it with
`vlt peek`). The variables exist only inside that child process.

**The child must read the variable itself.** These are refused, because they would print
the secret into your output:

```bash
vlt exec X -- env                    # prints the whole environment
vlt exec X -- printenv TOKEN
vlt exec X -- sh -c 'echo $TOKEN'    # interpolation onto a command line
vlt exec X -- sh -c 'env | grep TOK'
```

Interpolating a secret onto a command line also puts it in `ps` output, shell history and
logs. Pass it to a program that reads the environment. If a program genuinely needs it as
an argument, that is the user's call to make with `--allow-interpolation`, not yours.

**2. Write one field straight to a file (the `cat file >` case):**
```bash
vlt file ssh/vps-beta key --out ~/.ssh/tmp_deploy --mode 0600
vlt file cert/client key --out /etc/app/client.key --mode 0400
```

**3. Render a whole config or `.env`:**
```bash
vlt render --secret openai.com/example --out ./.env
vlt render --secret db/prod --template pg.conf.tpl --out ./pg.conf
```
Templates live in `~/.local/share/vlt/templates/` and use `{{VAR}}` or `${VAR}`
placeholders named after the record's `env_map` keys.

**Files written by `file` and `render` are registered as containing live secrets. You
will be blocked from reading them back.** That is intentional — they are for the
program to consume, not for you. If you need to check your work, use `vlt peek`.

### SSH to a host — `vlt-ssh`

For any `ssh`-type record, use `vlt-ssh` instead of assembling the login
yourself. It works with a **key**, a **password**, or both, and you never see
either:

```bash
vlt-ssh vps/alpha/ssh                            # interactive shell
vlt-ssh vps/alpha/ssh uptime                     # one remote command
vlt-ssh vps/alpha/ssh 'cd /srv && make'          # quote a compound one
vlt-ssh -N -L 8080:localhost:80 vps/alpha/ssh    # ssh options go BEFORE the name
```

- Host, port and username come from the record, whatever its `env_map` calls them.
- A key is written to a private 0600 file, passed with `-i`, and deleted when ssh
  exits. A password goes to `sshpass` through its environment, never as `-p`.
  With both, the key is tried first.
- A first connection accepts the host key (`StrictHostKeyChecking=accept-new`);
  a *changed* host key is still refused. Say so to the user; do not override it.
- Without a tty, a key-only login runs with `BatchMode=yes`, so it fails instead
  of hanging on a prompt.
- For `scp`/`rsync`, `vlt-ssh` does not help: use `vlt exec` with a program that
  reads the variables itself, or ask the user.

Do not replace it with `vlt file … key` + `ssh -i`: that leaves a live key on disk
that nothing cleans up.

### Request a missing credential
```bash
vlt request stripe.com/example --type apikey --fields key \
    --reason "deploy script needs the Stripe live key"

vlt request vps/beta --type ssh --fields host,port,username,password \
    --reason "connecting to the Frankfurt VPS"
```
A terminal window opens on the user's desktop with a notification. They type the values
there; the values are encrypted straight into the vault. You get back only success or
failure, then a `vlt peek`. **Never** ask the user for the value in chat as a fallback —
if the window cannot open, tell them to run `VLT_HUMAN=1 vlt add <name>` themselves.

### Keys and certificates span lines

Nothing special is needed to ask for one:

```bash
vlt request ssh/beta --type ssh --fields host,port,username,key \
    --reason "deploy needs the server key"
```

The person pastes it whole into the window that opens and presses `^D`; the
value is stored with the terminating newline OpenSSH requires. Use it the same
way as any other field:

```bash
vlt file ssh/beta key --out /tmp/deploy.key --mode 0600
```

Never ask for a key in chat, never read one from `~/.ssh`, and never
reconstruct one line by line — `vlt request` is the whole answer.

## Naming and structure

Every record — whatever the credential — has the same shape:

- **name**: `<provider>/<account>[/<purpose>]`, lowercase.
  `github.com/example`, `openai.com/personal`, `ssh/vps-beta`, `internal/build-server`
- **type**: `login token apikey oauth ssh database cert vpn smtp service`
- **fields**: only these — `username password token key secret host port url path
  region account_id`. Anything else goes in `extra`.
- **env_map**: field → environment variable, used by `exec` and `render`.

When you create a request, pick the name and fields from this vocabulary. Do not invent
a parallel scheme; the uniformity is the point.

## What is blocked, and why

The guard hook denies:

| Attempt | Instead |
|---|---|
| `Read ~/.ssh/id_rsa`, `cat .env`, `Read ~/.netrc` | `vlt list` / `vlt exec` |
| `grep -r "ghp_" ~`, `find ~/.ssh -name 'id_*'` | `vlt list` |
| reading the encrypted store or the master key | `vlt exec` / `vlt file` |
| `vlt get`, `vlt show`, `vlt set`, `vlt add`, `vlt import` | human-only |
| `vlt hide` / `vlt unhide` — changing what `peek` masks | human-only |
| `vlt exec X -- env` / `printenv` / `echo $VAR` | run the consuming program |
| reading a file `vlt` just rendered | `vlt peek` |
| editing the hook, the CLI or the policy | ask the user |

If you hit a denial, **do not route around it**. Read the message: it names the command
that does what you actually need. If none does, tell the user what is missing.

Specifically, none of these are acceptable workarounds, and all of them are blocked:
setting `VLT_HUMAN=1`; putting a forbidden command inside a script and running the
script; spelling a command to dodge a pattern (`c""at`, `cd` then a relative path);
piping an encoded payload to a shell; or asking the user to paste a value into the chat.

The user can loosen this temporarily with `vlt guard warn` or `vlt guard off` — that is
their call, never yours, and never something to suggest as a way past a block.

## Housekeeping

```bash
vlt audit --tail 40            # who read what, when
vlt audit --name github.com/example
vlt scan ~                     # inventory credential files not yet in the vault
vlt doctor                     # health check
```

`vlt scan` is safe to run and reports paths and key *names* only — never values. Use it
when the user asks what is still scattered outside the vault.
