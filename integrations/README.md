# Integrations

The `vlt` CLI works anywhere Python does. **The enforcement does not.**

That distinction is the whole point of this page, so it is worth stating plainly
before anything else:

> The guarantees in the main README hold **only** where the agent harness can run
> a pre-tool hook that denies a tool call before it executes. Everywhere else,
> `vlt` is a convenient encrypted store and a protocol the agent may follow — and
> nothing stops that agent reading `~/.ssh/id_rsa` directly instead.

An agent that can be *asked* not to read your keys is not the same as an agent
that *cannot*.

## Claude Code — supported

Everything works. `install.sh` sets it up:

- `vault-guard.py` runs as a `PreToolUse` hook on
  `Read|Edit|Write|NotebookEdit|Bash|Grep|Glob`. It returns a deny decision, so
  the tool call never executes. It runs as a separate process, so a prompt
  injection cannot talk it out of a decision.
- `SKILL.md` teaches the protocol — `list` → `peek` → `exec`/`file`/`render`, and
  `request` when something is missing.
- A block in `CLAUDE.md` states the rule so agents do not waste a turn
  discovering it by being denied.

The hook is what makes this real. Without it the skill is advice, and
[claude-code#44868](https://github.com/anthropics/claude-code/issues/44868) shows
what advice is worth.

## Everything else — CLI only

For **Codex CLI**, **opencode**, **Cursor**, **Gemini CLI**, **Aider** and the
rest, you get the store and the protocol, not the enforcement:

1. Install the CLI (`./install.sh` does this regardless of what agent you use).
2. Put the protocol where that agent reads its instructions — `AGENTS.md`,
   `.cursorrules`, a system prompt. Start from
   `claude-code/SKILL.md`; the commands are identical.
3. Understand what you have not got: nothing prevents that agent reading a
   credential file. Treat compliance as best-effort.

A minimal instruction block:

```markdown
## Credentials
Never read .env, ~/.ssh, ~/.netrc, *.pem, or ~/.aws/credentials. Never search for
keys, tokens or passwords. Never ask for a credential value in chat.
  vlt list                          what exists
  vlt peek <name>                   structure only — length, charset, first chars
  vlt exec <name> -- <command>      run a command with it in the environment
  vlt-ssh <name> [command]          ssh with a record's key or password
  vlt file <name> <field> --out P   write one field to a file
  vlt request <name> --fields a,b   missing? opens a window for the user
Never print, echo, cat, log or commit a credential value.
```

The CLI still refuses its own human-only commands to anything that looks like an
agent (`CLAUDECODE`, `AI_AGENT` and similar in the environment), and human-only
commands still require a terminal or a desktop confirmation. That is a second
layer, not a substitute for the first.

## Adding enforcement for another harness

If your agent runs a hook before tool execution, port `vault-guard.py`. It needs
three things from the harness:

1. **The tool name and its arguments**, before the tool runs.
2. **A way to deny**, with a message the model sees.
3. **To run out-of-process**, so the model cannot reason its way past it.

The hook reads a JSON event on stdin (`tool_name`, `tool_input`) and writes a
JSON decision on stdout. Adapting the input and output shapes is most of the
work; the matching logic is harness-independent.

If you do port it, `tests/hooktest.py`, `tests/evasion_test.py` and
`tests/prose_test.py` are the acceptance criteria — they call the hook directly
and do not care what invokes it in production.
