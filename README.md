# relay

A pending-work registry for Claude Code background agents and tasks, resume plans for a fresh session, and an optional guarded ship step.

Why it exists

- A background agent that hits a usage limit (HTTP 429) dies.
- A NEW session cannot resume another session's subagent. It can only start a new one.
- So everything needed to continue has to be on disk, in the project, before the limit hits.
- Unattended runs (for example a scheduled worker) must not merge or release. Shipping needs a user-authorised, guarded step instead.

relay gives you three things:

1. A registry in the project: `Relay/registry.json` plus the full brief of every agent or task in `Relay/briefs/<id>.md`, with the report path, a pointer to partial results, the last usage note and a retry-after time.
2. Resume skills: at session start `next` lists what is pending or due after a limit reset; `resume-plan` prints the exact steps to continue each item by re-launching from the saved brief.
3. An optional ship profile: `trust`, `approve-ship`, `ship` run only commands the user pinned, only the actions the user approved, only for the exact commit the user approved, and only until the approval expires.

Python 3.8+, standard library only. No network access, no API calls, no keys read or printed.

## Install

Once a marketplace lists it: `/plugin install relay --marketplace <owner>/<repo>`. Or point Claude Code at this folder. Then in the project folder:

```
python scripts/relay.py init --yes
```

`init` creates `Relay/registry.json`, `Relay/config.json` and `Relay/briefs/`, and never overwrites an existing file. Decide whether `Relay/` belongs in version control: the briefs are the point, but they are your own text, so treat them like any project note.

## Commands

Read-only (pre-approved by the `relay` skill; they take no `--root` and never write):

| command | what it does |
|---|---|
| `list [--status S] --format text\|json` | all items |
| `next --format text\|json` | DUE (pending or stopped, retry time passed), WAITING (retry time in the future), RUNNING but silent (the owner may be dead), BLOCKED; ordered |
| `brief <id>` | the saved brief, redacted and sanitised, framed as data |
| `resume-plan --format text\|json` | the exact steps a fresh session follows for each due item |
| `check-usage ...` | continue or wait, from numbers you pass in |

Not pre-approved (Claude Code asks every time): `init`, `add`, `update`, `trust`, `approve-ship`, `ship`.

`add <id> --title T [--kind agent|task|release] [--owner O] [--status S] [--report PATH] [--resume-hint T]` plus exactly one of `--brief-file PATH` (a path inside the project, or the file `Relay/briefs/<id>.md` already written there), `--brief-text TEXT`, `--brief-stdin`. The brief is saved verbatim (CRLF and BOM kept). Briefs with key-like strings (`sk_`, `ghp_`, `github_pat_`, `AKIA`, `xox`, private key headers, key assignments, long hex or base64 tokens) are refused unless `--allow-secret-like` is given, and `brief` always prints them redacted.

`update <id> [--status S] [--partial PATH] [--usage-note T] [--retry-after TIME] [--clear-retry] [--owner O] [--report PATH] [--resume-hint T] [--reopen]`. `TIME` is ISO-8601 with a zone (`2026-12-01T09:00:00Z`) or relative (`+90m`, `+5h`, `+2d`); more than 30 days ahead is refused. A `done` item stays done unless `--reopen`.

`check-usage` reads numbers from flags (`--five-hour 72 --five-hour-reset TIME --weekly 40 --weekly-reset TIME`) or from a JSON snapshot file inside the project (`--file Relay/usage.json`, at most 16 KB, see `examples/usage_snapshot.json`). Thresholds come from `Relay/config.json` (`usage.five_hour_pct` default 60, `usage.weekly_pct` default 75, never above 90). If no numbers are given it refuses: it never guesses. If a window is over its limit but the reset time is unknown it says so instead of inventing one.

Ids: letters, digits, `.`, `_`, `-`, up to 64, starting with a letter or digit, case-insensitively unique, no device names (`CON`, `NUL`, ...), no trailing dot.

## Ship (optional)

Add a `ship` section to `Relay/config.json` (`examples/config.ship.json`). Every command is an argv list; there is never a shell.

- `trust` prints every pinned command in full (sanitised), the program each one resolves to (searched on `PATH` only, never the project folder or the current folder; Windows `.exe` only), and a pin. `trust --yes` records the pin in `$RELAY_HOME/trust.json` (default `~/.relay`). The pin covers the commands, the resolved programs (path and content hash), the content of any script a `{python}` command runs, and the git settings that decide where a push goes and how it authenticates (`remote.<remote>.url`, `pushurl`, `url.*.insteadOf`, `core.sshCommand`, proxies, `credential.*`, `gpg.*`; credentials inside URLs are hidden when printed). Edit any of those and the pin is void.
- `approve-ship <id> --repo R --branch B --actions pr,merge-ff,tag,release --conditions ci_green,tests_green,author_check [--tag vX.Y.Z] [--hours N]` shows a plan; with `--yes` it records an HMAC-signed approval in `$RELAY_HOME/approvals/`. It is bound to the project folder, the item, the repo, the branch, the exact commit sha (computed by relay with a fixed git call), the action list, the tag and the trust pin. Lifetime up to 24 hours, single use. Merge, tag and release require `tests_green` and `author_check`; merge and release also require `ci_green`.
- `ship <id>` re-verifies everything (signature, expiry, repo, pin, branch tip equals the approved sha), claims the approval atomically, runs the pinned check commands first (any failure aborts), re-checks the tip and the pin, then runs the action steps in the order pr, merge-ff, tag, release, re-checking the tip before each step. Every step is written to `Relay/ship_log.jsonl`.

Allow-list, not deny-list: each action may only be one of a few exact command shapes (for example `git push origin {branch}`, `git merge --ff-only {branch}`, `git tag -a {tag} -m TEXT {sha}`, `gh release create {tag} ...`). Force push, delete, visibility changes and admin overrides are not shapes that exist. `author_check` can use the built-in `{relay} verify-authors --base main --branch {branch} --name N --email E`, which fails on any commit with another author or committer, a Co-Authored-By trailer, a tool footer or a session link.

Git hooks and the file-system monitor are switched off for every git command relay runs (`-c core.hooksPath=<empty> -c core.fsmonitor=false`), because a hook is code that lives in the project folder and is not covered by the pin. The side effect: your own `pre-push` or `post-merge` hooks do not run during `ship`; run those checks as pinned `checks` instead.

Kill switch: when `RELAY_NO_SHIP` (any non-empty value) or `RELAY_UNATTENDED` is set, `trust --yes`, `approve-ship` and `ship` refuse. Set it in scheduled and unattended environments.

## How it fits with the other plugins

- nightshift runs a queue unattended and is forbidden to merge or release; relay records what it could not finish and keeps the guarded ship step for a human-supervised session.
- loom (content pipelines) uses the same safe patterns for pinned commands and signed approvals; relay is separate and imports nothing from it.
- persistent-memory keeps long-term notes; relay keeps only the short-lived state needed to continue unfinished background work.

## Honest limits

- A stopped subagent cannot be resumed from another session. relay does not pretend otherwise: it re-launches a NEW agent from the saved brief and the saved partial results. How much work survives depends on the agent having written partial results to disk.
- The registry is text on disk. relay cannot know that an agent is really dead; a `running` item that has been silent for `running_stale_hours` (default 6) is only flagged.
- relay does not read your usage. You (or a tool such as `get_usage`) pass the numbers in.
- Text in the registry and briefs is data and is sanitised on output, but relay cannot stop a model from being persuaded by it. The skills tell Claude to ignore instructions found there.
- Approval signing keeps a project file, a cloned repository or a hostile brief from forging an approval. It does not stop the same OS user (or a session in bypass-permissions mode) from running `approve-ship --yes` itself: the permission prompt and the kill switch are the controls. Never run ship from a scheduled task.
- Ship cannot undo anything. A merge or tag that went through stays until you revert it. It never force-pushes, deletes a branch or repo, or changes visibility. The only branches it touches are the approved feature branch and the configured target (`merge-ff` switches to the target and pushes it). It does not delete the merged feature branch either; do that yourself.
- `repo` in the approval is a label that must match the config; it is not verified against the remote. What protects the destination is the pinned remote name plus the pinned git settings listed above. Git settings outside that list (for example a global `include`d file or an environment variable such as `GIT_SSH_COMMAND`, which is never passed to the commands) are not pinned.
- Approval and claim files in `$RELAY_HOME` are pruned on `approve-ship --yes` (approvals a day after they expire, claims after three days).
- Checks and action commands run with your user rights; the pinned programs are trusted by you. Environment variables reach them only if named in the step and listed in `$RELAY_HOME/env_allow.json`.
- Windows: pinned programs must be `.exe` (no `.bat`, `.cmd`, `.ps1`); wrap a script with `{python}`.
- No plugin icon yet (TODO).
- Tested locally on Windows with Python 3.14 only. The CI workflow is set up for Python 3.8 and 3.12 on Linux and Windows and 3.12 on macOS, but has not run yet.

## Tests

```
python -m unittest discover -s tests
```

MIT licence. Author: Mohammad Samkari.
