# relay

A pending-work registry for Claude Code background agents and tasks, resume plans for a fresh session, and an optional guarded ship step.

Why it exists

- A background agent that hits a usage limit (HTTP 429) dies.
- A NEW session cannot resume another session's subagent. It can only start a new one.
- So everything needed to continue has to be on disk, in the project, before the limit hits.
- Unattended runs (for example a scheduled worker) must not merge or release. Shipping needs a user-authorised, guarded step instead.

relay gives you three things:

1. A registry in the project: `Relay/registry.json` plus the full brief of every agent or task in `Relay/briefs/<id>.md`, with the report path, a pointer to partial results, the last usage note and a retry-after time.
2. Resume skills: at session start `next` lists what is pending or due after a limit reset; `resume-plan` prints a plan to show the user before re-launching each item from its saved brief.
3. An optional ship profile: `trust`, `approve-ship`, `ship` run only commands the user pinned, only the actions the user approved, only for the exact commit the user approved, and only until the approval expires.

Python 3.8+, standard library only. No network access of its own, no API calls, no keys read or printed.

## Install

Add the marketplace and install: `/plugin marketplace add msamkari/samkari-plugins`, then `/plugin install relay@samkari-plugins`. Or point Claude Code at this folder.

Inside Claude Code the skills run the script for you. In your own terminal call it by its real path, from the PROJECT folder (the one that holds `Relay/`), never from the plugin folder:

```
# bash, zsh, Git Bash (quote the path when it has a space)
python "<plugin-folder>/scripts/relay.py" init --yes

# PowerShell: ${CLAUDE_PLUGIN_ROOT} is NOT a PowerShell variable; $env:CLAUDE_PLUGIN_ROOT only exists inside Claude Code
python "<plugin-folder>/scripts/relay.py" init --yes
python "$env:CLAUDE_PLUGIN_ROOT/scripts/relay.py" next --format text
```

About the pre-approved skill commands: they are written without quotes on purpose, because Claude Code matches the exact text. If the plugin folder has a space in its path (a Windows user name with a space, for example) the shell splits an unquoted path and the command fails. Quote it (Claude Code will then ask for each command instead of pre-approving it) or install the plugin under a path without spaces.

`init` creates `Relay/registry.json`, `Relay/config.json` and `Relay/briefs/` and never overwrites an existing file. Decide whether `Relay/` belongs in version control: the briefs are the point, but they are your own text, so treat them like any project note.

## Commands

Read-only (pre-approved by the `relay` skill; they take no `--root` and never write anything):

| command | what it does |
|---|---|
| `list [--status S] --format text\|json` | all items |
| `next --format text\|json` | DUE (pending or stopped, retry time passed), WAITING (retry time in the future), RUNNING but silent (the owner may be dead), BLOCKED; ordered |
| `brief <id>` | the saved brief, redacted and sanitised, quoted as data after a fixed warning line |
| `resume-plan --format text\|json` | a plan to SHOW the user: relay's fixed steps plus every item field as quoted data |
| `check-usage ...` | continue or wait, from numbers you pass in |

Which commands write files (everything else writes nothing):

| command | writes |
|---|---|
| `init --yes` | `Relay/registry.json`, `Relay/config.json`, `Relay/briefs/` (never overwrites) |
| `add` | `Relay/briefs/<id>.md` (unless you pass an existing one), `Relay/registry.json` and its `.bak` |
| `update` | `Relay/registry.json` and its `.bak` |
| `trust --yes` | `trust.json` in `$RELAY_HOME` (default `~/.relay`) |
| `approve-ship --yes` | `secret.key` (first time), `approvals/<nonce>.json` in `$RELAY_HOME`; prunes old approvals and claims there |
| `ship` | `claims/<signature>` in `$RELAY_HOME` (before any step runs), `Relay/ship_log.jsonl`, `Relay/registry.json` (item marked done), and whatever the pinned git and gh commands change |
| `verify-authors` | nothing |

Not pre-approved (Claude Code asks every time): `init`, `add`, `update`, `trust`, `approve-ship`, `ship`.

`add <id> --title T [--kind agent|task|release] [--owner O] [--status S] [--report PATH] [--resume-hint T]` plus exactly one of `--brief-file PATH` (a path inside the project, or the file `Relay/briefs/<id>.md` already written there), `--brief-text TEXT`, `--brief-stdin`. The brief is saved verbatim (CRLF and BOM kept). Briefs with key-like strings (`sk_`, `ghp_`, `github_pat_`, `AKIA`, `xox`, private key headers, key assignments, long hex or base64 tokens) are refused unless `--allow-secret-like` is given (a warning is printed), and `brief` always prints them redacted. The report path must be inside `Relay/reports/`; paths into `.claude/`, `.github/`, `.git/`, settings files, `.env*`, `*.key`, `*.pem` or `CLAUDE.md` are refused (a report path is where a re-launched agent is told to write). A registry that already holds such a path (for example one that arrived with a cloned project) is not refused as a whole: its item is marked REFUSED, left out of the resume plan and its brief is not printed.

`update <id> [--status S] [--partial PATH] [--usage-note T] [--retry-after TIME] [--clear-retry] [--owner O] [--report PATH] [--resume-hint T] [--reopen]`. `TIME` is ISO-8601 with a zone (`2026-12-01T09:00:00Z`, `+03:00`) or relative (`+90m`, `+5h`, `+2d`); it is stored as one UTC instant, so every spelling of the same moment is the same value; more than 30 days ahead is refused. A `done` item stays done unless `--reopen`. A write that would make the registry larger than the 1 MiB limit every command enforces is refused and writes nothing.

`check-usage` reads numbers from flags (`--five-hour 72 --five-hour-reset TIME --weekly 40 --weekly-reset TIME`) or from a JSON snapshot file inside the project (`--file Relay/usage.json`, at most 16 KB, see `examples/usage_snapshot.json`). Thresholds come from `Relay/config.json` (`usage.five_hour_pct` default 60, `usage.weekly_pct` default 75, never above 90). If no numbers are given it refuses: it never guesses. If a window is over its limit but the reset time is unknown it says so instead of inventing one.

Ids: letters, digits, `.`, `_`, `-`, up to 64, starting with a letter or digit, case-insensitively unique, no device names (`CON`, `NUL`, ...), no trailing dot.

Files relay will not read or replace: symlinks and junctions, and hard-linked files (more than one link), because those can be the same file as one outside the project.

## Ship (optional)

Add a `ship` section to `Relay/config.json` (`examples/config.ship.json`). Every command is an argv list; there is never a shell.

- `trust` prints every pinned command in full (never cut), the program each one resolves to (searched on `PATH` only, never the project folder or the current folder; Windows `.exe` only) and a pin. `trust --yes` records the pin in `$RELAY_HOME/trust.json`. The pin covers the commands, the resolved program path and content hash, the content of the script a `{python}` or `{relay}` command runs, and the settings of the pinned remote (its url, pushurl and refspecs). When the pin no longer matches, `trust` and `ship` print WHAT changed (a different resolved path, a changed program, script or git setting, the ship section); they never suggest `--yes`. A different PATH order between shells is a common cause.
- Before any ship step relay scans the repository and REFUSES it if its own config (the file `.git/config`, worktree config and anything it includes) holds: `filter.*.smudge|clean|process`, `core.editor`, `core.sshCommand`, `core.fsmonitor`, `core.hooksPath`, `core.gitProxy`, `core.askpass`, `core.attributesFile`, `sequence.editor`, `credential.*`, `include.*` or `includeIf.*`, `url.*.insteadOf|pushInsteadOf`, `alias.*`, `diff.*.command|textconv` or `diff.external`, `merge.*.driver`, `gpg.program`, `http.*`, `https.*`, `protocol.*`, `push.followTags`, `remote.*.vcs|proxy|receivepack|uploadpack|mirror`, or a `url`/`pushurl` of any remote other than the pinned one. It also refuses a repository whose `.gitattributes` (in the approved commit, HEAD, the target branch, the working folder, or `.git/info/attributes`) uses a `filter` or git LFS. Includes are refused outright, so no `includeIf` can change a setting later, for example only on one branch. The config scan is repeated before every action step; the attributes scan runs at `trust`, `approve-ship`, the start of `ship` and again before the actions.
- `repo` in the config and in an approval is verified against the URL of the pinned remote: for a network URL (https, ssh, scp style) the `owner/name` in the URL must equal `config.ship.repo`; for a local path or `file://` URL the name cannot be checked and `trust` says so.
- `approve-ship <id> --repo R --branch B --actions pr,merge-ff,tag,release --conditions ci_green,tests_green,author_check [--tag vX.Y.Z] [--hours N]` shows a plan; with `--yes` it records an HMAC-signed approval in `$RELAY_HOME/approvals/`. It is bound to the project folder, the item, the repo, the branch, the exact commit sha (computed by relay with a fixed git call on `refs/heads/<branch>`), the action list, the tag and the trust pin. It refuses when a tag or another ref has the same name as the branch or the target (git would take that name for the tag). Lifetime up to 24 hours, single use. Merge, tag and release require `tests_green` and `author_check`; merge and release also require `ci_green`.
- `ship <id>` re-verifies everything (signature, expiry, repo, pin, repository scan, branch tip equals the approved sha), records the approval as spent BEFORE any step runs (if that record cannot be written it refuses), runs the pinned check commands in a clean temporary detached worktree of the approved commit (not your working folder; any failure aborts), re-checks the tip and the pin, then runs the action steps in the order pr, merge-ff, tag, release, re-checking the tip, the pin and the config before each step. Every step is written to `Relay/ship_log.jsonl`.

Allow-list, not deny-list: each action may only be one of a few exact command shapes, and refs are bound to the approved commit:

| action | shapes (a `--` may stand before the refs) |
|---|---|
| pr | `git push [-u] origin {push_branch}`, `gh pr create ...` |
| merge-ff | `git switch main`, `git fetch origin`, `git merge --ff-only {sha}`, `git push origin {push_target}` |
| tag | `git tag -a -m TEXT {tag} {sha}`, `git push origin {push_tag}` |
| release | `gh release create {tag} --verify-tag ...` (`--target` only `{sha}`) |

`{push_branch}` is `<sha>:refs/heads/<branch>`, `{push_target}` is `<sha>:refs/heads/<target>` and `{push_tag}` is `refs/tags/<tag>:refs/tags/<tag>`. Before a merge relay checks that HEAD is the target branch, before a target push that the target branch IS the approved sha, and before a tag push that the tag points at the approved sha. Force push, delete, visibility changes and admin overrides are not shapes that exist. `author_check` is the built-in `{relay} verify-authors --base main --branch {sha} --name N --email E`, which examines exactly the commits reachable from the approved sha (never a ref name a tag could shadow) and fails on any commit with another author or committer, a Co-Authored-By trailer, a tool footer or a session link.

Every git and gh process relay starts runs with: no system or user git configuration (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL` pointing at a private temp file), no editor (`GIT_EDITOR=:`, `-c core.editor=:`), no prompts (`GIT_TERMINAL_PROMPT=0`, no `GIT_ASKPASS`), hooks off (`-c core.hooksPath=<empty temp folder>`), `-c core.fsmonitor=false` and `-c protocol.ext.allow=never`. The private config file holds only plain data copied from your own git config: `core.autocrlf`, `core.eol`, `core.safecrlf`, `core.longpaths`, `user.name`, `user.email` (without them every CRLF checkout on Windows looks modified and a tag needs a repo-level identity). Consequences: your own `pre-push` or `post-merge` hooks do not run during `ship` (pin those checks as `checks`), a credential helper or `safe.directory` from your global config is not used (use an SSH remote whose key needs no prompt, or pass an agent socket with a step `env` entry that is also in `env_allow.json`), and `core.sshCommand` is refused in the repository config instead of being blanked (an empty value makes git try to run an empty program on every ssh push; checked with `GIT_TRACE`).

Kill switch: when `RELAY_NO_SHIP` (any non-empty value) or `RELAY_UNATTENDED` is set, `trust --yes`, `approve-ship` and `ship` refuse. Set it in scheduled and unattended environments.

## How it fits with the other plugins

- nightshift runs a queue unattended and is forbidden to merge or release; relay records what it could not finish and keeps the guarded ship step for a human-supervised session.
- loom (content pipelines) uses the same safe patterns for pinned commands and signed approvals; relay is separate and imports nothing from it.
- persistent-memory keeps long-term notes; relay keeps only the short-lived state needed to continue unfinished background work.

## Honest limits

- A stopped subagent cannot be resumed from another session. relay does not pretend otherwise: it re-launches a NEW agent from the saved brief and the saved partial results. How much work survives depends on the agent having written partial results to disk.
- The registry is text on disk. relay cannot know that an agent is really dead; a `running` item that has been silent for `running_stale_hours` (default 6) is only flagged.
- relay does not read your usage. You (or a tool such as `get_usage`) pass the numbers in.
- Text in the registry and briefs is data: every field is printed quoted after a fixed warning line and sanitised (control, bidi, zero-width, tag, variation-selector, private-use and fill characters are removed; Arabic marks are kept), the report path is restricted, and the skills tell Claude to show the plan to you first. But relay cannot stop a model from being persuaded by text, and a registry has no signature: it cannot tell which entries you wrote.
- A pinned command runs with your user rights, and relay pins what it can see: the program (path and content) and the CONTENT of the script it is given (`{python} tools/check.py`). Modules that script imports, and the code `{python} -m something` runs, are not pinned (a known limit). Checks run in a clean worktree of the approved commit, so a check script must be committed on that branch, and a script whose content in that commit differs from the pinned one is refused.
- Approval signing keeps a project file, a cloned repository or a hostile brief from forging an approval. It does not stop the same OS user (or a session in bypass-permissions mode) from running `approve-ship --yes` itself: the permission prompt and the kill switch (`RELAY_NO_SHIP`) are the controls. Never run ship from a scheduled task.
- Ship cannot undo anything. A merge or tag that went through stays until you revert it. It never force-pushes, deletes a branch or repo, or changes visibility. The only branches it touches are the approved feature branch and the configured target (`merge-ff` switches to the target and pushes it). It does not delete the merged feature branch either; do that yourself.
- The repository scan is a refusal list of known code-running settings, not proof that no other setting matters. Remote helpers and programs named in a setting relay does not know are not covered.
- Windows: pinned programs must be `.exe` (no `.bat`, `.cmd`, `.ps1`); wrap a script with `{python}`. A project path longer than about 258 characters cannot be used at all: Windows cannot start a process whose current folder is that long, so `list`, `next`, `ship` and every pinned command fail there. Keep the project path short.
- Every pinned command runs in a process tree that is killed when it ends or times out (a Job Object on Windows, a process group on POSIX). A process started through WMI (`Win32_Process.Create`), a scheduled task, a service or `setsid` is outside that tree and outlives the run.
- Locks: a stale lock is taken over when its owner process is gone or its pid belongs to a process that started at another time. Where the start time cannot be read the lock is respected for a day. A lock left by a crash on another machine (a synced folder) needs ten times the stale limit.
- Approval and claim files in `$RELAY_HOME` are pruned on `approve-ship --yes` (approvals a day after they expire, claims after three days). The relay home folder keeps its inherited folder permissions on Windows (only the files in it get an owner-only ACL), so do not point `RELAY_HOME` at a shared folder.
- Environment variables reach pinned commands only if named in the step and listed in `$RELAY_HOME/env_allow.json`.
- Interrupted writes can leave `Relay/.relay-*.tmp` files; delete them by hand.
- Tested locally on Windows with Python 3.14 only. The CI workflow covers Python 3.8 and 3.12 on Ubuntu, Windows and macOS (3.12) but has not run on this version yet.

## Tests

```
python -m unittest discover -s tests
```

MIT licence. Author: Mohammad Samkari.
