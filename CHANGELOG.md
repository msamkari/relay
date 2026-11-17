# Changelog

## 0.1.1

Hardening after an adversarial review of 0.1.0. Breaking for ship configs: the 0.1.0 command shapes that named a branch by its bare name are gone (see Changed).

Fixed
- `merge-ff`, `push` and `tag` are bound to the approved commit and to fully qualified refs. Before: a tag spelled like the approved branch made `git merge --ff-only <branch>` merge and push an unapproved commit. Now `approve-ship` and `ship` refuse when a tag (or `refs/<name>`, `refs/remotes/<name>`) has the same name as the branch or the target; the merge names the sha, pushes use `<sha>:refs/heads/<branch>` and `refs/tags/<tag>:refs/tags/<tag>`, a tag is `git tag -a -m TEXT <tag> <sha>`, and HEAD, the target branch and the tag are verified against the approved sha right before the step that depends on them.
- `verify-authors` (the `author_check`) reads refs as `refs/heads/<name>` or a full sha, and ship requires `--branch {sha}`, so it examines exactly the commits reachable from the approved sha and a tag named `main` cannot narrow the range.
- Every git and gh process runs hardened: no system or user git configuration (a private temp config that copies only `core.autocrlf`, `core.eol`, `core.safecrlf`, `core.longpaths`, `user.name`, `user.email`), `GIT_EDITOR=:`, no prompts, no askpass, hooks pointed at an empty temp folder, `core.editor=:`, `core.fsmonitor=false`, `protocol.ext.allow=never`.
- The repository config is scanned before every ship step and the repository is refused when it holds filter drivers, editors, ssh commands, fsmonitor, hooks paths, credential helpers, includes (so no `includeIf onbranch` redirect), URL rewrites, aliases, diff or merge programs, a gpg program, http settings, remote helpers, or a url of a remote that is not the pinned one; also when a `.gitattributes` uses a filter or git LFS. The settings of the pinned remote are part of the pin.
- Checks (`ci_green`, `tests_green`, `author_check`) run in a clean temporary detached worktree of the approved commit, not the working folder, which is removed afterwards. A check script whose content in that commit differs from the pinned script is refused.
- The approval is recorded as spent before any step runs; if the record cannot be written the ship is refused.
- The pin stores the resolved program path and content hash per step; a mismatch prints what changed and never suggests `--yes`.
- Stale-lock takeover uses the owner's process start time (a reused pid is no longer mistaken for the owner), a one-day ceiling where the start time cannot be read, and an accurate message naming the lock folder.
- Parallel `trust --yes` runs keep every pin (regression test; the write is locked and atomic).
- `trust` prints argv in full, never cut.
- `resume-plan` and `brief` print every item field as quoted data after a fixed warning line; the plan says to show it to the user first. Report paths must be inside `Relay/reports/` and never `.claude/`, settings, `.env*`, `*.key`, `*.pem`, `CLAUDE.md`, `.github/`, `.git/`; a registry that already holds one marks the item REFUSED instead of failing as a whole.
- The repo name in an approval is verified against the pinned remote URL (network URLs; a local path cannot be checked).
- Hard-linked files are refused for reads and replacements of the registry, briefs, ship log and home files.
- A registry save that would exceed the size limit is refused instead of writing a file every command then rejects.
- The output sanitiser also removes variation selectors, tag characters, private-use characters, Hangul fillers, the braille blank, Khmer inherent vowels and the combining grapheme joiner; Arabic combining marks are kept.
- Windows helpers are absolute paths in the system folder (`taskkill` included); git and gh are resolved from PATH without the project and current folders, and the PATH handed to every child no longer contains them either.
- The error text for a key-like brief no longer offers `--allow-secret-like` (the flag still exists and is documented in the README).
- Test suite: layout test accepts the icon, CRLF in the changelog fixed, a test that no text file has a carriage return, timing-dependent assertions removed from the new tests.

Changed (breaking for ship configs)
- Action shapes: `git push origin {push_branch}` (was `{branch}`), `git merge --ff-only {sha}` (was `{branch}`), `git push origin {push_target}` (was `main`), `git tag -a -m TEXT {tag} {sha}` (`-m` and `{sha}` now required), `git push origin {push_tag}` (was `{tag}`), `gh release create {tag} --verify-tag` (`--verify-tag` required; `--target` only `{sha}`). A `--` may stand before the refs. `examples/config.ship.json` is updated.
- A `{relay}` check may only run `verify-authors --branch {sha}`.
- Trust records are now objects with readable details, and the pin payload changed: every 0.1.0 pin no longer matches, so run `trust` again after upgrading (a bare-hash record that happens to equal the new hash is still accepted, but a mismatch on one cannot show a diff).

Known limits (also in the README)
- A pinned command runs with the user's rights. relay pins the program and the content of the script it is given; modules that script imports and `{python} -m ...` code are not pinned.
- A session in bypass-permissions mode can run `approve-ship --yes` itself; `RELAY_NO_SHIP` is the kill switch.
- The repository scan is a refusal list; it is not proof that no other setting runs code. `core.sshCommand` is refused rather than blanked (an empty value makes git spawn an empty program on every ssh push).
- Because the user-level git configuration is not read, credential helpers and `safe.directory` from it do not apply during ship (use an SSH remote with a key that needs no prompt, or an agent socket allowed through `env_allow.json`).
- "Unless explicitly pinned" for filters and git LFS is not implemented: they are always refused.
- The home folder keeps inherited Windows folder permissions; a secret planted by another principal in a shared `RELAY_HOME` is not detected. Leftover `.relay-*.tmp` files after a crash are not swept.
- A process started through WMI, a scheduled task or a service outlives the run; Windows paths over about 258 characters cannot be used.
- Only run on Windows with Python 3.14 here; Python 3.8, Linux and macOS are covered by CI only.

## 0.1.0

First release.

- Pending-work registry in the project (`Relay/registry.json`, strict versioned schema, atomic writes, `.bak`, stale-lock and dead-pid takeover, loud failure on corruption) with the full brief of each item saved verbatim in `Relay/briefs/<id>.md`.
- Commands: `init`, `add`, `update`, `list`, `next`, `brief`, `resume-plan`, `check-usage` (read-only ones are pre-approved by the `relay` skill; nothing else is).
- `add` refuses briefs that contain key-like strings unless `--allow-secret-like` is given; `brief` always redacts them when printing.
- One output sanitiser for everything printed (ANSI/CSI/OSC, C0/C1, bidi, zero-width, tag characters, line and paragraph separators).
- Optional guarded ship: `trust` (pin commands, programs and scripts), `approve-ship` (HMAC-signed, expiring, bound to the exact commit, single use), `ship` (checks first, allow-listed command shapes only, no shell, whole-tree kill, step log).
- Trust also pins the git settings that decide where a push goes and how it authenticates (remote url and pushurl, url rewrites, ssh command, proxies, credential helpers, gpg program). Git hooks and the file-system monitor are switched off for every git command relay runs.
- Approval and claim files in the home folder are pruned on `approve-ship --yes`.
- `resume-plan` and `brief` show the saved resume hint and last usage note; key-like strings are refused in title, owner, hint and note and redacted on every print.
- Skills `relay` and `relay-ship`.
- Plugin icon added (square 1024 px PNG, generated with Gemini and chosen by the author).
