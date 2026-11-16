# Changelog

## 0.1.0
- Plugin icon added (square 1024 px PNG, generated with Gemini and chosen by the author).

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
- Known gaps: no plugin icon yet (TODO); real Python 3.8, Linux and macOS runs are covered by CI only.
