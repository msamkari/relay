# Changelog

## 0.1.0

First release.

- Pending-work registry in the project (`Relay/registry.json`, strict versioned schema, atomic writes, `.bak`, stale-lock and dead-pid takeover, loud failure on corruption) with the full brief of each item saved verbatim in `Relay/briefs/<id>.md`.
- Commands: `init`, `add`, `update`, `list`, `next`, `brief`, `resume-plan`, `check-usage` (read-only ones are pre-approved by the `relay` skill; nothing else is).
- `add` refuses briefs that contain key-like strings unless `--allow-secret-like` is given; `brief` always redacts them when printing.
- One output sanitiser for everything printed (ANSI/CSI/OSC, C0/C1, bidi, zero-width, tag characters, line and paragraph separators).
- Optional guarded ship: `trust` (pin commands, programs and scripts), `approve-ship` (HMAC-signed, expiring, bound to the exact commit, single use), `ship` (checks first, allow-listed command shapes only, no shell, whole-tree kill, step log).
- Skills `relay` and `relay-ship`.
- Known gaps: no plugin icon yet (TODO); real Python 3.8, Linux and macOS runs are covered by CI only.
