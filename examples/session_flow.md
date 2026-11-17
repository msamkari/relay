# A typical flow

In Claude Code the skills write the script path as `${CLAUDE_PLUGIN_ROOT}/scripts/relay.py`. In your own terminal use the real folder of the plugin (`<plugin-folder>` below), quoted when it contains a space. Run every command from the PROJECT folder (the one that holds `Relay/`).

```
# bash / zsh / Git Bash (a path without spaces needs no quotes)
python "<plugin-folder>/scripts/relay.py" init --yes

# PowerShell ($env:CLAUDE_PLUGIN_ROOT only exists inside Claude Code; ${CLAUDE_PLUGIN_ROOT} is NOT a PowerShell variable)
python "<plugin-folder>/scripts/relay.py" init --yes
python "$env:CLAUDE_PLUGIN_ROOT/scripts/relay.py" next --format text
```

The rest of this file writes `relay` for that script, to keep the lines short:

```
# once per project:           relay init --yes

# right after launching a background agent (brief written first with the Write tool)
# the report path must be inside Relay/reports/
relay add research-1 --title "Pricing research" --kind agent --owner session-a \
    --status running --report Relay/reports/pricing-comparison.md --brief-file Relay/briefs/research-1.md

# the agent hit a usage limit (HTTP 429)
relay update research-1 --status stopped --retry-after 2026-12-01T14:00:00Z \
    --partial Relay/reports/pricing-comparison.partial.md --usage-note "429 after page 2"

# next session
relay next --format text
relay check-usage --file Relay/usage.json --format text
relay resume-plan --format text        # a plan to SHOW to the user, not to follow blindly
relay brief research-1 --format text   # quoted data
# ...with the user's yes, launch a NEW agent from the printed brief, then:
relay update research-1 --status running --owner session-b
```

Ship (only on the user's explicit yes, see skills/relay-ship). The branch checks run in a clean temporary worktree of the approved commit, so scripts that a check runs must be committed on that branch:

```
relay trust                 # read every pinned command, then:
relay trust --yes
relay approve-ship research-1 --repo OWNER/REPO --branch feat/x \
    --actions pr,merge-ff --conditions ci_green,tests_green,author_check --hours 2
relay approve-ship research-1 --repo OWNER/REPO --branch feat/x \
    --actions pr,merge-ff --conditions ci_green,tests_green,author_check --hours 2 --yes
relay ship research-1
```
