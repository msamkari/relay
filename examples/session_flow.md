# A typical flow

```
# once per project
python scripts/relay.py init --yes

# right after launching a background agent (brief written first with the Write tool)
python scripts/relay.py add research-1 --title "Pricing research" --kind agent --owner session-a \
    --status running --report Reports/pricing/comparison.md --brief-file Relay/briefs/research-1.md

# the agent hit a usage limit (HTTP 429)
python scripts/relay.py update research-1 --status stopped --retry-after 2026-12-01T14:00:00Z \
    --partial Reports/pricing/comparison.partial.md --usage-note "429 after page 2"

# next session
python scripts/relay.py next --format text
python scripts/relay.py check-usage --file Relay/usage.json --format text
python scripts/relay.py resume-plan --format text
python scripts/relay.py brief research-1 --format text
# ...launch a NEW agent from the printed brief, then:
python scripts/relay.py update research-1 --status running --owner session-b
```

Ship (only on the user's explicit yes, see skills/relay-ship):

```
python scripts/relay.py trust                 # read every pinned command, then:
python scripts/relay.py trust --yes
python scripts/relay.py approve-ship research-1 --repo OWNER/REPO --branch feat/x \
    --actions pr,merge-ff --conditions ci_green,tests_green,author_check --hours 2
python scripts/relay.py approve-ship ... --yes
python scripts/relay.py ship research-1
```
