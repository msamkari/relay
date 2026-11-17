# Brief: research agent for the pricing comparison

Goal: compare the three pricing pages listed under Inputs and write one table.

Inputs
- Reports/pricing/sources.md (the list of pages, one per line)

Constraints
- Read only; do not change files outside Relay/reports/.
- No keys or tokens in the report. If a page needs a login, skip it and say so.

Output
- Write the report to Relay/reports/pricing-comparison.md.
- Save what you have so far to Relay/reports/pricing-comparison.partial.md after every page.

If you are re-launched after a stop
- Read Relay/reports/pricing-comparison.partial.md first and continue with the first page not yet in it.
- Do not redo finished pages.
