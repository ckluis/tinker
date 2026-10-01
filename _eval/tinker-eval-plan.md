# Tinker evaluation plan

You have the Tinker framework source (zip) and its overview doc. Evaluate it.

## Step 1 — Prove understanding
In your own words: (a) what Tinker is and what problem it solves, (b) how a
request flows from credential to response, (c) what "no existence oracle" and
"fail closed" mean in this design. Flag anything unclear — don't paper over it.

## Step 2 — Evaluate
1. Architecture: sound layering? Anything you'd restructure?
2. Security: does tenant isolation hold? Where would YOU attack it (auth,
   approval replay, PII exfiltration, file uploads)? Reference code paths.
3. Verification culture: spot-check 2–3 claims from STATUS.md against the
   actual code. Do they hold?
4. LLM-first thesis: kill-bar experiments claim the MCP API is self-teaching
   and static docs add no measurable value (BACKLOG.md). Do you buy the
   methodology?
5. Production readiness: what's the single riskiest gap before real traffic?
6. Verdict: strengths, weaknesses, 1–10 score with justification.

Ground claims in code and docs, not in what the project's own ledger says
about itself. Distinguish what you verified from what you took on trust.
