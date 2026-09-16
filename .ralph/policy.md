# RALPH-Lite Controller Policy

RALPH-Lite exists to keep ZEN Control development moving inside an explicitly human-approved plan.
The Python controller is the authority for approval state, loop accounting, qualification, repair budgets, and stop conditions. Codex is an implementation worker, not the authority.

## Non-negotiable controls

- A human must approve the exact SHA-256 of every proposed 5-10 step plan before execution.
- Execute exactly one approved plan step per Codex loop. Do not silently expand scope.
- Capture useful out-of-scope discoveries in `.ralph/ideas.md`; do not implement them in the current step.
- `.ralph/plan.md`, `.ralph/state.json`, `.ralph/journal.md`, `.ralph/ideas.md`, and this policy are controller-owned. Codex must not edit them.
- The controller runs authoritative qualification gates after every Codex implementation/repair loop.
- Existing tests may only be modified when the human-approved step explicitly has `test_change_policy=modify`. `add-only` permits new tests but no edits/deletes of existing tests.
- Never delete, skip, xfail, disable, bypass, or weaken a test/gate merely to obtain PASS.
- Never disable or weaken RALPH-Lite controls, sandboxing, qualification, approval hashes, or repair limits from inside an executing plan.
- Never access or modify credentials, secrets, `.env*`, certificates, private keys, or secret stores.
- Never interact with live/production RouterOS or other external production systems from the autonomous loop.
- Stay inside the repository workspace. Do not use destructive host-level commands or privilege escalation.
- If the same failure survives three repair attempts, stop in `BLOCKED_HUMAN`.
- If safe completion requires policy relaxation or judgement outside the approved plan, stop in `BLOCKED_HUMAN`.

## Loop record

Every Codex invocation is one loop. The controller records loop number, plan step, phase, result, repair attempt, failure fingerprint, files changed, gates run, summary, ideas captured, and next action in `.ralph/journal.md`.
