# ZEN and RALPH-Lite Glossary

These are shared terms derived from the current ZEN and RALPH-Lite implementation and its operator-facing contracts. They define documentation language; they do not replace live diagnostics, RouterOS verification, or controller qualification.

## ZEN terms

| Term | Meaning |
| --- | --- |
| **ZEN Control (ZEN)** | The self-hosted application that manages household policy, observes supported evidence, and coordinates bounded RouterOS changes. It is not an arbitrary RouterOS command console. |
| **RouterOS enforcement authority** | The MikroTik RouterOS configuration that actually enforces network policy. Critical static primitives remain operator owned; ZEN validates them and may hold writes when proof is missing. |
| **desired policy** | Policy intent computed by ZEN from configuration, schedules, assignments, and approved service contracts. It is not proof that a RouterOS action happened. |
| **enforced / live evidence** | Current supported evidence that RouterOS reflects an applicable policy or contract. It is distinct from desired state and from retained historical activity. |
| **reconciliation** | The bounded process that evaluates desired policy, checks authority/evidence, and applies or verifies permitted app-owned changes. Automatic reconciliation has configurable observation/planning behavior but must preserve write safeguards. |
| **RouterOS mutation lane** | The process-wide re-entrant serialized lane for app-owned RouterOS writes. Read-only observation may be parallel-capable; it does not gain mutation authority. |
| **static operator-owned authority** | Critical RouterOS rules, queues, scripts, ordering, and hardening that ZEN validates but does not create, guess-repair, or silently broaden. |
| **app-owned dynamic authority** | Bounded RouterOS state in documented `MC_*`/`MC-*` namespaces that ZEN may manage through its guarded write paths. |
| **service contract** | The documented RouterOS classifier/enforcement conditions for a concrete supported service. A custom service needs explicit approval before it can become enforceable. |
| **reporting-only** | A classifier, service, or evidence path that can inform reporting but lacks an approved RouterOS enforcement contract. It must not be presented as enforced. |
| **aggregate policy group** | A logical group that expands to concrete services. It never creates an aggregate RouterOS rule or its own RouterOS authority. |
| **retained activity** | Network-flow or DNS evidence stored for reporting and analysis. Its presence does not prove a policy was enforced; its absence does not prove there was no activity. |
| **commissioning** | The first-run process that establishes and checks the deployment, configuration, RouterOS boundary, and required readiness evidence. A fresh installation is expected to fail closed when required authority is unavailable. |
| **support bundle** | A sanitized diagnostics archive for support. It contains bounded diagnostic evidence and deliberately excludes credentials, raw household activity, raw logs, and sensitive identity material. |
| **`UNKNOWN`** | Evidence cannot be classified reliably. It is not zero, healthy, or PASS. |
| **`UNAVAILABLE`** | Required evidence could not be obtained. It is not a healthy state and does not by itself describe an unrelated evidence plane. |
| **`PENDING`** | A check or action has not reached its terminal result. It is not PASS. |
| **readiness** | The application’s composite dependency/runtime contract, exposed separately from process liveness and from retained telemetry completeness. |

## RALPH-Lite terms

| Term | Meaning |
| --- | --- |
| **RALPH-Lite (RALPH)** | ZEN Control’s supervised autonomous engineering loop. A model can propose/implement bounded work; the controller owns approval state, qualification, recovery, and publication authority. |
| **approved plan** | The immutable, human-approved sequence of bounded implementation steps identified by its exact plan hash. Approval grants authority only for that plan. |
| **plan step** | One approved, scoped unit of work. A single implementation loop executes exactly one plan step; out-of-scope findings are recorded for later consideration. |
| **plan hash** | The SHA-256 identifier of the exact approved plan. It prevents a changed plan from being treated as already approved. |
| **controller** | The RALPH-Lite program that enforces policy, loop accounting, qualification, repair limits, stop conditions, Git recovery, and controlled publication. It is authoritative over model claims. |
| **qualification** | Controller-owned checks that determine whether a step has the required evidence to pass. A successful model response never substitutes for these gates. |
| **recovery checkpoint** | The Git-backed state captured before the first model turn of an approved plan, used to classify changes and support recovery. |
| **test-change policy** | The approval-time rule governing whether existing tests may be changed. `none` permits no test edits; `add-only` permits only new tests; `modify` permits approved changes to existing tests. |
| **human gate / `BLOCKED_HUMAN`** | A stop condition requiring named human evidence, approval, or judgement. It cannot be converted to pass by the model. |
| **`BLOCKED_ENVIRONMENT`** | A stop condition caused by the execution environment rather than an approved implementation decision; the environment must be repaired before resuming. |
| **steer** | Auditable bounded human direction for an active approved objective. It is not a general policy bypass or expanded authorization. |
| **final qualification** | The controller’s complete post-plan gate sequence before a plan becomes ready for controlled commit/push handling. |
| **`READY_TO_COMMIT`** | A qualified state in which the controller may perform its controlled finalize/commit flow; it does not give the model arbitrary Git publication authority. |
