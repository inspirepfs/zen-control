## Scope declaration

- Issue / triage reference:
- One engineering objective and non-goals:
- Affected surfaces: RouterOS authority, authentication/security, PWA/browser, diagnostics/incidents/performance, release readiness, public audit, RALPH, CI, or none:

## Evidence and safety

- Authority/security coordination required? If yes, identify the reviewer or explain why it is not applicable:
- Failure and rollback behaviour:
- Tests and focused checks run:
- Runtime/container smoke performed when relevant:
- Documentation and deployment-configuration changes:
- RouterOS mutation surface added or widened? If yes, explain the fresh proof, reread, and post-write verification:

## Draft-PR workflow

Open this as a Draft PR early, while the implementation is still short-lived and
bounded. Keep it draft until scope, evidence and required authority/security
coordination are ready for CI and review. Do not include secrets, household data,
RouterOS exports, databases, or unsanitized support material.
