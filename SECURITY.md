# Security Policy

ZEN Control can make bounded changes to a real MikroTik firewall and should be treated as security-sensitive infrastructure.

## Reporting a vulnerability

Please do **not** publish credentials, household data, exploit details or a live deployment address in a public issue.

Until a dedicated security-reporting channel is published, open a minimal GitHub issue asking for a private security contact **without including exploit details**, or use GitHub's private vulnerability reporting feature if it is enabled for the repository.

Include enough information to reproduce the problem safely:

- affected release/commit;
- affected authority boundary or endpoint;
- whether RouterOS writes are involved;
- whether authentication/authorization can be bypassed;
- whether household/telemetry data can be exposed;
- a minimal reproduction using synthetic data where possible.

## High-priority classes

Particularly important reports include:

- unauthenticated/under-authorized RouterOS writes;
- bypass of fresh-auth/TOTP requirements;
- write paths outside the declared RouterOS adapter boundary;
- unsafe Kid Control cutover/rollback ordering;
- leakage of secrets or household telemetry;
- service-classifier state being misrepresented as enforced authority;
- failures that silently convert `UNKNOWN`/`UNAVAILABLE` into healthy evidence.

## Secret handling

Never include `.env`, tunnel tokens, private keys, recovery codes, raw configuration exports or real household telemetry in an issue or pull request.

## Public-source secret and depersonalization audit

Before a public release run `python3 scripts/public_release_audit.py --history --deployment-markers`. The marker scan reads selected non-secret deployment identity values from the ignored local `.env` and reports only variable names plus source locations, never the values themselves. Current-tree identity leakage fails the gate; historical identity is surfaced for explicit review. High-confidence secret matches in reachable Git history fail the audit.

Use a dedicated RouterOS API account, restrict the API service to the ZEN management path/host, and never publish a router administrator credential. The public RouterOS setup bundle contains placeholders/confirmation guards rather than deployment credentials.
