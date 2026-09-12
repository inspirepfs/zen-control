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
