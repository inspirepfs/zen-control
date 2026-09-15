# RouterOS integration

ZEN Control keeps RouterOS as the enforcement authority. The application never exposes an arbitrary RouterOS command surface and does not silently repair malformed static critical firewall rules.

## Safety rule

**Inspect first, change second, verify last.** If ZEN cannot prove a critical authority contract, the correct response is to repair the known RouterOS defect—not to disable the application write gate.

## Supported baseline

- RouterOS v7 on a vendor security-fixed release; for the September 2026 advisory use stable `7.24.2+`, long-term `7.23.4+`, or later fixed release.
- Review the vendor advisory at <https://mikrotik.com/supportsec/september-2026-vulnerability/>; after upgrade, check logs for `Flagged` status and inspect unexpected users/scripts/configuration.
- Stable/reserved IPv4 identity for the ZEN host and managed devices.
- Dedicated RouterOS API account with reachability restricted to the ZEN management host/path.
- Existing firewall reviewed before importing any mutating template.

## Start read-only

Run `inspect.rsc` first for a broad inventory and `verify.rsc` for established restricted-device surfaces. Both are deliberately read-only. Save the output before changing a working router.

For a new installation or disaster-recovery rebuild, use the consolidated [setup bundle](setup/README.md). It contains fail-closed operator templates for deployment-specific primitives plus idempotent current built-in service/DoH rules.

## Ownership model

### Static operator-owned authority

ZEN validates, but does not runtime-create/guess-repair, these critical concepts:

- global `MASTER - Block Restricted Internet` authority;
- `MC - Per Device Block` authority;
- `Restricted Devices - Web Policy` jump to `restricted-web`;
- QUIC/HTTP3, DoT and DoQ restricted-device hardening;
- `RW99 - Return` ordering;
- global `Restricted Slow Internet` queue and named mode scripts;
- built-in TLS/SNI classifier/drop rules;
- FastTrack posture that cannot bypass `Restricted_Devices`.

### App-owned dynamic authority

App-owned dynamic lists/queues/schedulers use documented `MC_*`/`MC-*` namespaces and remain bounded by the application write gate. Custom service rules require explicit approval before they can become enforceable. Aggregate policy groups never receive aggregate RouterOS rules; they expand to concrete services.

## API and network paths

The current adapter uses RouterOS API on configured `MIKROTIK_PORT` (`8728` by default). Treat this as trusted management traffic and restrict it to the ZEN host. Do not expose RouterOS API to the Internet for ZEN.

For retained activity, RouterOS Traffic Flow/IPFIX can target the ZEN host on UDP/2055 where bundled GoFlow2 listens. Telemetry export is optional to enforcement: losing IPFIX does not make RouterOS policy stop.

## Built-in services

The setup bundle includes concrete contracts for YouTube/GoogleVideo, ChatGPT, OpenAI, Netflix, Prime Video, BBC iPlayer, TikTok, Discord, Roblox, Steam, Xbox and PlayStation.

These are TLS/SNI classifiers. They do **not** claim every protocol/endpoint is visible or blockable, particularly when applications use encrypted client hello, VPNs, alternate protocols or endpoints outside the catalogued host patterns.

## FastTrack

FastTrack is a common reason restrictions appear inconsistent. Either disable it or use the reviewed pattern that excludes `Restricted_Devices` in both source and destination directions. ZEN's Security posture intentionally fails/holds when it cannot prove an acceptable contract.

## When ZEN reports an authority hold

1. Stop making unrelated RouterOS changes.
2. Run `inspect.rsc` and `setup/99-verify.rsc`.
3. Identify missing/duplicate/order/FastTrack/list/queue/script issues.
4. Repair only the proven static defect.
5. Rerun verification and Settings → Security.
6. Resume enforcement only after authority is provable again.

Do not "make the dashboard green" by weakening a rule check or granting a broader API policy.

## Kid Control

Do not delete legacy Kid Control simply as part of setup. ZEN's migration/cutover flow controls any authority transfer and may deliberately retain disabled legacy configuration as rollback evidence/safety net.

## Next step

For exact templates and installation order continue with [setup/README.md](setup/README.md).
