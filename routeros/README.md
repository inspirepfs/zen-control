# RouterOS integration

ZEN Control keeps RouterOS as the enforcement authority. The application never exposes an arbitrary RouterOS command surface and does not silently repair malformed static critical firewall rules.

## Start read-only

Run `inspect.rsc` first for a broad inventory and `verify.rsc` for the established restricted-device surfaces. Both are deliberately read-only.

For a new installation or disaster-recovery rebuild, use the consolidated [setup bundle](setup/README.md). It contains fail-closed operator templates for deployment-specific primitives plus idempotent current built-in service/DoH rules.

## Static operator-owned authority

ZEN validates, but does not runtime-create/repair, these critical concepts:

- global `MASTER - Block Restricted Internet` authority;
- `MC - Per Device Block` authority;
- `Restricted Devices - Web Policy` jump to `restricted-web`;
- QUIC/HTTP3, DoT and DoQ restricted-device hardening;
- `RW99 - Return` ordering;
- global `Restricted Slow Internet` queue and named mode scripts;
- built-in TLS/SNI classifier/drop rules;
- a FastTrack posture that cannot bypass `Restricted_Devices`.

App-owned dynamic lists/queues/schedulers use the documented `MC_*`/`MC-*` namespaces and remain bounded by the application write gate.

## Built-in services

The versioned setup bundle includes the concrete working contracts for:

YouTube/GoogleVideo, ChatGPT, OpenAI, Netflix, Prime Video, BBC iPlayer, TikTok, Discord, Roblox, Steam, Xbox and PlayStation.

These are TLS/SNI classifiers, not a claim that every protocol or endpoint used by those services is observable or blockable by SNI.

## API and telemetry

Use a dedicated RouterOS API account and restrict API reachability to the ZEN host. The current adapter uses the RouterOS API service on the configured `MIKROTIK_PORT` (8728 by default), so treat that path as trusted-LAN/management traffic.

For retained network activity, RouterOS Traffic Flow/IPFIX can target the ZEN host on UDP/2055 where the bundled GoFlow2 service listens. See `setup/70-ipfix.template.rsc`.

## Kid Control

Do not delete legacy Kid Control simply as part of RouterOS setup. ZEN's migration/cutover flow controls any authority transfer and may deliberately retain disabled legacy configuration as rollback evidence/safety net.
