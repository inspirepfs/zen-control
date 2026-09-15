# ZEN Control RouterOS setup bundle

This directory consolidates the RouterOS contracts used by the current ZEN Control release. It is intentionally split into **operator-reviewed templates** and **idempotent built-in service/hardening scripts** rather than one blind import.

ZEN does not own an arbitrary RouterOS configuration. Static critical firewall authority remains manually/operator owned; the application validates those primitives and fails closed when it cannot prove them. Dynamic `MC_*` state is created only through bounded application paths.

## Before you change the router

- Export/backup the current RouterOS configuration using your normal recovery procedure.
- Record current RouterOS version and upgrade to a vendor security-fixed release if required.
- Run `../inspect.rsc` and save the output.
- Review existing firewall ordering, interface lists, FastTrack and Kid Control.
- Confirm the ZEN host has a stable address and that you can recover local router access if a firewall edit is wrong.

Do not run deployment-specific templates remotely through an untested path where one incorrect rule could lock you out.

## Supported baseline

- RouterOS 7 on a vendor security-fixed release. For the September 2026 advisory use stable `7.24.2+`, long-term `7.23.4+`, or later fixed release.
- Follow <https://mikrotik.com/supportsec/september-2026-vulnerability/> for the current vendor guidance; do not expose SSH or other management services to untrusted networks.
- LAN ZEN host with stable/reserved IPv4 identity.
- RouterOS interface list named `WAN`, or an operator-reviewed equivalent reflected in the core template.
- RouterOS API reachability from the ZEN host only.
- Existing firewall policy reviewed before any mutating template is enabled.

## Bundle map

| File | Purpose | Mutating? |
| --- | --- | --- |
| `10-core-authority.template.rsc` | core block/jump/QUIC/DoT/DoQ/return authority | yes, guarded |
| `20-global-mode.template.rsc` | NORMAL/SLOW/BLOCKED global scripts + slow queue | yes, guarded |
| `30-built-in-services.rsc` | built-in service classifier/drop contracts | yes, idempotent named contract |
| `40-known-doh-hardening.rsc` | optional narrow known-DoH SNI hardening | yes |
| `50-fasttrack.template.rsc` | reviewed FastTrack exclusion/disable pattern | yes, guarded |
| `60-api-user.template.rsc` | dedicated API user/service restriction pattern | yes, guarded |
| `70-ipfix.template.rsc` | Traffic Flow/IPFIX export to ZEN | yes, guarded |
| `80-local-dns.template.rsc` | optional RouterOS local DNS mapping | yes, guarded |
| `90-dhcp-reservation.template.rsc` | stable managed-device identity pattern | yes, guarded |
| `99-verify.rsc` | post-setup authority verification | **no** |

Every `.template.rsc` file contains a fail-closed confirmation guard. A literal unedited template must abort instead of mutating the router.

## Safe installation order

1. Run `../inspect.rsc` and save the output.
2. Review `10-core-authority.template.rsc`; edit its confirmation guard and deployment-specific assumptions.
3. Review `20-global-mode.template.rsc`; set the global SLOW target/rate before enabling its guard.
4. Apply `30-built-in-services.rsc` for current built-in service contracts.
5. Optionally apply `40-known-doh-hardening.rsc`; it is not complete DoH/ECH/VPN prevention.
6. Review `50-fasttrack.template.rsc`. Either disable FastTrack or exclude `Restricted_Devices` in both directions.
7. Review `60-api-user.template.rsc`; choose a unique local password and restrict API reachability to ZEN.
8. Review `70-ipfix.template.rsc` if using retained traffic analytics.
9. Review `80-local-dns.template.rsc` only if MikroTik is part of the LAN DNS path. If Pi-hole is authoritative, configure split DNS there instead.
10. Use `90-dhcp-reservation.template.rsc` as a pattern for stable device identity.
11. Run `99-verify.rsc`, then confirm **Settings → Security** and **Operational Diagnostics** before enabling automatic enforcement.

## Authority contract ZEN validates

Critical static primitives include:

- `MASTER - Block Restricted Internet`: `forward` drop from `Restricted_Devices` to `WAN`;
- `MC - Per Device Block`: `forward` drop from `MC_Mode_Blocked` to `WAN`;
- `Restricted Devices - Web Policy`: `forward` jump from `Restricted_Devices` to `restricted-web`;
- `RW01 - Block QUIC HTTP3`: `restricted-web` UDP/443 drop;
- `MC - Block Restricted DoT`: TCP/853 drop for `Restricted_Devices`;
- `MC - Block Restricted DoQ`: UDP/853 drop for `Restricted_Devices`;
- exactly one `RW99 - Return` at the end of managed `restricted-web`;
- `Restricted Slow Internet`: global SLOW simple queue;
- mode scripts `restricted-internet-on`, `restricted-internet-slow`, `restricted-internet-off`.

The active per-device block and restricted-web jump must occur before the earliest enabled `forward` established/related ACCEPT. An enabled FastTrack rule is accepted only when it excludes `Restricted_Devices` on both source and destination address-list matches.

## Built-in service contract

`30-built-in-services.rsc` mirrors `app/service_catalog.py` for YouTube/GoogleVideo, ChatGPT, OpenAI, Netflix, Prime Video, BBC iPlayer, TikTok, Discord, Roblox, Steam, Xbox and PlayStation. ZEN later manages membership of matching `MC_Block_*` source lists; it does not silently repair the static built-in rules at runtime.

TLS/SNI matching is useful evidence/enforcement for named HTTPS endpoints, but it does not identify every service path or defeat VPN/ECH by itself.

## Verification and expected failure behaviour

After setup, `99-verify.rsc` should be followed by ZEN Settings → Security. If ZEN still holds enforcement, treat that as useful evidence. Do not add broad duplicate rules until the posture becomes green. Compare names, chains, ordering, address-list direction, queue/script identity and enabled state with the documented contract.

## Repair and rollback

The setup bundle is not an automated rollback engine. Preserve your pre-change RouterOS backup/export. If a template causes an unexpected result, restore or manually repair the exact affected static primitive, rerun `99-verify.rsc`, then re-check ZEN Security.

Application rollback and RouterOS rollback are separate decisions: an application/UI failure is not a reason to undo a known-good firewall contract.

## Kid Control

The setup bundle does **not** delete Kid Control. Existing legacy Kid Control may be retained as a rollback safety net. ZEN's migration workflow owns any deliberate authority transfer and never treats this setup bundle as permission to erase legacy schedules/device rows.
