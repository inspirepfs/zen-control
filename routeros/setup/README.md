# ZEN Control RouterOS setup bundle

This directory consolidates the RouterOS contracts used by the current ZEN Control release. It is intentionally split into **operator-reviewed templates** and **idempotent built-in service/hardening scripts** rather than one blind import.

ZEN does not own an arbitrary RouterOS configuration. Static critical firewall authority remains manually/operator owned; the application validates those primitives and fails closed when it cannot prove them. Dynamic `MC_*` state is created only through the bounded application paths documented by the source.

## Supported baseline

- RouterOS 7 on a vendor security-fixed release. For the September 2026 MikroTrick fix, use stable `7.24.2+` or long-term `7.23.4+` (or a later vendor-supported security-fixed release).
- A LAN host running ZEN with stable/reserved IPv4 identity.
- A RouterOS interface list named `WAN`, or an operator-reviewed equivalent reflected in the core template.
- RouterOS API reachability from the ZEN host only.
- Existing firewall policy reviewed before any mutating template is enabled.

## Safe installation order

1. Run `../inspect.rsc` and save the output.
2. Review `10-core-authority.template.rsc`; edit its confirmation guard and any deployment-specific assumptions before import.
3. Review `20-global-mode.template.rsc`; set the **global SLOW target/rate** for your network before enabling its guard.
4. Apply `30-built-in-services.rsc` for the concrete service contracts currently shipped by ZEN.
5. Optionally apply `40-known-doh-hardening.rsc`. This is narrow SNI hardening, not complete DoH/ECH/VPN prevention.
6. Review `50-fasttrack.template.rsc`. Either disable FastTrack or use a rule that excludes `Restricted_Devices` in both source and destination directions.
7. Review `60-api-user.template.rsc`; choose a unique password locally and restrict API reachability to the ZEN host.
8. Review `70-ipfix.template.rsc` if using retained traffic analytics.
9. Review `80-local-dns.template.rsc` only if MikroTik is part of your LAN DNS path. If Pi-hole is authoritative, configure split DNS there instead.
10. Use `90-dhcp-reservation.template.rsc` as a pattern for stable managed-device identity.
11. Run `99-verify.rsc`, then confirm **Settings → Security** and **Operational Diagnostics** in ZEN before enabling automatic enforcement.

Every `.template.rsc` file contains a fail-closed confirmation guard. A literal unedited template must abort instead of mutating the router.

## Authority contract ZEN validates

The critical static primitives are:

- `MASTER - Block Restricted Internet`: `forward` drop from `Restricted_Devices` to `WAN`.
- `MC - Per Device Block`: `forward` drop from `MC_Mode_Blocked` to `WAN`.
- `Restricted Devices - Web Policy`: `forward` jump from `Restricted_Devices` to `restricted-web`.
- `RW01 - Block QUIC HTTP3`: `restricted-web` UDP/443 drop.
- `MC - Block Restricted DoT`: `restricted-web` TCP/853 drop for `Restricted_Devices`.
- `MC - Block Restricted DoQ`: `restricted-web` UDP/853 drop for `Restricted_Devices`.
- exactly one `RW99 - Return` at the end of the managed `restricted-web` contract.
- `Restricted Slow Internet`: the global SLOW simple queue.
- mode scripts `restricted-internet-on`, `restricted-internet-slow`, and `restricted-internet-off`.

The active per-device block and restricted-web jump must occur before the earliest enabled `forward` established/related ACCEPT. An enabled FastTrack rule is accepted only when it excludes `Restricted_Devices` on **both** source and destination address-list matches.

## Built-in service contract

`30-built-in-services.rsc` mirrors `app/service_catalog.py` for YouTube/GoogleVideo, ChatGPT, OpenAI, Netflix, Prime Video, BBC iPlayer, TikTok, Discord, Roblox, Steam, Xbox and PlayStation. The script creates/normalizes only those named static classifier/drop rules. ZEN later manages membership of the matching `MC_Block_*` source lists; it does not silently repair the static built-in rules at runtime.

TLS/SNI matching is useful evidence and enforcement for the named HTTPS endpoints, but it is not a claim to identify every protocol/path a service can use.

## Kid Control

The setup bundle does **not** delete Kid Control. Existing legacy Kid Control may be retained as a rollback safety net. ZEN's migration workflow owns any deliberate authority transfer and never treats this setup bundle as permission to erase legacy schedules/device rows.
