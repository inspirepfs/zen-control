"""Static, evidence-led in-product help for ZEN Control.

Help content is deliberately configuration-free and contains no household data.
It is safe to expose to authenticated viewers and cheap to compose on every page.
"""

from __future__ import annotations

from copy import deepcopy

HELP_SCHEMA = "zen_help_catalog_v1"


def _items(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _topic(
    key: str,
    category: str,
    title: str,
    summary: str,
    *,
    does: tuple[str, ...] | str = (),
    watch: tuple[str, ...] | str = (),
    evidence: str = "",
    related: tuple[tuple[str, str], ...] = (),
) -> dict:
    return {
        "key": key,
        "category": category,
        "title": title,
        "summary": summary,
        "does": _items(does),
        "watch": _items(watch),
        "evidence": evidence,
        "related": [{"label": label, "href": href} for label, href in related],
    }


_TOPICS = {
    "getting_started": _topic(
        "getting_started", "Start here", "How ZEN Control fits together",
        "ZEN separates policy intent, RouterOS enforcement, telemetry evidence and operational history so each surface can say what it actually knows.",
        does=(
            "Use Devices for a device-centred view, Policies for desired controls, Schedules for time-based changes and Activity for retained network evidence.",
            "Use Why this state? when you need the decision chain, and Diagnostics when you need component health rather than policy detail.",
            "Shared-display mode lets children view the dashboard while server-side write protection remains locked until a parent unlocks it.",
        ),
        watch=(
            "RouterOS remains enforcement authority; ZEN does not silently repair critical manually owned firewall authority.",
            "Activity is network evidence, not browser history, screen time or proof of user intent.",
        ),
        related=(("Dashboard", "/?view=dashboard&section=overview#dashboard/overview"), ("Managed devices", "/?view=devices&section=managed#devices/managed"), ("Glossary", "/help?topic=glossary")),
    ),
    "dashboard_overview": _topic(
        "dashboard_overview", "Overview", "Dashboard overview",
        "The Dashboard is a fast operational summary: favourites, connected-system health and current household mode without replacing the owning feature pages.",
        does=("Shows current high-level policy, authority, service, telemetry and operations health.", "Links each health row back to the feature that owns the underlying state."),
        watch=("A healthy Dashboard row means the evidence checked by that row is healthy; it is not a guarantee that every downstream internet service is reachable."),
        related=(("Devices", "/?view=devices&section=managed#devices/managed"), ("Diagnostics", "/diagnostics")),
    ),
    "dashboard_controls": _topic(
        "dashboard_controls", "Controls", "Household internet controls",
        "Household mode and restricted-web controls are broad controls. Device-, schedule-, quota- and service-specific policy can still narrow the effective result.",
        does=("NORMAL, SLOW and BLOCKED change the household-wide control state.", "Restricted-web policy enables or disables the validated web-service blocking path."),
        watch=("Kid Control remains installed as a safety net and is not managed away by these controls.", "Temporary device access does not override the global household MASTER state."),
        related=(("Why this policy?", "/help?topic=policy_explain"), ("Security authority", "/?view=settings&section=security#settings/security")),
    ),
    "devices_managed": _topic(
        "devices_managed", "Devices", "Managed devices",
        "Managed devices combines local ZEN policy assignment with fresh RouterOS enforcement evidence and reconciliation state.",
        does=("Shows desired versus live mode, service and bandwidth state.", "Provides guarded actions for mode, temporary access, reward time and reconciliation."),
        watch=("A drift badge means desired policy and fresh RouterOS state do not match; inspect the plan before applying changes.", "Removing a managed device retires live IP-keyed policy, device schedules/exceptions and reward state so a later device reusing that IP cannot inherit them. Historical telemetry remains retained by IP and does not prove continuous physical-device identity across reuse."),
        related=(("Device 360", "/help?topic=device_360"), ("Policy explainability", "/help?topic=policy_explain")),
    ),
    "devices_discovery": _topic(
        "devices_discovery", "Devices", "Device discovery",
        "Discovery is a read-only inventory used to find RouterOS-visible devices before explicitly adding them to ZEN management.",
        does=("Shows discovered addresses/names and lets an authorised parent add a selected device to the local managed-device model."),
        watch=("Discovery does not automatically make every LAN device managed or restricted."),
        related=(("Managed devices", "/?view=devices&section=managed#devices/managed"),),
    ),
    "devices_bulk": _topic(
        "devices_bulk", "Devices", "Bulk device actions",
        "Bulk actions apply an explicit parent-selected operation to multiple managed devices or copy existing device policy between devices.",
        does=("Reduces repetitive device administration while retaining normal validation and audit paths."),
        watch=("Review the selected devices before applying; bulk scope is intentionally explicit and is not inferred from names or profiles."),
        related=(("Managed devices", "/?view=devices&section=managed#devices/managed"),),
    ),
    "policies_profiles": _topic(
        "policies_profiles", "Policies", "Profiles",
        "Profiles are reusable desired-policy bundles for mode, bandwidth, blocked concrete services or aggregate groups, and quota configuration.",
        does=("Lets one policy definition drive multiple assigned devices.", "Preview impact before saving changes to a profile used by several devices."),
        watch=("A profile is desired configuration, not proof of historical RouterOS execution."),
        related=(("Simulation", "/policy/simulate"), ("Policy quality", "/policy/quality")),
    ),
    "policies_assignments": _topic(
        "policies_assignments", "Policies", "Device policy assignments",
        "Assignments connect managed devices to profiles and optional per-device mode overrides.",
        does=("Lets a device inherit a profile while retaining explicit device-specific override semantics."),
        watch=("A device override can intentionally shadow a broader profile decision; Policy Quality distinguishes that from a true conflict."),
        related=(("Policy quality", "/policy/quality"), ("Why this policy?", "/help?topic=policy_explain")),
    ),
    "policies_services": _topic(
        "policies_services", "Policies", "Services and custom service contracts",
        "Service definitions provide classification metadata and concrete enforcement targets. Custom services remain reporting-only until an operator explicitly provisions and validates their RouterOS contract.",
        does=("Maintains DNS/TLS classifier metadata.", "Previews and explicitly provisions custom RouterOS service contracts when approved."),
        watch=("Creating a custom service never silently creates firewall authority.", "Reporting-only services can classify activity but cannot be claimed as enforced.", "Telemetry retains the last known-good live classifier catalogue if a replacement is temporarily missing or malformed; a valid empty catalogue deliberately classifies nothing.", "Custom service metadata cannot be deleted while live policy/configuration objects still reference its stable key."),
        related=(("Classification", "/activity/classification"), ("Aggregate groups", "/help?topic=aggregate_groups")),
    ),
    "policies_bandwidth": _topic(
        "policies_bandwidth", "Policies", "Bandwidth presets",
        "Bandwidth presets are reusable upload/download limits referenced by profiles and device policy.",
        does=("Keeps queue-rate choices consistent across policy definitions."),
        watch=("Bandwidth may be irrelevant while a stronger BLOCKED device mode is active; Policy Quality can flag shadowed configuration."),
        related=(("Policy quality", "/policy/quality"),),
    ),
    "policies_tools": _topic(
        "policies_tools", "Policies", "Policy tools and reusable sets",
        "Tools & sets contains simulation, quality analysis, aggregate policy groups and reusable service collections.",
        does=("Provides safe analysis before policy changes and reusable authoring constructs."),
        watch=("Reusable service collections are authoring macros; aggregate policy groups are live logical policy targets. Neither creates aggregate RouterOS firewall authority."),
        related=(("Simulation", "/policy/simulate"), ("Policy quality", "/policy/quality"), ("Aggregate groups", "/help?topic=aggregate_groups")),
    ),
    "aggregate_groups": _topic(
        "aggregate_groups", "Policies", "Aggregate policy groups",
        "Aggregate groups let policy target a named logical set such as Gaming or Streaming while enforcement expands to concrete member services.",
        does=("Supports create, rename, description/member updates and safe custom deletion.", "Keeps a stable machine key when the display name changes so profile, quota, schedule and history references stay valid."),
        watch=("Groups may contain concrete services only; nested groups are rejected.", "ZEN never creates MC_Block_<group> or a group-level TLS learner. RouterOS enforcement stays concrete-service based."),
        related=(("Policy tools", "/?view=policies&section=tools#policies/tools"), ("Policy quality", "/policy/quality")),
    ),
    "schedules_planner": _topic(
        "schedules_planner", "Schedules", "Targeted schedule planner",
        "Schedules apply time-based mode or service decisions to all devices, a profile, a device or a concrete/aggregate service target according to deterministic precedence.",
        does=("Shows the live policy clock and lets authorised parents create, edit, pause, enable and delete recurring schedule windows without changing schedule identity."),
        watch=("More-specific schedules can intentionally shadow broader schedules; equal-precedence contradictions are conflicts. On DST fallback, an ambiguous wall time uses the first physical occurrence; on spring-forward, a nonexistent time moves to the first valid local instant after the gap."),
        related=(("Simulation", "/policy/simulate"), ("Policy quality", "/policy/quality")),
    ),
    "schedules_exceptions": _topic(
        "schedules_exceptions", "Schedules", "Date exceptions",
        "Date exceptions alter normal recurring policy for a specific date or date range, such as holidays or special events.",
        does=("Lets an explicit dated exception supersede normal recurring policy where the resolver defines that precedence."),
        watch=("Conflicting overlapping exceptions at the same precedence are reported by Policy Quality rather than guessed."),
        related=(("Policy quality", "/policy/quality"),),
    ),
    "schedules_templates": _topic(
        "schedules_templates", "Schedules", "Schedule templates",
        "Templates are reusable authoring definitions that reduce repetitive schedule entry.",
        does=("Creates reusable schedule patterns that can be cloned/applied into live policy."),
        watch=("A template is not itself live enforcement until it is used by a schedule/exception.", "Contradictory modes for the same weekday and time are rejected before save; Policy Quality also detects ambiguous legacy/stored template data."),
        related=(("Planner", "/?view=schedules&section=planner#schedules/planner"),),
    ),
    "schedules_router": _topic(
        "schedules_router", "Schedules", "Router schedules",
        "This view exposes relevant RouterOS schedule evidence so ZEN can distinguish local policy scheduling from RouterOS-owned schedule state.",
        evidence="RouterOS schedule visibility is operational evidence; ZEN does not silently adopt or rewrite unrelated/manual schedules.",
        related=(("Planner", "/?view=schedules&section=planner#schedules/planner"),),
    ),
    "activity_overview": _topic(
        "activity_overview", "Activity", "Activity overview",
        "Activity combines IPFIX traffic, Pi-hole DNS and service-catalogue classification into parent-facing network evidence.",
        does=("Shows managed-device traffic, service attribution, DNS evidence and classification coverage."),
        watch=("Activity is not browser history, foreground-app time, proof of user identity or proof of user intent."),
        evidence="ECH, VPNs, generic HTTPS, custom ports and missing DNS/TLS evidence can reduce classification coverage; UNKNOWN is preferable to invented attribution.",
        related=(("Classification", "/activity/classification"), ("Historical analytics", "/activity/analytics?period=7d")),
    ),
    "activity_devices": _topic(
        "activity_devices", "Activity", "Device activity",
        "Device Activity drills retained network evidence down to one managed address while keeping links back to its policy and Device 360 state.",
        evidence="The device name/IP identifies the managed network endpoint, not necessarily the person physically using it at every moment.",
        related=(("Device 360", "/help?topic=device_360"), ("Policy correlation", "/help?topic=policy_history")),
    ),
    "activity_services": _topic(
        "activity_services", "Activity", "Service activity",
        "Service Activity shows network traffic attributed to concrete services using the current catalogue and retained classifier evidence.",
        watch=("Aggregate groups are presentation/policy expansion only; attribution remains on concrete services."),
        evidence="Attributed bytes indicate network traffic matched to service evidence, not foreground screen time.",
        related=(("Services", "/?view=policies&section=services#policies/services"), ("Classification", "/activity/classification")),
    ),
    "activity_classification": _topic(
        "activity_classification", "Activity", "Classification Intelligence",
        "Classification Intelligence measures coverage and triages unknown DNS evidence into current-signature matches, name-only hints and unmatched candidates.",
        does=("Highlights classifier gaps and can prefill a custom-service DNS suffix for manual review."),
        watch=("Name-only hints are clues, not classification, and no confidence/risk score is manufactured.", "Zero observed bytes or DNS queries are NO EVIDENCE, not a measured 0% classification result; partial source failures remain explicitly UNAVAILABLE.", "Activity, dashboard and Classification Intelligence preserve the same NO EVIDENCE / UNAVAILABLE / INCONSISTENT states instead of coercing missing percentages to zero."),
        related=(("Classification workbench", "/activity/classification"), ("Services", "/?view=policies&section=services#policies/services")),
    ),
    "activity_dns": _topic(
        "activity_dns", "Activity", "DNS evidence",
        "DNS views summarize Pi-hole queries and explicit blocked-query evidence associated with managed devices.",
        evidence="A DNS query means a device requested name resolution; it does not prove a page was viewed or an application was foregrounded.",
        related=(("Classification", "/activity/classification"),),
    ),
    "activity_summaries": _topic(
        "activity_summaries", "Activity", "Parent summaries",
        "Parent summaries compose existing traffic, DNS, service, new-domain and current quota evidence into a compact daily view.",
        watch=("Historical summaries do not backdate today's quota configuration into yesterday."),
        evidence="New/unusual domains are evidence-led labels based on retained lookback, not behavioural risk scores.",
        related=(("Summary Center", "/activity/summary?period=today"),),
    ),
    "activity_history": _topic(
        "activity_history", "Activity", "Historical analytics and policy correlation",
        "History compares retained activity over time and, from v0.33 onward, can correlate it with durable desired-policy checkpoints.",
        watch=("Policy checkpoints prove what ZEN resolved, not continuous historical RouterOS execution.", "Periods before the first retained policy checkpoint remain UNKNOWN rather than being reconstructed from current configuration."),
        related=(("Historical analytics", "/activity/analytics?period=7d"), ("Policy correlation", "/activity/policy-history?period=7d")),
    ),
    "activity_reporting": _topic(
        "activity_reporting", "Activity", "Reporting & analytics",
        "Reporting composes retained traffic, DNS, classification, policy-checkpoint and operational lifecycle evidence into comparable household windows.",
        does=("Compares current and preceding equivalent periods.", "Ranks device/service movers and exposes notification/incident trends.", "Exports a flat CSV for offline analysis."),
        watch=("Policy checkpoints prove what ZEN resolved, not continuous historical RouterOS execution.", "Missing or unavailable telemetry remains explicit and is never converted into a healthy zero."),
        evidence="Reporting is read-only and carries no RouterOS mutation authority.",
        related=(("7-day report", "/reporting?period=7d"), ("Historical analytics", "/activity/analytics?period=7d")),
    ),
    "notifications": _topic(
        "notifications", "Operations", "Notification centre",
        "Notifications are ZEN's durable attention layer over existing incident and worker evidence. They can be read, acknowledged, dismissed or muted by preference without changing the underlying source state.",
        does=("Shows unread, unresolved and historical attention events with deduplication and source links.", "Supports minimum severity, quiet hours, repeat cooldowns, per-event enable/disable, source-family muting and exact device/subject filters.", "Correlates related notifications, records a durable lifecycle timeline, explains why attention is being shown, escalates unresolved warning attention under explicit local rules, and previews digest candidates/noisy sources.", "Fans eligible attention out through browser push, environment-configured SMTP email and HMAC-signed webhooks with durable retry/delivery history."),
        watch=("A notification preference or intelligence rule changes attention only; external delivery adapters transmit that attention only. Notification intelligence never authorises a RouterOS write, and neither path suppresses the owning incident, worker or policy evidence.", "Notification intelligence retains source severity separately from attention severity; an automatic escalation is not evidence that the source itself became critical.", "Quiet hours and filters retain the durable notification row so evidence can still be inspected; critical attention can be configured to bypass quiet hours and always bypasses repeat cooldown.", "SMTP credentials/recipients and webhook signing secrets are environment-only; HTTP webhooks require an explicit test-only opt-in."),
        related=(("Incident centre", "/?view=incidents&section=active#incidents/active"), ("Notification preferences", "/?view=notifications&section=preferences#notifications/preferences"), ("Notification intelligence", "/?view=notifications&section=intelligence#notifications/intelligence"), ("External delivery", "/?view=notifications&section=delivery#notifications/delivery"), ("Operations", "/?view=settings&section=operations#settings/operations")),
    ),
    "incidents": _topic(
        "incidents", "Operations", "Incident centre",
        "Incidents turn persistent operational/security signals into an acknowledge/resolve lifecycle while keeping resolved items suppressed until the underlying signal genuinely clears.",
        does=("Separates current active problems from historical/resolved operational evidence."),
        watch=("Acknowledging or resolving an incident does not repair the underlying RouterOS or service condition."),
        related=(("Diagnostics", "/diagnostics"), ("Audit", "/?view=audit&section=recent#audit/recent")),
    ),
    "audit": _topic(
        "audit", "Operations", "Audit trail",
        "Audit is the durable record of significant ZEN configuration, authentication, reconciliation, provisioning and operational actions.",
        does=("Provides searchable recent evidence and contextual links back to the owning feature."),
        watch=("Audit records actions and outcomes; it is not packet telemetry or a complete browser/activity log."),
        related=(("Operations", "/?view=settings&section=operations#settings/operations"),),
    ),
    "settings_parents": _topic(
        "settings_parents", "Settings", "Parent access and shared display",
        "Parent Access controls authentication, independent TOTP authenticators, recovery codes, shared-display mode and the short privileged parent-unlock window.",
        does=("Keeps the Kitchen Display readable while server-side writes remain locked until a parent authenticates.", "During the final minute of an active parent window, More time accepts a fresh OTP or recovery code and adds one configured unlock period without dropping the current page context."),
        watch=("Authenticator codes are single-use replay-protected values. Re-entering the same 30-second code is rejected; use the next authenticator code for a later unlock or extension.", "More time never extends a locked display, cannot be stacked early, and still requires fresh parent proof.", "The visual lock badge is not the security boundary; write routes enforce the lock server-side.", "The short parent unlock is bound to the running ZEN process. An application restart returns a shared display to locked/read-only even if the signed browser session itself survives."),
        related=(("PWA/tablet", "/help?topic=pwa"),),
    ),
    "settings_policy": _topic(
        "settings_policy", "Settings", "Policy defaults, quota and reward settings",
        "Policy defaults configure broad local behaviour used by the resolver, including quota/reward feature settings.",
        watch=(
            "Quota enforcement depends on retained telemetry availability and follows the configured fail-open behaviour when evidence is unavailable.",
            "Quota state is recomputed from current retained usage; late-arriving telemetry can trigger enforcement on the next resolution and a new local calendar day does not inherit the previous day's exhausted state.",
            "Reward redemption reserves minutes before RouterOS is touched. If an interruption makes the grant result uncertain, ZEN keeps those minutes reserved until RouterOS evidence proves whether to complete or refund them; it never guesses and creates free access.",
            "Extending temporary access preserves the existing RouterOS expiry fail-safe until the replacement expiry is safely committed.",
        ),
        related=(("Policy explainability", "/help?topic=policy_explain"),),
    ),
    "settings_automation": _topic(
        "settings_automation", "Settings", "Automation and reconciliation",
        "Automation controls bounded background workers such as reconciliation, incident monitoring and the already-built summary-delivery infrastructure.",
        does=("Automatic reconciliation applies the same validated desired-policy plan used by manual reconciliation."),
        watch=("Notification Centre is now implemented as a read-side attention layer; summary delivery remains a separate scheduled-reporting capability and does not imply push delivery."),
        related=(("Diagnostics", "/diagnostics"),),
    ),
    "settings_security": _topic(
        "settings_security", "Settings", "Security and RouterOS authority",
        "Security validates the manually owned critical firewall structure and the conditions ZEN requires before it is allowed to write enforcement changes.",
        does=("Checks MASTER/global authority, per-device structure, QUIC/DoT/DoQ/DoH handling, FastTrack safety and bypass evidence."),
        watch=("ZEN fails loudly on malformed critical authority and does not silently create/repair those manually owned rules."),
        related=(("Diagnostics", "/diagnostics"), ("Incidents", "/?view=incidents&section=active#incidents/active")),
    ),
    "settings_operations": _topic(
        "settings_operations", "Settings", "Operations, backup and recovery",
        "Operations contains readiness/integrity evidence, configuration snapshots, import/export, diagnostics, performance tooling and the current formal release-readiness gate.",
        does=("Supports semantic configuration backup/restore, sanitized diagnostic export and evidence-led release acceptance."),
        watch=("Operational history such as audit, incidents and policy-history checkpoints is not rewritten as configuration identity during restore.", "A PENDING release check means evidence or commissioning is still outstanding; it is never treated as PASS."),
        related=(("Release readiness", "/release-readiness"), ("Diagnostics", "/diagnostics"), ("Performance", "/performance"), ("Import preview", "/help?topic=import_preview")),
    ),
    "release_readiness": _topic(
        "release_readiness", "Operations", "Final release readiness",
        "Release Readiness composes current runtime, diagnostics, performance, recovery and shared-display evidence without creating a second enforcement authority.",
        does=("Runs a non-destructive export/import/reopen smoke against a temporary policy database.", "Names bounded sanitized diagnostic warning/blocker identities directly in release evidence so a PENDING/FAIL dependency gate explains what requires review.", "Requires affirmative live performance and controlled-restart evidence before reporting PASS."),
        watch=("PENDING is not PASS and missing evidence is never converted to healthy state.", "HTTPS/PWA secure transport remains post-core commissioning; local TLS, browser PWA evidence and optional public Access proof remain separate from RouterOS authority and Notification Centre attention."),
        related=(("Diagnostics", "/diagnostics"), ("Performance", "/performance"), ("Operations", "/?view=settings&section=operations#settings/operations")),
    ),
    "device_360": _topic(
        "device_360", "Drill-downs", "Device 360",
        "Device 360 is the read-only operational landing page for one managed device, combining current policy, live RouterOS evidence, access modifiers, activity, incidents and audit links.",
        watch=("It intentionally contains no write forms; changes route back to the existing guarded control surfaces."),
        evidence="Telemetry panels can degrade independently without turning missing activity evidence into zero usage.",
        related=(("Why this policy?", "/help?topic=policy_explain"), ("Device activity", "/help?topic=activity_devices")),
    ),
    "policy_explain": _topic(
        "policy_explain", "Drill-downs", "Why this policy?",
        "Policy Explainability traces ordered inputs from profile/defaults through device overrides, schedules, exceptions, quotas, temporary access, live device mode and global household authority.",
        does=("Shows which step actively contributes to the effective result and why a service is blocked/allowed."),
        watch=("If RouterOS cannot be read, live/effective evidence becomes UNKNOWN rather than assuming NORMAL."),
        related=(("Simulation", "/policy/simulate"), ("Policy quality", "/policy/quality")),
    ),
    "policy_simulation": _topic(
        "policy_simulation", "Drill-downs", "Policy simulation",
        "Simulation answers what the shared resolver would desire for hypothetical profile, device, schedule and service changes without saving them.",
        does=("Shows baseline versus proposed mode, bandwidth, service/group and decision-source impact."),
        watch=("Future quota consumption is not predicted, and current RouterOS comparison is explicitly current-state evidence rather than a future forecast."),
        related=(("Profiles", "/?view=policies&section=profiles#policies/profiles"), ("Policy quality", "/policy/quality")),
    ),
    "policy_quality": _topic(
        "policy_quality", "Drill-downs", "Policy quality",
        "Policy Quality statically detects conflicting, shadowed, redundant, unused or dependency-broken policy without touching RouterOS.",
        does=("Distinguishes deterministic precedence/shadowing from equal-precedence ambiguity.", "Surfaces missing policy/service references and ambiguous schedule-template data without inventing a live shadow for orphaned targets."),
        watch=("Warnings and shadows are not necessarily errors; use the owner links to decide whether the configuration is intentional."),
        related=(("Simulation", "/policy/simulate"),),
    ),
    "policy_history": _topic(
        "policy_history", "Drill-downs", "Historical policy correlation",
        "Policy Correlation aligns retained traffic/DNS evidence with durable desired-policy checkpoints captured from the real resolver. From v0.49, new checkpoints are also bound to the current management identity so IP reuse cannot silently become physical-device continuity.",
        does=("Separates identity coverage, desired-policy coverage and retained DNS/IPFIX evidence instead of treating one as proof of another.",),
        watch=("Legacy pre-v0.49 rows and time before the current management identity remain explicitly UNKNOWN / identity-unproven / IP-scoped.", "A desired-policy checkpoint is not proof of historical RouterOS enforcement or execution; current collector health also does not rewrite retained historical evidence."),
        related=(("Historical analytics", "/activity/analytics?period=7d"),),
    ),
    "classification": _topic(
        "classification", "Drill-downs", "Classification workbench",
        "The workbench tracks classification coverage and prioritizes unknown DNS candidates using current catalogue evidence.",
        watch=("CURRENT SIGNATURE means today's catalogue can match a historically unclassified hostname; ZEN does not rewrite the old telemetry record.", "Coverage percentages are only trusted when classified plus unclassified evidence reconciles to the observed denominator. Missing IPFIX or DNS stays unavailable rather than becoming zero."),
        related=(("Services", "/?view=policies&section=services#policies/services"),),
    ),
    "secure_transport": _topic(
        "secure_transport", "Tablet & access", "Secure transport and remote access",
        "Secure transport commissions local Caddy HTTPS first and can optionally add outbound-only Cloudflare Tunnel/Access remote access while retaining ZEN's own authentication, TOTP/shared-display lock and RouterOS authority boundaries.",
        does=("Uses Secure session cookies when remote access is enabled.", "Can enforce an explicit Host allowlist and reports whether Cloudflare Access protection has been operator-confirmed."),
        watch=("Configuration readiness is not live Internet proof; validate the public Access challenge and an authenticated ZEN journey after starting the tunnel.", "Once Secure cookies are enabled, authenticated browser sessions must use the HTTPS hostname rather than direct LAN HTTP."),
        related=(("Parent access", "/?view=settings&section=parents#settings/parents"), ("Operations", "/?view=settings&section=operations#settings/operations")),
    ),
    "diagnostics": _topic(
        "diagnostics", "Operations", "Operational diagnostics",
        "Diagnostics gives one fresh cross-component health and commissioning view across ZEN, SQLite, RouterOS authority, service contracts, PostgreSQL telemetry, traffic-ingest, Pi-hole DNS, IPFIX and background workers.",
        does=("Provides explicit PASS / WARN / BLOCKED / UNAVAILABLE commissioning state.", "Builds a public-safe ZIP support bundle with sanitized runtime evidence, environment-presence counts and aggregate audit event counts.", "Provides a copyable text support summary and an in-container CLI download path."),
        watch=("Diagnostics and support export are read-only; they do not auto-repair or acquire RouterOS authority.", "Each dependency is proved independently: ZEN does not infer healthy Pi-hole, IPFIX or classifier state from another subsystem being reachable.", "Raw Docker/application logs, household device identities, DNS/activity records, credentials, tokens, sessions and push endpoint/key material are deliberately excluded from the default bundle."),
        related=(("Performance", "/performance"), ("Operations", "/?view=settings&section=operations#settings/operations")),
    ),
    "performance": _topic(
        "performance", "Operations", "Performance evidence",
        "Performance retains bounded route/component timings and the formal acceptance budgets so responsiveness is judged from measured p50/p95/p99 rather than feel alone.",
        does=("Shows request latency, RouterOS/SQLite/PostgreSQL/template timings, slow-request breakdowns and PASS/PENDING/FAIL acceptance classes."),
        watch=("Acceptance budgets never authorize skipping RouterOS fresh reads or post-write validation; optimize a slow safety path rather than weakening it."),
        related=(("Diagnostics", "/diagnostics"),),
    ),
    "policy_summary": _topic(
        "policy_summary", "Drill-downs", "Policy summary",
        "Policy Summary provides a compact read-only desired-policy table across managed devices with direct links to Device 360, explainability, assignments and Activity.",
        evidence="This is configuration/desired-state summary, not a complete historical or live RouterOS proof for every row.",
        related=(("Managed devices", "/?view=devices&section=managed#devices/managed"),),
    ),
    "import_preview": _topic(
        "import_preview", "Operations", "Configuration import preview",
        "Import Preview compares current and incoming semantic configuration before an explicit apply operation.",
        does=("Creates a pre-import safety snapshot before applying a validated import."),
        watch=("Nothing changes during preview. Applying replaces container-side policy configuration; it does not silently recreate manually owned RouterOS authority."),
        related=(("Operations", "/?view=settings&section=operations#settings/operations"),),
    ),
    "kid_control_migration": _topic(
        "kid_control_migration", "Operations", "MikroTik Kid Control migration",
        "Migration reads legacy Kid Control, stages equivalent ZEN intent, and can transfer authority only after fresh identity, policy, RouterOS and reconciliation gates pass.",
        does=("Uses configured MAC addresses as stable migration identity and requires a static DHCP-backed IP before cutover.", "Materialises or safely reuses equivalent ZEN policy, verifies enforcement, then disables only the exact validated legacy profile.", "Retains the original Kid Control configuration and durable cutover evidence for rollback."),
        watch=("/ip/kid-control/device remains read-only; ZEN never deletes or edits legacy membership or schedules.", "Cutover and rollback require a fresh authenticator/recovery code and automatic reconciliation must be ENFORCE.", "Rollback restores legacy authority first, then reverses only migration-owned ZEN changes."),
        related=(("Automation", "/?view=settings&section=automation#settings/automation"), ("Operations", "/?view=settings&section=operations#settings/operations"), ("Migration workbench", "/migration/kid-control")),
    ),
    "pwa": _topic(
        "pwa", "Tablet & access", "Installed Android/tablet app",
        "ZEN's PWA provides an installable standalone shell for Android/shared displays while keeping policy data and mutation authority online-only.",
        does=("Caches only versioned presentation assets and a sanitized offline screen.", "Preserves server-side parent lock, CSRF and authentication.", "Android installation has been proven on at least one real device; installability is evaluated independently by each browser/device.", "The Parent access PWA card exposes device-local install/reinstall diagnostics covering secure context, manifest, service worker/control, browser install events, standalone mode, notification permission and push-subscription presence."),
        watch=("Authenticated HTML/API data is never service-worker cached and mutations are never queued for later replay.", "Android/Chromium installation requires a secure HTTPS origin (localhost is a development exception).", "READY means the PWA prerequisites are healthy; READY TO INSTALL is shown only after the browser actually emits beforeinstallprompt. PROMPT NOT OFFERED is deliberately not treated as a ZEN failure because the event is browser-controlled and may be absent when already installed, blocked by browser/device policy, running in a Custom Tab/in-app browser, failing browser-specific criteria, or when installation is browser-managed.", "Use Copy diagnostics or window.ZEN_PWA_DIAGNOSTICS() when comparing phone/tablet behaviour. The diagnostic report is device-local and excludes hostname, credentials, household data and push endpoint/key material.", "Installed-PWA push lifecycle commissioning remains separate evidence from installability."),
        related=(("Parent access", "/?view=settings&section=parents#settings/parents"), ("Diagnostics", "/diagnostics")),
    ),
    "glossary": _topic(
        "glossary", "Reference", "ZEN terminology and evidence boundaries",
        "A compact reference for the state labels ZEN uses repeatedly.",
        does=(
            "Desired: what ZEN's resolver currently wants. Live: what a fresh RouterOS read reports. Effective: the state after relevant authority/override precedence is considered.",
            "DRIFT: desired and live evidence disagree. UNKNOWN/UNAVAILABLE: evidence could not be proven; ZEN does not silently convert that to NORMAL or zero activity.",
            "REPORTING ONLY: classification metadata exists but a trusted concrete RouterOS service contract has not been approved/validated.",
            "Aggregate policy group: logical policy expansion to concrete services; never aggregate RouterOS firewall authority.",
            "Classified traffic: network bytes attributed through available service evidence; not foreground-app or screen-time measurement.",
        ),
        evidence="ZEN prefers explicit UNKNOWN/UNAVAILABLE states over claims that telemetry or RouterOS evidence cannot support.",
        related=(("Start here", "/help?topic=getting_started"),),
    ),
}


_ROOT_CONTEXT = {
    ("dashboard", "overview"): "dashboard_overview",
    ("dashboard", "controls"): "dashboard_controls",
    ("devices", "managed"): "devices_managed",
    ("devices", "discovery"): "devices_discovery",
    ("devices", "bulk"): "devices_bulk",
    ("policies", "profiles"): "policies_profiles",
    ("policies", "assignments"): "policies_assignments",
    ("policies", "services"): "policies_services",
    ("policies", "bandwidth"): "policies_bandwidth",
    ("policies", "tools"): "policies_tools",
    ("schedules", "planner"): "schedules_planner",
    ("schedules", "exceptions"): "schedules_exceptions",
    ("schedules", "templates"): "schedules_templates",
    ("schedules", "router"): "schedules_router",
    ("activity", "overview"): "activity_overview",
    ("activity", "devices"): "activity_devices",
    ("activity", "services"): "activity_services",
    ("activity", "classification"): "activity_classification",
    ("activity", "dns"): "activity_dns",
    ("activity", "summaries"): "activity_summaries",
    ("activity", "history"): "activity_history",
    ("activity", "reports"): "activity_reporting",
    ("notifications", "inbox"): "notifications",
    ("notifications", "preferences"): "notifications",
    ("notifications", "intelligence"): "notifications",
    ("notifications", "delivery"): "notifications",
    ("notifications", "history"): "notifications",
    ("incidents", "active"): "incidents",
    ("incidents", "history"): "incidents",
    ("audit", "recent"): "audit",
    ("settings", "parents"): "settings_parents",
    ("settings", "policy"): "settings_policy",
    ("settings", "automation"): "settings_automation",
    ("settings", "security"): "settings_security",
    ("settings", "operations"): "settings_operations",
}


def get_help_topic(key: str | None) -> dict:
    key = str(key or "getting_started").strip().lower()
    topic = _TOPICS.get(key) or _TOPICS["getting_started"]
    return deepcopy(topic)


def help_for_context(view: str | None, section: str | None) -> dict:
    key = _ROOT_CONTEXT.get((str(view or "dashboard").lower(), str(section or "overview").lower()), "getting_started")
    return get_help_topic(key)


def help_catalog() -> list[dict]:
    return [deepcopy(_TOPICS[key]) for key in _TOPICS]


def help_api_payload(selected: str | None = None) -> dict:
    topics = help_catalog()
    chosen = get_help_topic(selected)
    return {
        "schema": HELP_SCHEMA,
        "selected": chosen,
        "topics": [
            {"key": item["key"], "category": item["category"], "title": item["title"], "summary": item["summary"]}
            for item in topics
        ],
        "privacy": {
            "contains_household_data": False,
            "contains_credentials": False,
            "read_only": True,
        },
    }

_OWNER_DESTINATIONS = {
    "dashboard_overview": ("Dashboard", "/?view=dashboard&section=overview#dashboard/overview"),
    "dashboard_controls": ("Dashboard", "/?view=dashboard&section=controls#dashboard/controls"),
    "devices_managed": ("Devices", "/?view=devices&section=managed#devices/managed"),
    "devices_discovery": ("Devices", "/?view=devices&section=discovery#devices/discovery"),
    "devices_bulk": ("Devices", "/?view=devices&section=bulk#devices/bulk"),
    "policies_profiles": ("Policies", "/?view=policies&section=profiles#policies/profiles"),
    "policies_assignments": ("Policies", "/?view=policies&section=assignments#policies/assignments"),
    "policies_services": ("Policies", "/?view=policies&section=services#policies/services"),
    "policies_bandwidth": ("Policies", "/?view=policies&section=bandwidth#policies/bandwidth"),
    "policies_tools": ("Policy tools", "/?view=policies&section=tools#policies/tools"),
    "aggregate_groups": ("Policy tools", "/?view=policies&section=tools#policies/tools"),
    "schedules_planner": ("Schedules", "/?view=schedules&section=planner#schedules/planner"),
    "schedules_exceptions": ("Schedules", "/?view=schedules&section=exceptions#schedules/exceptions"),
    "schedules_templates": ("Schedules", "/?view=schedules&section=templates#schedules/templates"),
    "schedules_router": ("Schedules", "/?view=schedules&section=router#schedules/router"),
    "activity_overview": ("Activity", "/?view=activity&section=overview#activity/overview"),
    "activity_devices": ("Activity", "/?view=activity&section=devices#activity/devices"),
    "activity_services": ("Activity", "/?view=activity&section=services#activity/services"),
    "activity_classification": ("Activity", "/?view=activity&section=classification#activity/classification"),
    "activity_dns": ("Activity", "/?view=activity&section=dns#activity/dns"),
    "activity_summaries": ("Activity", "/?view=activity&section=summaries#activity/summaries"),
    "activity_history": ("Activity", "/?view=activity&section=history#activity/history"),
    "activity_reporting": ("Activity", "/?view=activity&section=reports#activity/reports"),
    "notifications": ("Notifications", "/?view=notifications&section=inbox#notifications/inbox"),
    "incidents": ("Incidents", "/?view=incidents&section=active#incidents/active"),
    "audit": ("Audit", "/?view=audit&section=recent#audit/recent"),
    "settings_parents": ("Parent access", "/?view=settings&section=parents#settings/parents"),
    "settings_policy": ("Policy settings", "/?view=settings&section=policy#settings/policy"),
    "settings_automation": ("Automation", "/?view=settings&section=automation#settings/automation"),
    "settings_security": ("Security", "/?view=settings&section=security#settings/security"),
    "settings_operations": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "device_360": ("Devices", "/?view=devices&section=managed#devices/managed"),
    "policy_explain": ("Devices", "/?view=devices&section=managed#devices/managed"),
    "policy_simulation": ("Policy tools", "/?view=policies&section=tools#policies/tools"),
    "policy_quality": ("Policy tools", "/?view=policies&section=tools#policies/tools"),
    "policy_history": ("Activity history", "/?view=activity&section=history#activity/history"),
    "classification": ("Activity", "/?view=activity&section=classification#activity/classification"),
    "diagnostics": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "secure_transport": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "performance": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "policy_summary": ("Dashboard", "/?view=dashboard&section=overview#dashboard/overview"),
    "import_preview": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "kid_control_migration": ("Operations", "/?view=settings&section=operations#settings/operations"),
    "pwa": ("Parent access", "/?view=settings&section=parents#settings/parents"),
}


def help_owner(key: str | None) -> tuple[str, str]:
    topic = get_help_topic(key)
    return _OWNER_DESTINATIONS.get(
        topic["key"],
        ("Dashboard", "/?view=dashboard&section=overview#dashboard/overview"),
    )
