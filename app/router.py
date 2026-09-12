import ipaddress
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import routeros_api

from app.bandwidth import BandwidthRateError, build_max_limit, limits_equal, parse_max_limit
from app.bypass import DOH_ROUTER_RULES
from app.service_catalog import SERVICE_ENFORCEMENT, SUPPORTED_SERVICE_KEYS
from app.service_provisioning import CUSTOM_SERVICE_COMMENT_PREFIX
from app.performance import perf_span
from app.security import (
    MANAGED_LIST_PREFIXES, MANAGED_QUEUE_PREFIXES, MANAGED_TEMP_PREFIXES,
    chain_rules, encoded_ipv4_from_name, fasttrack_excludes_restricted,
    forward_authority_order, infer_global_mode, make_check, posture_score,
    queue_target_ipv4, rule_enabled,
)


class RouterError(RuntimeError):
    pass


def _ros_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"true", "yes", "1"}


class RouterOSAdapter:
    MASTER_RULE_COMMENT = "MASTER - Block Restricted Internet"
    WEB_POLICY_COMMENT = "Restricted Devices - Web Policy"
    SLOW_QUEUE_NAME = "Restricted Slow Internet"
    RESTRICTED_LIST = "Restricted_Devices"
    SCHED_PREFIX = "MC-SCHED-"
    TEMP_SCHED_NAME = "MC-TEMP-RESTORE"
    DEVICE_BLOCK_LIST = "MC_Mode_Blocked"
    DEVICE_BLOCK_RULE_COMMENT = "MC - Per Device Block"
    DEVICE_SLOW_LIST = "MC_Mode_Slow"
    DEVICE_SLOW_QUEUE_PREFIX = "MC-SLOW-"
    DEVICE_BANDWIDTH_QUEUE_PREFIX = "MC-BW-"
    DEVICE_TEMP_SCHED_PREFIX = "MC-TEMP-DEV-"
    DEVICE_TEMP_SCRIPT_PREFIX = "MC-TEMP-RESTORE-DEV-"
    DEVICE_TEMP_DURATIONS = {15, 30, 60}
    QUIC_RULE_COMMENT = "RW01 - Block QUIC HTTP3"
    DOT_RULE_COMMENT = "MC - Block Restricted DoT"
    DOQ_RULE_COMMENT = "MC - Block Restricted DoQ"
    ESTABLISHED_RULE_COMMENT = "defconf: accept established,related,untracked"

    MODE_SCRIPTS = {
        "normal": "restricted-internet-on",
        "slow": "restricted-internet-slow",
        "blocked": "restricted-internet-off",
    }

    def __init__(self) -> None:
        self.host = os.environ["MIKROTIK_HOST"]
        self.port = int(os.getenv("MIKROTIK_PORT", "8728"))
        self.username = os.environ["MIKROTIK_USER"]
        self.password = os.environ["MIKROTIK_PASSWORD"]
        self.timezone = os.getenv("ROUTER_TIMEZONE", "Europe/London")
        self.device_slow_limit = os.getenv(
            "MIKROTIK_DEVICE_SLOW_LIMIT",
            "128k/256k",
        )
        # RouterOS public methods historically opened and closed a TCP/API
        # session independently. A single dashboard request can call many of
        # those methods, multiplying login/connection latency. Keep a
        # thread-local coherent session so one request/action can reuse the
        # transport while every RouterOS resource query remains a fresh read.
        self._session_local = threading.local()

    class _SharedPoolHandle:
        """Facade used by methods that unconditionally disconnect their pool.

        Public adapter methods retain their existing ``finally: pool.disconnect()``
        behaviour. Inside a coherent session those disconnects become no-ops;
        the outer session owns the one real disconnect.
        """

        def __init__(self, pool):
            self._pool = pool

        def disconnect(self):
            return None

    def _open_connection(self):
        try:
            with perf_span("routeros.connect"):
                pool = routeros_api.RouterOsApiPool(
                    self.host,
                    username=self.username,
                    password=self.password,
                    port=self.port,
                    plaintext_login=True,
                    use_ssl=False,
                )
                return pool, pool.get_api()
        except Exception as exc:
            raise RouterError(f"Unable to connect to MikroTik: {exc}") from exc

    def _connect(self):
        shared = getattr(self._session_local, "state", None)
        if shared is not None:
            return self._SharedPoolHandle(shared[0]), shared[1]
        return self._open_connection()

    @contextmanager
    def coherent_session(self):
        """Reuse one RouterOS API transport for one synchronous request/action.

        This is a performance boundary only. It does not cache RouterOS values:
        every adapter method continues to execute its normal resource queries,
        including post-write fresh validation. Nested callers reuse the same
        session and only the outermost context disconnects it.
        """
        shared = getattr(self._session_local, "state", None)
        if shared is not None:
            self._session_local.depth = int(getattr(self._session_local, "depth", 1)) + 1
            try:
                yield
            finally:
                self._session_local.depth -= 1
            return

        pool, api = self._open_connection()
        self._session_local.state = (pool, api)
        self._session_local.depth = 1
        self._session_local.authority_proven = False
        try:
            yield
        finally:
            self._session_local.state = None
            self._session_local.depth = 0
            self._session_local.authority_proven = False
            pool.disconnect()

    @staticmethod
    def _validate_ipv4(address: str) -> str:
        try:
            parsed = ipaddress.ip_address(address.strip())
        except ValueError as exc:
            raise RouterError(f"Invalid IP address: {address}") from exc
        if parsed.version != 4:
            raise RouterError("Only IPv4 restricted devices are supported for now")
        return str(parsed)

    @staticmethod
    def _validate_description(description: str) -> str:
        value = description.strip()
        if not value:
            raise RouterError("Description is required")
        if len(value) > 80:
            raise RouterError("Description must be 80 characters or fewer")
        return value

    @staticmethod
    def _entry_id(entry: dict) -> str | None:
        return entry.get("id") or entry.get(".id")

    @staticmethod
    def _exact_comment_rules(rules: list[dict], comment: str) -> list[dict]:
        return [rule for rule in rules if rule.get("comment") == comment]

    def get_security_posture(self) -> dict:
        """Read-only validation of the RouterOS enforcement/security contract.

        This intentionally does not repair static firewall primitives. The app
        may clean its own stale dynamic resources only through the explicit
        cleanup endpoint. A critical posture failure means the application can
        no longer prove that an ENFORCE cycle would have the advertised effect.
        """
        pool, api = self._connect()
        try:
            firewall_resource = api.get_resource("/ip/firewall/filter")
            rules = firewall_resource.get()
            address_resource = api.get_resource("/ip/firewall/address-list")
            address_entries = address_resource.get()
            queue_resource = api.get_resource("/queue/simple")
            queues = queue_resource.get()
            sched_resource = api.get_resource("/system/scheduler")
            schedulers = sched_resource.get()
            script_resource = api.get_resource("/system/script")
            scripts = script_resource.get()

            checks: list[dict] = []

            def add_rule_contract(
                key, name, comment, expected, *, severity="critical", require_enabled=True
            ):
                expected_chain = str(expected.get("chain", "")).strip()
                same_comment = self._exact_comment_rules(rules, comment)
                matches = [
                    rule for rule in same_comment
                    if not expected_chain or str(rule.get("chain", "")).strip() == expected_chain
                ]
                shadow_chains = sorted({
                    str(rule.get("chain", "")).strip()
                    for rule in same_comment
                    if expected_chain and str(rule.get("chain", "")).strip() != expected_chain
                } - {""})
                if len(matches) != 1:
                    detail = (
                        f"Expected exactly one '{comment}' rule in chain={expected_chain or '<any>'}; "
                        f"found {len(matches)}."
                    )
                    if shadow_chains:
                        detail += " Same comment also exists in ignored chain(s): " + ", ".join(shadow_chains) + "."
                    checks.append(make_check(
                        key, name, ok=False, severity=severity,
                        detail=detail,
                        remediation="Restore the documented static RouterOS primitive in the required chain; the app will not create or repair it silently.",
                    ))
                    return None
                rule = matches[0]
                enabled = rule_enabled(rule)
                problems = []
                if require_enabled and not enabled:
                    problems.append("disabled")
                for field, value in expected.items():
                    if str(rule.get(field, "")) != str(value):
                        problems.append(f"{field}={rule.get(field)!r} (expected {value!r})")
                if problems:
                    detail = "; ".join(problems)
                elif require_enabled:
                    detail = "Contract valid and enabled."
                else:
                    detail = (
                        "Structural contract valid; runtime state is ENABLED."
                        if enabled else
                        "Structural contract valid; runtime state is DISABLED as expected outside global BLOCKED mode."
                    )
                checks.append(make_check(
                    key, name, ok=not problems, severity=severity,
                    detail=detail,
                    remediation="Correct the static rule in RouterOS, then rescan." if problems else "",
                ))
                return rule

            master = add_rule_contract(
                "master", "Global MASTER authority", self.MASTER_RULE_COMMENT,
                {"chain": "forward", "action": "drop", "src-address-list": self.RESTRICTED_LIST, "out-interface-list": "WAN"},
                require_enabled=False,
            )
            device_block = add_rule_contract(
                "device_block", "Per-device block authority", self.DEVICE_BLOCK_RULE_COMMENT,
                {"chain": "forward", "action": "drop", "src-address-list": self.DEVICE_BLOCK_LIST, "out-interface-list": "WAN"},
            )
            web_jump = add_rule_contract(
                "web_jump", "Restricted web policy jump", self.WEB_POLICY_COMMENT,
                {"chain": "forward", "action": "jump", "jump-target": "restricted-web", "src-address-list": self.RESTRICTED_LIST},
            )
            quic = add_rule_contract(
                "quic", "QUIC / HTTP3 suppression", self.QUIC_RULE_COMMENT,
                {"chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "443"},
            )
            dot = add_rule_contract(
                "dot", "DNS-over-TLS suppression", self.DOT_RULE_COMMENT,
                {"chain": "restricted-web", "action": "drop", "protocol": "tcp", "dst-port": "853", "src-address-list": self.RESTRICTED_LIST},
            )
            doq = add_rule_contract(
                "doq", "DNS-over-QUIC suppression", self.DOQ_RULE_COMMENT,
                {"chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "853", "src-address-list": self.RESTRICTED_LIST},
            )

            # A deliberately narrow known-DoH SNI baseline supplements the core controls. This is
            # warning-level rather than write-gate authority because SNI cannot
            # prove complete DoH coverage (ECH, unknown providers and IP-literal
            # endpoints can evade it). The app validates but never creates or
            # silently repairs these manually-owned rules.
            doh_rule_errors = []
            doh_rule_seen = []
            for contract in DOH_ROUTER_RULES:
                matches = self._exact_comment_rules(rules, contract["comment"])
                if len(matches) != 1:
                    doh_rule_errors.append(
                        f"{contract['comment']}: expected 1 rule, found {len(matches)}"
                    )
                    continue
                rule = matches[0]
                problems = []
                expected = {
                    "chain": "restricted-web",
                    "action": "drop",
                    "protocol": "tcp",
                    "dst-port": "443",
                    "src-address-list": self.RESTRICTED_LIST,
                    "tls-host": contract["tls_host"],
                }
                if not rule_enabled(rule):
                    problems.append("disabled")
                for field, value in expected.items():
                    if str(rule.get(field, "")) != str(value):
                        problems.append(
                            f"{field}={rule.get(field)!r} (expected {value!r})"
                        )
                if problems:
                    doh_rule_errors.append(
                        f"{contract['comment']}: " + "; ".join(problems)
                    )
                else:
                    doh_rule_seen.append(contract["comment"])

            checks.append(make_check(
                "known_doh_sni",
                "Known DoH TLS/SNI suppression",
                ok=not doh_rule_errors,
                severity="warning",
                warning=bool(doh_rule_errors),
                detail=(
                    f"{len(doh_rule_seen)}/{len(DOH_ROUTER_RULES)} narrow known-DoH TLS-host rules validated. "
                    "Coverage is intentionally not presented as complete."
                    if not doh_rule_errors else
                    f"{len(doh_rule_seen)}/{len(DOH_ROUTER_RULES)} rules valid; "
                    + " | ".join(doh_rule_errors[:4])
                ),
                remediation=(
                    "Install the known-resolver DoH TLS/SNI hardening rules, then rescan. "
                    "Do not broaden TLS-host patterns to generic CDN domains."
                    if doh_rule_errors else ""
                ),
            ))

            # Global mode is a runtime state machine: MASTER is intentionally
            # disabled in NORMAL/SLOW, while the global slow queue is enabled
            # only in SLOW.  Treating a disabled MASTER as a broken static
            # contract falsely security-held a perfectly valid NORMAL router.
            slow_matches = [q for q in queues if q.get("name") == self.SLOW_QUEUE_NAME]
            if master is None or len(slow_matches) != 1:
                checks.append(make_check(
                    "global_mode_state", "Global mode runtime state", ok=False,
                    detail=(
                        f"MASTER rules={1 if master is not None else 0}; "
                        f"'{self.SLOW_QUEUE_NAME}' queues={len(slow_matches)}."
                    ),
                    remediation="Restore exactly one MASTER primitive and one global slow queue before using global mode control.",
                ))
                global_mode = "unknown"
                master_enabled = bool(master and rule_enabled(master))
                slow_enabled = False
            else:
                master_enabled = rule_enabled(master)
                slow_enabled = rule_enabled(slow_matches[0])
                global_mode, global_mode_valid = infer_global_mode(master_enabled, slow_enabled)
                checks.append(make_check(
                    "global_mode_state", "Global mode runtime state", ok=global_mode_valid,
                    detail=(
                        f"{global_mode.upper()}: MASTER={'enabled' if master_enabled else 'disabled'}, "
                        f"global slow queue={'enabled' if slow_enabled else 'disabled'}."
                        if global_mode_valid else
                        "INVALID: MASTER block and global slow queue are enabled simultaneously."
                    ),
                    remediation=(
                        "Run one of the named global mode scripts to return RouterOS to NORMAL, SLOW or BLOCKED."
                        if not global_mode_valid else ""
                    ),
                ))

            # RouterOS only requires each active managed forward authority to
            # run before the broad established/related accept.  MASTER, the
            # per-device block and the restricted-web jump do not need a strict
            # relative order amongst themselves. The earlier strict
            # MASTER -> device -> web ordering caused a false critical result
            # on safe installations.
            managed_forward = [
                self.MASTER_RULE_COMMENT,
                self.DEVICE_BLOCK_RULE_COMMENT,
                self.WEB_POLICY_COMMENT,
            ]
            required_forward = [
                self.DEVICE_BLOCK_RULE_COMMENT,
                self.WEB_POLICY_COMMENT,
            ]
            if master_enabled:
                required_forward.insert(0, self.MASTER_RULE_COMMENT)
            forward_order = forward_authority_order(
                rules,
                managed_forward,
                self.ESTABLISHED_RULE_COMMENT,
                required_comments=required_forward,
            )
            positions = forward_order["positions"]
            anchor = forward_order.get("established_anchor") or {}
            anchor_index = forward_order.get("established_index")
            anchor_comment = anchor.get("comment") or "<no comment>"
            anchor_states = ",".join(anchor.get("connection_state") or []) or "?"
            pos_text = ", ".join(
                f"{comment}={positions.get(comment, '?')}"
                for comment in managed_forward
            )
            pos_text += f", established+related ACCEPT={anchor_index if anchor_index is not None else '?'}"
            collision_text = ""
            if forward_order.get("other_chain_collisions"):
                collision_text = " Legacy comment collisions outside FORWARD ignored: " + "; ".join(
                    f"{comment} -> {','.join(chains)}"
                    for comment, chains in forward_order["other_chain_collisions"].items()
                ) + "."
            candidate_text = ""
            if anchor:
                candidate_text = (
                    f" Structural anchor: comment={anchor_comment!r}, "
                    f"connection-state={anchor_states}, candidates={anchor.get('candidate_count', 1)}."
                )
            if forward_order["ok"]:
                detail = (
                    "All active managed FORWARD authorities precede the earliest active "
                    f"FORWARD ACCEPT matching established+related. Chain-local positions: {pos_text}."
                    + candidate_text + collision_text
                )
            else:
                parts = []
                if forward_order["missing_required"]:
                    parts.append("missing in FORWARD=" + ", ".join(forward_order["missing_required"]))
                if forward_order["duplicates"]:
                    parts.append(
                        "duplicates in FORWARD=" + ", ".join(
                            f"{key}x{count}" for key, count in forward_order["duplicates"].items()
                        )
                    )
                if forward_order["late"]:
                    parts.append("after FORWARD established+related ACCEPT=" + ", ".join(forward_order["late"]))
                detail = "; ".join(parts) + f". Chain-local positions: {pos_text}." + candidate_text + collision_text
            checks.append(make_check(
                "forward_order", "Forward-chain authority ordering", ok=forward_order["ok"],
                detail=detail,
                remediation=(
                    "Move every active managed FORWARD authority before the FORWARD established/related accept rule. "
                    "Rules in INPUT/OUTPUT/custom chains are deliberately ignored; the managed FORWARD rules do not require a strict order relative to one another."
                    if not forward_order["ok"] else ""
                ),
            ))

            master_index = positions.get(self.MASTER_RULE_COMMENT)
            established_index = forward_order.get("established_index")
            inactive_master_late = (
                not master_enabled
                and master_index is not None
                and established_index is not None
                and master_index >= established_index
            )
            checks.append(make_check(
                "inactive_master_placement",
                "Inactive MASTER future-BLOCKED placement",
                ok=not inactive_master_late,
                severity="warning",
                warning=inactive_master_late,
                detail=(
                    "Disabled MASTER is already positioned before established/related and is safe to enable for BLOCKED mode."
                    if not inactive_master_late else
                    "MASTER is currently disabled, so active enforcement is unaffected, but enabling BLOCKED mode would place MASTER after established/related."
                ),
                remediation=(
                    "Move MASTER - Block Restricted Internet before the general established/related accept rule before using global BLOCKED mode."
                    if inactive_master_late else ""
                ),
            ))

            # Return ordering is also chain-local. A same-comment rule in another
            # chain must not become the RW99 anchor or distort the execution order.
            restricted_rules = chain_rules(rules, "restricted-web")
            restricted_indexes = {id(rule): idx for idx, rule in enumerate(restricted_rules)}
            rw99 = self._exact_comment_rules(restricted_rules, "RW99 - Return")
            if len(rw99) == 1:
                rw99_index = restricted_indexes[id(rw99[0])]
                managed_chain_comments = {
                    self.QUIC_RULE_COMMENT, self.DOT_RULE_COMMENT, self.DOQ_RULE_COMMENT,
                    "RW99 - Return",
                }
                managed_chain_comments.update(item["comment"] for item in DOH_ROUTER_RULES)
                for service in SERVICE_ENFORCEMENT.values():
                    managed_chain_comments.update(item["comment"] for item in service.get("rules", []))
                    managed_chain_comments.update(item["comment"] for item in service.get("learners", []))
                late = [
                    rule.get("comment") for rule in restricted_rules
                    if (
                        rule.get("comment") in managed_chain_comments
                        or str(rule.get("comment") or "").startswith(CUSTOM_SERVICE_COMMENT_PREFIX)
                    )
                    and rule.get("comment") != "RW99 - Return"
                    and restricted_indexes[id(rule)] > rw99_index
                ]
                checks.append(make_check(
                    "restricted_web_order", "restricted-web return ordering", ok=not late,
                    detail=(
                        f"All managed classifiers/blocks execute before RW99 in restricted-web ({len(restricted_rules)} chain-local rules)."
                        if not late else
                        "Rules after restricted-web RW99: " + ", ".join(late)
                    ),
                    remediation="Move managed restricted-web rules before RW99 - Return inside the restricted-web chain.",
                ))
            else:
                checks.append(make_check(
                    "restricted_web_order", "restricted-web return ordering", ok=False,
                    detail=f"Expected exactly one RW99 - Return in restricted-web; found {len(rw99)}.",
                    remediation="Restore RW99 - Return after all managed restricted-web rules in the restricted-web chain.",
                ))

            fasttrack_rules = [
                rule for rule in rules
                if rule.get("chain") == "forward"
                and rule.get("action") == "fasttrack-connection"
                and rule_enabled(rule)
            ]
            unsafe_fasttrack = [
                rule for rule in fasttrack_rules
                if not fasttrack_excludes_restricted(rule, self.RESTRICTED_LIST)
            ]
            checks.append(make_check(
                "fasttrack", "Managed-device FastTrack exclusion", ok=not unsafe_fasttrack,
                detail=(
                    "No enabled FastTrack rules can match Restricted_Devices."
                    if not unsafe_fasttrack else
                    f"{len(unsafe_fasttrack)} enabled FastTrack rule(s) are not provably excluded in both directions."
                ),
                remediation=(
                    "Disable FastTrack or explicitly exclude Restricted_Devices as both source and destination. "
                    "FastTrack can bypass simple queues and managed firewall processing."
                ) if unsafe_fasttrack else "",
            ))

            service_errors = []
            for key in SERVICE_ENFORCEMENT:
                try:
                    self._validate_service_primitive(api, key)
                except RouterError as exc:
                    service_errors.append(f"{key}: {exc}")
            checks.append(make_check(
                "service_contracts", "TLS/SNI service contracts", ok=not service_errors,
                detail=(
                    f"All {len(SERVICE_ENFORCEMENT)} concrete service contracts validated."
                    if not service_errors else " | ".join(service_errors[:6])
                ),
                remediation="Repair the listed static RW rules before trusting service enforcement.",
            ))

            restricted = {
                str(entry.get("address"))
                for entry in address_entries
                if entry.get("list") == self.RESTRICTED_LIST
                and not _ros_bool(entry.get("dynamic", False))
            }
            managed_entries = [
                entry for entry in address_entries
                if str(entry.get("list") or "").startswith(MANAGED_LIST_PREFIXES)
            ]
            seen = {}
            malformed_lists = []
            stale_lists = []
            for entry in managed_entries:
                key = (str(entry.get("list")), str(entry.get("address")))
                seen[key] = seen.get(key, 0) + 1
                try:
                    addr = str(ipaddress.ip_address(str(entry.get("address"))))
                except ValueError:
                    malformed_lists.append(key)
                    continue
                if addr not in restricted:
                    stale_lists.append(key)
            duplicates = [key for key, count in seen.items() if count > 1]

            stale_queues = []
            malformed_queues = []
            queue_duplicates = {}
            for entry in queues:
                name = str(entry.get("name") or "")
                if not name.startswith(MANAGED_QUEUE_PREFIXES):
                    continue
                queue_duplicates[name] = queue_duplicates.get(name, 0) + 1
                named_ip = encoded_ipv4_from_name(name, MANAGED_QUEUE_PREFIXES)
                target_ip = queue_target_ipv4(entry.get("target", ""))
                if not named_ip or not target_ip or named_ip != target_ip:
                    malformed_queues.append(name)
                    continue
                if named_ip not in restricted:
                    stale_queues.append(name)
            duplicate_queues = [name for name, count in queue_duplicates.items() if count > 1]

            scheduler_names = [str(item.get("name") or "") for item in schedulers]
            script_names = [str(item.get("name") or "") for item in scripts]
            stale_schedulers = []
            stale_scripts = []
            malformed_temp = []
            orphan_temp = []
            for name in scheduler_names:
                if not name.startswith(self.DEVICE_TEMP_SCHED_PREFIX):
                    continue
                addr = encoded_ipv4_from_name(name, (self.DEVICE_TEMP_SCHED_PREFIX,))
                if not addr:
                    malformed_temp.append(name)
                    continue
                if addr not in restricted:
                    stale_schedulers.append(name)
                expected_script = self._device_temp_script_name(addr)
                if expected_script not in script_names:
                    orphan_temp.append(f"{name} missing {expected_script}")
            for name in script_names:
                if not name.startswith(self.DEVICE_TEMP_SCRIPT_PREFIX):
                    continue
                addr = encoded_ipv4_from_name(name, (self.DEVICE_TEMP_SCRIPT_PREFIX,))
                if not addr:
                    malformed_temp.append(name)
                    continue
                if addr not in restricted:
                    stale_scripts.append(name)

            integrity_issues = (
                len(duplicates) + len(malformed_lists) + len(malformed_queues)
                + len(duplicate_queues) + len(malformed_temp) + len(orphan_temp)
            )
            checks.append(make_check(
                "managed_integrity", "App-owned RouterOS state integrity", ok=integrity_issues == 0,
                detail=(
                    "No duplicate/malformed MC state or broken temporary fail-safe pairs."
                    if integrity_issues == 0 else
                    f"duplicates={len(duplicates)} malformed_lists={len(malformed_lists)} "
                    f"malformed_queues={len(malformed_queues)} duplicate_queues={len(duplicate_queues)} "
                    f"malformed_temp={len(malformed_temp)} orphan_temp={len(orphan_temp)}"
                ),
                remediation="Inspect malformed/duplicate MC resources manually. Automatic cleanup removes stale resources only; it does not guess how to repair malformed live authority.",
            ))

            stale_total = len(stale_lists) + len(stale_queues) + len(stale_schedulers) + len(stale_scripts)
            checks.append(make_check(
                "stale_resources", "Stale app-owned resources", ok=stale_total == 0,
                severity="warning", warning=stale_total > 0,
                detail=("No MC state exists for unmanaged devices." if stale_total == 0 else f"{stale_total} stale MC resource(s) reference devices no longer in Restricted_Devices."),
                remediation="Use 'Clean stale MC state' after reviewing the listed resources.",
            ))

            critical_failures = [c for c in checks if c["severity"] == "critical" and c["status"] == "fail"]
            warnings = [c for c in checks if c["status"] == "warn"]
            score = posture_score(checks)
            status = "critical" if critical_failures else ("warning" if warnings else "hardened")
            return {
                "status": status,
                "score": score,
                "enforcement_ready": not critical_failures,
                "critical_count": len(critical_failures),
                "warning_count": len(warnings),
                "checks": checks,
                "stale": {
                    "address_lists": [f"{lst}:{addr}" for lst, addr in stale_lists],
                    "queues": stale_queues,
                    "schedulers": stale_schedulers,
                    "scripts": stale_scripts,
                    "total": stale_total,
                },
                "integrity": {
                    "duplicate_address_lists": [f"{lst}:{addr}" for lst, addr in duplicates],
                    "malformed_address_lists": [f"{lst}:{addr}" for lst, addr in malformed_lists],
                    "malformed_queues": malformed_queues,
                    "duplicate_queues": duplicate_queues,
                    "malformed_temp": malformed_temp,
                    "orphan_temp": orphan_temp,
                },
                "fasttrack": {
                    "enabled": len(fasttrack_rules),
                    "unsafe": len(unsafe_fasttrack),
                },
                "authority": {
                    "global_mode": global_mode,
                    "master_enabled": master_enabled,
                    "global_slow_enabled": slow_enabled,
                    "forward_positions": forward_order.get("positions", {}),
                    "forward_established_anchor": forward_order.get("established_anchor"),
                    "forward_established_candidates": forward_order.get("established_candidates", []),
                    "forward_chain_rule_count": forward_order.get("chain_rule_count", 0),
                    "forward_comment_collisions": forward_order.get("other_chain_collisions", {}),
                    "active_forward_rules": required_forward,
                },
                "doh": {
                    "expected": len(DOH_ROUTER_RULES),
                    "valid": len(doh_rule_seen),
                    "errors": doh_rule_errors,
                    "complete_for_catalog": not doh_rule_errors,
                    "coverage_note": (
                        "Known-provider TLS/SNI baseline only; ECH, unknown providers and "
                        "IP-literal DoH cannot be proven blocked by this contract."
                    ),
                },
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to evaluate RouterOS security posture: {exc}") from exc
        finally:
            pool.disconnect()

    def assert_policy_enforcement_ready(self) -> dict:
        posture = self.get_security_posture()
        if not posture.get("enforcement_ready"):
            # Never carry a successful authority decision across a failed fresh
            # read inside the same coherent request.
            if getattr(self, "_session_local", None) is not None:
                self._session_local.authority_proven = False
            failed = [
                check["name"] for check in posture.get("checks", [])
                if check.get("severity") == "critical" and check.get("status") == "fail"
            ]
            raise RouterError(
                "RouterOS security posture is not enforcement-ready: "
                + (", ".join(failed) or "critical hardening check failed")
            )
        if (
            getattr(self, "_session_local", None) is not None
            and getattr(self._session_local, "state", None) is not None
        ):
            self._session_local.authority_proven = True
        return posture

    def _require_policy_write_gate(self) -> dict | None:
        """Prove critical RouterOS authority before a policy-enforcement write.

        UI/reconciler callers already perform this check in several paths, but
        the adapter is the final authority boundary.  Keeping the invariant here
        prevents a future caller, script or maintenance path from bypassing the
        security gate accidentally.  A proof is reusable only inside the same
        coherent RouterOS request/session; it is never cached across requests.
        """
        if (
            getattr(self, "_session_local", None) is not None
            and getattr(self._session_local, "state", None) is not None
            and bool(getattr(self._session_local, "authority_proven", False))
        ):
            return None
        return self.assert_policy_enforcement_ready()

    def cleanup_stale_managed_resources(self) -> dict:
        """Remove only app-owned MC resources for devices no longer restricted."""
        pool, api = self._connect()
        removed = {"address_lists": 0, "queues": 0, "schedulers": 0, "scripts": 0}
        try:
            address_resource = api.get_resource("/ip/firewall/address-list")
            entries = address_resource.get()
            restricted = {
                str(item.get("address")) for item in entries
                if item.get("list") == self.RESTRICTED_LIST
                and not _ros_bool(item.get("dynamic", False))
            }
            for entry in entries:
                list_name = str(entry.get("list") or "")
                if not list_name.startswith(MANAGED_LIST_PREFIXES):
                    continue
                try:
                    addr = str(ipaddress.ip_address(str(entry.get("address"))))
                except ValueError:
                    continue
                if addr in restricted:
                    continue
                entry_id = self._entry_id(entry)
                if entry_id:
                    address_resource.remove(id=entry_id)
                    removed["address_lists"] += 1

            queue_resource = api.get_resource("/queue/simple")
            for entry in queue_resource.get():
                name = str(entry.get("name") or "")
                if not name.startswith(MANAGED_QUEUE_PREFIXES):
                    continue
                addr = encoded_ipv4_from_name(name, MANAGED_QUEUE_PREFIXES)
                if not addr or addr in restricted:
                    continue
                entry_id = self._entry_id(entry)
                if entry_id:
                    queue_resource.remove(id=entry_id)
                    removed["queues"] += 1

            sched_resource = api.get_resource("/system/scheduler")
            for entry in sched_resource.get():
                name = str(entry.get("name") or "")
                if not name.startswith(self.DEVICE_TEMP_SCHED_PREFIX):
                    continue
                addr = encoded_ipv4_from_name(name, (self.DEVICE_TEMP_SCHED_PREFIX,))
                if not addr or addr in restricted:
                    continue
                entry_id = self._entry_id(entry)
                if entry_id:
                    sched_resource.remove(id=entry_id)
                    removed["schedulers"] += 1

            script_resource = api.get_resource("/system/script")
            for entry in script_resource.get():
                name = str(entry.get("name") or "")
                if not name.startswith(self.DEVICE_TEMP_SCRIPT_PREFIX):
                    continue
                addr = encoded_ipv4_from_name(name, (self.DEVICE_TEMP_SCRIPT_PREFIX,))
                if not addr or addr in restricted:
                    continue
                entry_id = self._entry_id(entry)
                if entry_id:
                    script_resource.remove(id=entry_id)
                    removed["scripts"] += 1

            removed["total"] = sum(removed.values())
            return removed
        except Exception as exc:
            raise RouterError(f"Unable to clean stale managed RouterOS resources: {exc}") from exc
        finally:
            pool.disconnect()

    def get_managed_state_inventory(self) -> dict:
        """Return a read-only inventory of app-owned and app-required RouterOS state.

        The inventory is intentionally descriptive rather than reparative. It gives
        operators a disaster-recovery view of what currently exists without
        changing firewall, queue, scheduler or script authority.
        """
        pool, api = self._connect()
        try:
            identity = api.get_resource("/system/identity").get()
            router_name = identity[0].get("name", "unknown") if identity else "unknown"

            address_entries = api.get_resource("/ip/firewall/address-list").get()
            restricted = [
                {
                    "address": str(item.get("address") or ""),
                    "comment": str(item.get("comment") or ""),
                    "dynamic": _ros_bool(item.get("dynamic", False)),
                }
                for item in address_entries
                if item.get("list") == self.RESTRICTED_LIST
            ]

            managed_entries = [
                {
                    "list": str(item.get("list") or ""),
                    "address": str(item.get("address") or ""),
                    "comment": str(item.get("comment") or ""),
                    "dynamic": _ros_bool(item.get("dynamic", False)),
                }
                for item in address_entries
                if (
                    str(item.get("list") or "").startswith(MANAGED_LIST_PREFIXES)
                    or str(item.get("list") or "").startswith("MC_Detected_")
                )
            ]
            list_counts = {}
            for item in managed_entries:
                list_counts[item["list"]] = list_counts.get(item["list"], 0) + 1

            queue_rows = api.get_resource("/queue/simple").get()
            queues = []
            for item in queue_rows:
                name = str(item.get("name") or "")
                if name != self.SLOW_QUEUE_NAME and not name.startswith(MANAGED_QUEUE_PREFIXES):
                    continue
                queues.append({
                    "name": name,
                    "target": str(item.get("target") or ""),
                    "max_limit": str(item.get("max-limit") or ""),
                    "disabled": _ros_bool(item.get("disabled", False)),
                    "comment": str(item.get("comment") or ""),
                })

            scheduler_rows = api.get_resource("/system/scheduler").get()
            schedulers = []
            for item in scheduler_rows:
                name = str(item.get("name") or "")
                if not (
                    name.startswith(self.SCHED_PREFIX)
                    or name.startswith(self.DEVICE_TEMP_SCHED_PREFIX)
                    or name == self.TEMP_SCHED_NAME
                ):
                    continue
                schedulers.append({
                    "name": name,
                    "start_date": str(item.get("start-date") or ""),
                    "start_time": str(item.get("start-time") or ""),
                    "interval": str(item.get("interval") or ""),
                    "disabled": _ros_bool(item.get("disabled", False)),
                    "comment": str(item.get("comment") or ""),
                })

            script_rows = api.get_resource("/system/script").get()
            expected_scripts = set(self.MODE_SCRIPTS.values())
            scripts = []
            for item in script_rows:
                name = str(item.get("name") or "")
                if not (
                    name.startswith(self.DEVICE_TEMP_SCRIPT_PREFIX)
                    or name in expected_scripts
                ):
                    continue
                scripts.append({
                    "name": name,
                    "disabled": _ros_bool(item.get("disabled", False)),
                    "comment": str(item.get("comment") or ""),
                })

            firewall_rows = api.get_resource("/ip/firewall/filter").get()
            required_comments = {
                self.MASTER_RULE_COMMENT, self.DEVICE_BLOCK_RULE_COMMENT,
                self.WEB_POLICY_COMMENT, self.QUIC_RULE_COMMENT, self.DOT_RULE_COMMENT,
                self.DOQ_RULE_COMMENT, "RW99 - Return",
            }
            required_comments.update(item["comment"] for item in DOH_ROUTER_RULES)
            for service in SERVICE_ENFORCEMENT.values():
                required_comments.update(item["comment"] for item in service.get("rules", []))
                required_comments.update(item["comment"] for item in service.get("learners", []))
            firewall = [
                {
                    "comment": str(item.get("comment") or ""),
                    "chain": str(item.get("chain") or ""),
                    "action": str(item.get("action") or ""),
                    "disabled": _ros_bool(item.get("disabled", False)),
                }
                for item in firewall_rows
                if (
                    item.get("comment") in required_comments
                    or str(item.get("comment") or "").startswith(CUSTOM_SERVICE_COMMENT_PREFIX)
                )
            ]

            return {
                "router": router_name,
                "host": self.host,
                "counts": {
                    "restricted_devices": len(restricted),
                    "managed_address_entries": len(managed_entries),
                    "managed_address_lists": len(list_counts),
                    "managed_queues": len(queues),
                    "managed_schedulers": len(schedulers),
                    "managed_scripts": len(scripts),
                    "required_firewall_rules_seen": len(firewall),
                    "required_firewall_rules_expected": len(required_comments),
                },
                "restricted_devices": restricted,
                "address_lists": [
                    {"name": name, "entries": count}
                    for name, count in sorted(list_counts.items())
                ],
                "queues": sorted(queues, key=lambda item: item["name"]),
                "schedulers": sorted(schedulers, key=lambda item: item["name"]),
                "scripts": sorted(scripts, key=lambda item: item["name"]),
                "firewall": firewall,
            }
        except Exception as exc:
            raise RouterError(f"Unable to inventory managed RouterOS state: {exc}") from exc
        finally:
            pool.disconnect()

    def health(self) -> dict:
        pool, api = self._connect()
        try:
            identity = api.get_resource("/system/identity").get()
            router_name = identity[0].get("name", "unknown") if identity else "unknown"
            return {"connected": True, "router": router_name, "host": self.host}
        except Exception as exc:
            raise RouterError(f"MikroTik health check failed: {exc}") from exc
        finally:
            pool.disconnect()

    def get_restricted_devices(self) -> list[dict]:
        pool, api = self._connect()
        try:
            entries = api.get_resource("/ip/firewall/address-list").get(
                list=self.RESTRICTED_LIST
            )
            devices = []
            for entry in entries:
                devices.append(
                    {
                        "id": entry.get("id"),
                        "name": entry.get("comment") or "Unnamed device",
                        "address": entry.get("address"),
                        "dynamic": _ros_bool(entry.get("dynamic", False)),
                    }
                )
            devices.sort(key=lambda item: item["name"].lower())
            return devices
        except Exception as exc:
            raise RouterError(f"Unable to read Restricted_Devices: {exc}") from exc
        finally:
            pool.disconnect()

    def get_status(self) -> dict:
        pool, api = self._connect()
        try:
            firewall = api.get_resource("/ip/firewall/filter")
            queues = api.get_resource("/queue/simple")

            master_rules = firewall.get(comment=self.MASTER_RULE_COMMENT)
            slow_queues = queues.get(name=self.SLOW_QUEUE_NAME)

            if len(master_rules) != 1:
                raise RouterError(
                    f"Expected exactly one master rule, found {len(master_rules)}"
                )
            if len(slow_queues) != 1:
                raise RouterError(
                    f"Expected exactly one slow queue, found {len(slow_queues)}"
                )

            master_enabled = not _ros_bool(master_rules[0].get("disabled", False))
            slow_enabled = not _ros_bool(slow_queues[0].get("disabled", False))

            if master_enabled and slow_enabled:
                mode = "invalid"
            elif master_enabled:
                mode = "blocked"
            elif slow_enabled:
                mode = "slow"
            else:
                mode = "normal"

            return {
                "mode": mode,
                "master_block_enabled": master_enabled,
                "slow_queue_enabled": slow_enabled,
                "slow_limit": slow_queues[0].get("max-limit"),
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to determine router state: {exc}") from exc
        finally:
            pool.disconnect()

    def set_mode(self, mode: str) -> dict:
        mode = mode.lower()
        if mode not in self.MODE_SCRIPTS:
            raise RouterError(
                f"Invalid mode '{mode}'. Expected normal, slow or blocked."
            )

        self._require_policy_write_gate()
        script_name = self.MODE_SCRIPTS[mode]
        pool, api = self._connect()
        try:
            scripts = api.get_resource("/system/script")
            matches = scripts.get(name=script_name)
            if len(matches) != 1:
                raise RouterError(
                    f"Expected exactly one script named '{script_name}', "
                    f"found {len(matches)}"
                )
            scripts.call("run", {"number": matches[0]["id"]})
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to run {script_name}: {exc}") from exc
        finally:
            pool.disconnect()

        status = self.get_status()
        if status["mode"] != mode:
            raise RouterError(
                f"Requested mode '{mode}' but router reports '{status['mode']}'"
            )
        return status

    def get_web_policy_status(self) -> dict:
        pool, api = self._connect()
        try:
            rules = api.get_resource("/ip/firewall/filter").get(
                comment=self.WEB_POLICY_COMMENT
            )
            if len(rules) != 1:
                raise RouterError(
                    f"Expected exactly one '{self.WEB_POLICY_COMMENT}' rule, "
                    f"found {len(rules)}"
                )
            enabled = not _ros_bool(rules[0].get("disabled", False))
            return {"enabled": enabled, "rule_id": rules[0].get("id")}
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to read restricted web policy: {exc}") from exc
        finally:
            pool.disconnect()

    def set_web_policy(self, enabled: bool) -> dict:
        pool, api = self._connect()
        try:
            firewall = api.get_resource("/ip/firewall/filter")
            rules = firewall.get(comment=self.WEB_POLICY_COMMENT)
            if len(rules) != 1:
                raise RouterError(
                    f"Expected exactly one '{self.WEB_POLICY_COMMENT}' rule, "
                    f"found {len(rules)}"
                )
            firewall.set(
                id=rules[0]["id"],
                disabled="false" if enabled else "true",
            )
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to change restricted web policy: {exc}") from exc
        finally:
            pool.disconnect()

        actual = self.get_web_policy_status()
        if actual["enabled"] != enabled:
            raise RouterError("Router did not report the requested web policy state")
        return actual

    def _validate_service_contract(self, api, service_key: str, service: dict) -> dict:
        """Validate one exact RouterOS TLS/SNI service contract."""
        firewall = api.get_resource("/ip/firewall/filter")
        block_rules = []
        learner_rules = []

        for expected in service["rules"]:
            rules = firewall.get(comment=expected["comment"])
            if len(rules) != 1:
                raise RouterError(
                    f"Expected exactly one '{expected['comment']}' rule, found {len(rules)}"
                )
            rule = rules[0]
            problems = []
            if _ros_bool(rule.get("disabled", False)):
                problems.append("disabled")
            if rule.get("chain") != "restricted-web":
                problems.append(f"chain={rule.get('chain')!r}")
            if rule.get("action") != "drop":
                problems.append(f"action={rule.get('action')!r}")
            if rule.get("src-address-list") != service["source_list"]:
                problems.append(f"src-address-list={rule.get('src-address-list')!r}")
            if rule.get("dst-address-list") != expected["detector_list"]:
                problems.append(f"dst-address-list={rule.get('dst-address-list')!r}")
            if problems:
                raise RouterError(
                    f"'{expected['comment']}' does not match the managed service contract: "
                    + ", ".join(problems)
                )
            block_rules.append({
                "comment": expected["comment"],
                "rule_id": self._entry_id(rule),
                "detector_list": expected["detector_list"],
            })

        for expected in service.get("learners", []):
            rules = firewall.get(comment=expected["comment"])
            if len(rules) != 1:
                raise RouterError(
                    f"Expected exactly one '{expected['comment']}' rule, found {len(rules)}"
                )
            rule = rules[0]
            problems = []
            if _ros_bool(rule.get("disabled", False)):
                problems.append("disabled")
            if rule.get("chain") != "restricted-web":
                problems.append(f"chain={rule.get('chain')!r}")
            if rule.get("action") != "add-dst-to-address-list":
                problems.append(f"action={rule.get('action')!r}")
            if rule.get("protocol") != "tcp":
                problems.append(f"protocol={rule.get('protocol')!r}")
            if str(rule.get("dst-port", "")) != "443":
                problems.append(f"dst-port={rule.get('dst-port')!r}")
            if rule.get("address-list") != expected["address_list"]:
                problems.append(f"address-list={rule.get('address-list')!r}")
            if rule.get("tls-host") != expected["tls_host"]:
                problems.append(f"tls-host={rule.get('tls-host')!r}")
            if problems:
                raise RouterError(
                    f"'{expected['comment']}' does not match the managed TLS/SNI classifier contract: "
                    + ", ".join(problems)
                )
            learner_rules.append({
                "comment": expected["comment"],
                "rule_id": self._entry_id(rule),
                "address_list": expected["address_list"],
                "tls_host": expected["tls_host"],
            })

        if service.get("managed_custom"):
            all_rules = firewall.get()
            chain_local = [rule for rule in all_rules if rule.get("chain") == "restricted-web"]
            rw99 = [rule for rule in chain_local if rule.get("comment") == "RW99 - Return"]
            if len(rw99) != 1:
                raise RouterError(
                    f"Expected exactly one 'RW99 - Return' in restricted-web, found {len(rw99)}"
                )
            positions = {self._entry_id(rule): idx for idx, rule in enumerate(chain_local)}
            anchor_id = self._entry_id(rw99[0])
            anchor_pos = positions.get(anchor_id)
            late = []
            for item in block_rules + learner_rules:
                rule_id = item.get("rule_id")
                if rule_id not in positions or anchor_pos is None or positions[rule_id] >= anchor_pos:
                    late.append(item["comment"])
            if late:
                raise RouterError(
                    "Managed custom service rule(s) are not before RW99 - Return: "
                    + ", ".join(late)
                )

        return {
            "key": service_key,
            "name": service["name"],
            "source_list": service["source_list"],
            "rules": block_rules,
            "learners": learner_rules,
        }

    def _validate_service_primitive(self, api, service_key: str, service_catalog=None) -> dict:
        """Validate one built-in or explicitly supplied RouterOS service contract."""
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        if service_key not in catalog:
            raise RouterError(f"Unknown managed service key: {service_key}")
        return self._validate_service_contract(api, service_key, catalog[service_key])

    def _validate_service_primitives(self, api, service_keys=None, service_catalog=None) -> dict:
        """Validate selected service contracts without mutating RouterOS."""
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        keys = list(catalog) if service_keys is None else list(service_keys)
        return {
            key: self._validate_service_primitive(api, key, catalog)
            for key in keys
        }

    def _preview_custom_service_contract_api(self, api, service: dict) -> dict:
        """Fresh-read one deterministic custom contract without mutating RouterOS."""
        if not service.get("managed_custom"):
            raise RouterError("Custom service preview requires a managed custom contract")
        firewall = api.get_resource("/ip/firewall/filter")
        rules = firewall.get()
        address_lists = api.get_resource("/ip/firewall/address-list")
        expected_comments = {
            item["comment"] for item in service.get("learners", []) + service.get("rules", [])
        }
        ownership_prefix = str(service.get("ownership_prefix") or "")
        owned = [
            rule for rule in rules
            if ownership_prefix and str(rule.get("comment") or "").startswith(ownership_prefix)
        ]
        owned_comments = [str(rule.get("comment") or "") for rule in owned]
        unexpected_owned = sorted(set(owned_comments) - expected_comments)
        present_expected = sorted(set(owned_comments) & expected_comments)
        conflicts = []
        if unexpected_owned:
            conflicts.append(
                "Unexpected app-owned rule(s): " + ", ".join(unexpected_owned)
            )

        reserved_lists = {service["source_list"]}
        reserved_lists.update(service.get("detector_lists") or [])
        foreign_refs = []
        for rule in rules:
            comment = str(rule.get("comment") or "")
            if comment in expected_comments:
                continue
            refs = {
                str(rule.get("src-address-list") or ""),
                str(rule.get("dst-address-list") or ""),
                str(rule.get("address-list") or ""),
            }
            used = sorted((refs & reserved_lists) - {""})
            if used:
                foreign_refs.append(f"{comment or '<no comment>'} -> {','.join(used)}")
        if foreign_refs:
            conflicts.append(
                "Reserved custom list name(s) are referenced by unrelated/manual rule(s): "
                + " | ".join(foreign_refs[:8])
            )

        all_expected_present = len(present_expected) == len(expected_comments)
        none_expected_present = not present_expected
        validated = None
        validation_error = ""
        if all_expected_present and not conflicts:
            try:
                validated = self._validate_service_contract(api, service["key"], service)
            except RouterError as exc:
                validation_error = str(exc)
                conflicts.append(validation_error)
        elif present_expected and not all_expected_present:
            missing = sorted(expected_comments - set(present_expected))
            conflicts.append(
                "Partial managed custom contract; missing rule(s): " + ", ".join(missing)
            )

        source_entries = address_lists.get(list=service["source_list"])
        detector_counts = {}
        for list_name in service.get("detector_lists") or []:
            detector_counts[list_name] = len(address_lists.get(list=list_name))
        if none_expected_present and (source_entries or any(detector_counts.values())):
            occupied = []
            if source_entries:
                occupied.append(f"{service['source_list']}={len(source_entries)}")
            occupied.extend(
                f"{name}={count}" for name, count in sorted(detector_counts.items()) if count
            )
            conflicts.append(
                "Reserved custom address-list namespace already contains entries: "
                + ", ".join(occupied)
            )

        if validated and not conflicts:
            status = "healthy"
        elif none_expected_present and not conflicts:
            status = "absent"
        else:
            status = "conflict"

        actions = []
        if status == "absent":
            for learner in service.get("learners", []):
                actions.append({
                    "action": "create",
                    "kind": "tls_learner",
                    "comment": learner["comment"],
                    "chain": "restricted-web",
                    "tls_host": learner["tls_host"],
                    "address_list": learner["address_list"],
                })
            for rule in service.get("rules", []):
                actions.append({
                    "action": "create",
                    "kind": "block_rule",
                    "comment": rule["comment"],
                    "chain": "restricted-web",
                    "source_list": service["source_list"],
                    "detector_list": rule["detector_list"],
                })

        return {
            "key": service["key"],
            "name": service["name"],
            "status": status,
            "healthy": status == "healthy",
            "conflicts": conflicts,
            "error": " | ".join(conflicts),
            "contract": service,
            "validated": validated or {},
            "actions": actions,
            "source_entries": len(source_entries),
            "detector_counts": detector_counts,
            "detector_addresses": sum(detector_counts.values()),
            "present_rules": len(present_expected),
            "expected_rules": len(expected_comments),
        }

    def inspect_custom_service_contract(self, service: dict) -> dict:
        pool, api = self._connect()
        try:
            return self._preview_custom_service_contract_api(api, service)
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to inspect custom service contract: {exc}") from exc
        finally:
            pool.disconnect()

    def provision_custom_service_contract(self, service: dict) -> dict:
        """Create one absent custom contract, then fresh-read and validate it."""
        self._require_policy_write_gate()
        pool, api = self._connect()
        created_ids = []
        try:
            preview = self._preview_custom_service_contract_api(api, service)
            if preview["status"] == "healthy":
                return {**preview, "idempotent": True, "created": 0}
            if preview["status"] != "absent":
                raise RouterError(
                    "Refusing custom service provisioning because RouterOS state conflicts: "
                    + (preview.get("error") or preview["status"])
                )

            firewall = api.get_resource("/ip/firewall/filter")
            rw99 = [
                rule for rule in firewall.get(comment="RW99 - Return")
                if rule.get("chain") == "restricted-web"
            ]
            if len(rw99) != 1 or not self._entry_id(rw99[0]):
                raise RouterError(
                    "Cannot provision custom service: exactly one addressable RW99 - Return "
                    "must exist in restricted-web"
                )
            place_before = self._entry_id(rw99[0])

            def add_and_capture(comment, **values):
                firewall.add(**values, comment=comment, **{"place-before": place_before})
                matches = firewall.get(comment=comment)
                if len(matches) != 1 or not self._entry_id(matches[0]):
                    raise RouterError(
                        f"RouterOS did not return exactly one created rule '{comment}'"
                    )
                created_ids.append(self._entry_id(matches[0]))

            for learner in service.get("learners", []):
                add_and_capture(
                    learner["comment"],
                    chain="restricted-web",
                    action="add-dst-to-address-list",
                    protocol="tcp",
                    **{
                        "dst-port": "443",
                        "address-list": learner["address_list"],
                        "tls-host": learner["tls_host"],
                        "disabled": "false",
                    },
                )
            for rule in service.get("rules", []):
                add_and_capture(
                    rule["comment"],
                    chain="restricted-web",
                    action="drop",
                    **{
                        "src-address-list": service["source_list"],
                        "dst-address-list": rule["detector_list"],
                        "disabled": "false",
                    },
                )
        except Exception as exc:
            try:
                firewall = api.get_resource("/ip/firewall/filter")
                for rule_id in reversed(created_ids):
                    firewall.remove(id=rule_id)
                # Preflight requires the custom namespace to be empty, so any
                # detector entries learned during this failed transaction are
                # ours to remove as part of rollback.
                address_lists = api.get_resource("/ip/firewall/address-list")
                for list_name in service.get("detector_lists") or []:
                    for entry in address_lists.get(list=list_name):
                        entry_id = self._entry_id(entry)
                        if entry_id:
                            address_lists.remove(id=entry_id)
            except Exception:
                pass
            if isinstance(exc, RouterError):
                raise
            raise RouterError(f"Unable to provision custom service contract: {exc}") from exc
        finally:
            pool.disconnect()

        verified = self.inspect_custom_service_contract(service)
        if verified.get("status") != "healthy":
            # The install was not trustworthy after a new RouterOS read. Remove only
            # the deterministic app-owned comments from this contract.
            try:
                rollback_pool, rollback_api = self._connect()
                try:
                    firewall = rollback_api.get_resource("/ip/firewall/filter")
                    for expected in service.get("learners", []) + service.get("rules", []):
                        for rule in firewall.get(comment=expected["comment"]):
                            rule_id = self._entry_id(rule)
                            if rule_id:
                                firewall.remove(id=rule_id)
                    address_lists = rollback_api.get_resource("/ip/firewall/address-list")
                    for list_name in service.get("detector_lists") or []:
                        for entry in address_lists.get(list=list_name):
                            entry_id = self._entry_id(entry)
                            if entry_id:
                                address_lists.remove(id=entry_id)
                finally:
                    rollback_pool.disconnect()
            except Exception:
                pass
            raise RouterError(
                "Custom service post-write validation failed; deterministic rules were rolled back: "
                + (verified.get("error") or verified.get("status", "unknown"))
            )
        return {**verified, "idempotent": False, "created": len(created_ids)}

    def remove_custom_service_contract(self, service: dict) -> dict:
        """Remove one healthy app-owned custom contract and its app-owned list data."""
        self._require_policy_write_gate()
        pool, api = self._connect()
        removed_rules = 0
        removed_entries = 0
        try:
            preview = self._preview_custom_service_contract_api(api, service)
            if preview["status"] == "absent":
                return {**preview, "idempotent": True, "removed_rules": 0, "removed_entries": 0}
            if preview["status"] != "healthy":
                raise RouterError(
                    "Refusing custom service removal because the existing MC contract is malformed/conflicting: "
                    + (preview.get("error") or preview["status"])
                )

            firewall = api.get_resource("/ip/firewall/filter")
            for item in preview.get("validated", {}).get("rules", []) + preview.get("validated", {}).get("learners", []):
                rule_id = item.get("rule_id")
                if not rule_id:
                    raise RouterError(f"Cannot remove unaddressable managed rule '{item.get('comment')}'")
                firewall.remove(id=rule_id)
                removed_rules += 1

            address_lists = api.get_resource("/ip/firewall/address-list")
            for list_name in [service["source_list"], *(service.get("detector_lists") or [])]:
                for entry in address_lists.get(list=list_name):
                    entry_id = self._entry_id(entry)
                    if entry_id:
                        address_lists.remove(id=entry_id)
                        removed_entries += 1
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to remove custom service contract: {exc}") from exc
        finally:
            pool.disconnect()

        verified = self.inspect_custom_service_contract(service)
        if verified.get("status") != "absent":
            raise RouterError(
                "Custom service removal did not converge after fresh RouterOS read: "
                + (verified.get("error") or verified.get("status", "unknown"))
            )
        return {
            **verified,
            "idempotent": False,
            "removed_rules": removed_rules,
            "removed_entries": removed_entries,
        }

    def get_service_contract_health(self, custom_services=None) -> dict:
        """Return built-in plus custom RouterOS contract health without mutation."""
        pool, api = self._connect()
        try:
            address_lists = api.get_resource("/ip/firewall/address-list")
            rows = []
            healthy = 0
            detector_total = 0
            degraded = 0
            reporting_only = 0

            for key, service in SERVICE_ENFORCEMENT.items():
                error = ""
                validated = None
                try:
                    validated = self._validate_service_primitive(api, key)
                    healthy += 1
                except RouterError as exc:
                    error = str(exc)
                    degraded += 1
                detector_lists = sorted({
                    str(rule.get("detector_list") or "")
                    for rule in service.get("rules", ()) if rule.get("detector_list")
                })
                detector_counts = {name: len(address_lists.get(list=name)) for name in detector_lists}
                detector_total += sum(detector_counts.values())
                rows.append({
                    "key": key, "name": service.get("name", key),
                    "status": "healthy" if not error else "degraded",
                    "healthy": not bool(error), "approved": True, "builtin": True,
                    "error": error,
                    "tls_patterns": [item.get("tls_host") for item in service.get("learners", ()) if item.get("tls_host")],
                    "learners": len(service.get("learners", ())),
                    "block_rules": len(service.get("rules", ())),
                    "source_list": service.get("source_list", ""),
                    "detector_lists": detector_lists,
                    "detector_counts": detector_counts,
                    "detector_addresses": sum(detector_counts.values()),
                    "contract": validated or {},
                    "coverage_note": service.get("coverage_note", ""),
                })

            for definition in custom_services or []:
                if definition.get("builtin"):
                    continue
                service = definition.get("routeros_contract")
                if not service:
                    # Invalid/not-provisionable metadata is reporting-only only
                    # when it has never been approved. An approved definition
                    # without a valid deterministic contract is degraded and
                    # deliberately omitted from runtime write authority.
                    approved = bool(definition.get("enforcement_approved"))
                    if approved:
                        degraded += 1
                        status = "degraded"
                        healthy_state = False
                    else:
                        reporting_only += 1
                        status = "reporting"
                        healthy_state = None
                    rows.append({
                        "key": definition.get("key"), "name": definition.get("name"),
                        "status": status, "healthy": healthy_state,
                        "approved": approved,
                        "builtin": False, "error": definition.get("provisioning_error", ""),
                        "tls_patterns": list(definition.get("tls_patterns") or []),
                        "learners": 0, "block_rules": 0, "source_list": "",
                        "detector_lists": [], "detector_counts": {}, "detector_addresses": 0,
                        "contract": {}, "coverage_note": "Reporting-only custom classifier.",
                    })
                    continue
                preview = self._preview_custom_service_contract_api(api, service)
                approved = bool(definition.get("enforcement_approved"))
                status = preview["status"]
                error = preview.get("error", "")
                if approved:
                    if status == "healthy":
                        healthy += 1
                    else:
                        degraded += 1
                        status = "degraded"
                        if not error:
                            error = "Approved custom contract is not installed"
                else:
                    if status == "absent":
                        status = "reporting"
                        reporting_only += 1
                    else:
                        degraded += 1
                        status = "orphaned"
                        error = (
                            "RouterOS has an MC custom contract without local operator approval. "
                            + (error or "Remove it or explicitly reprovision from ZEN Control.")
                        )
                detector_total += int(preview.get("detector_addresses") or 0)
                rows.append({
                    "key": definition.get("key"), "name": definition.get("name"),
                    "status": status, "healthy": status == "healthy",
                    "approved": approved, "builtin": False, "error": error,
                    "tls_patterns": list(definition.get("tls_patterns") or []),
                    "learners": len(service.get("learners", ())),
                    "block_rules": len(service.get("rules", ())),
                    "source_list": service.get("source_list", ""),
                    "detector_lists": list(service.get("detector_lists") or []),
                    "detector_counts": dict(preview.get("detector_counts") or {}),
                    "detector_addresses": int(preview.get("detector_addresses") or 0),
                    "contract": preview.get("validated") or {},
                    "preview": preview, "coverage_note": service.get("coverage_note", ""),
                })

            managed_total = len(SERVICE_ENFORCEMENT) + sum(
                1 for item in custom_services or []
                if not item.get("builtin") and item.get("enforcement_approved")
            )
            return {
                "available": True,
                "services": rows,
                "healthy": healthy,
                "total": managed_total,
                "degraded": degraded,
                "reporting_only": reporting_only,
                "custom_approved": max(0, managed_total - len(SERVICE_ENFORCEMENT)),
                "detector_addresses": detector_total,
            }
        except Exception as exc:
            raise RouterError(f"Unable to read service TLS/SNI health: {exc}") from exc
        finally:
            pool.disconnect()

    def get_managed_device_observation_snapshot(
        self,
        service_catalog=None,
        service_health_map=None,
    ) -> dict:
        """Read dashboard/device observational state with bounded RouterOS queries.

        This is a read-only UI optimization.  It collapses the old per-device
        mode/service/bandwidth N+1 pattern into one fresh snapshot acquired
        during the current request.  It does *not* cache values across requests
        and it is never used by write/pre-write/post-write validation paths.

        Temporary-access state intentionally remains outside this snapshot
        because the existing temporary-access reader also performs bounded
        cleanup of expired app-owned scheduler/script artefacts.
        """
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        health_map = service_health_map or {}
        pool, api = self._connect()
        try:
            address_list = api.get_resource("/ip/firewall/address-list")
            queues = api.get_resource("/queue/simple")

            with perf_span("routeros.snapshot.address_lists"):
                restricted_rows = address_list.get(list=self.RESTRICTED_LIST)
                blocked_rows = address_list.get(list=self.DEVICE_BLOCK_LIST)
                slow_rows = address_list.get(list=self.DEVICE_SLOW_LIST)
                service_rows = {
                    key: address_list.get(list=service["source_list"])
                    for key, service in catalog.items()
                }

            with perf_span("routeros.snapshot.queues"):
                queue_rows = queues.get()

            # This primitive is global rather than per-device; validate it once
            # for the whole observational snapshot.  A malformed primitive must
            # not hide the managed-device inventory from the UI, so retain the
            # failure as per-device evidence rather than aborting the snapshot.
            device_authority_error = None
            with perf_span("routeros.snapshot.device_authority"):
                try:
                    self._validate_device_block_primitive(api)
                except RouterError as exc:
                    device_authority_error = str(exc)

            contract_state = {}
            with perf_span("routeros.snapshot.service_authority"):
                for key, service in catalog.items():
                    known = health_map.get(key)
                    if known is not None:
                        healthy = bool(known.get("healthy"))
                        contract_state[key] = {
                            "available": healthy,
                            "error": None if healthy else str(known.get("error") or "Service contract is not healthy"),
                        }
                        continue
                    try:
                        self._validate_service_primitive(api, key, catalog)
                        contract_state[key] = {"available": True, "error": None}
                    except RouterError as exc:
                        contract_state[key] = {"available": False, "error": str(exc)}

            def by_address(rows):
                result = {}
                for row in rows:
                    address = str(row.get("address") or "").strip()
                    if not address:
                        continue
                    result.setdefault(address, []).append(row)
                return result

            restricted_by_address = by_address(restricted_rows)
            blocked_by_address = by_address(blocked_rows)
            slow_by_address = by_address(slow_rows)
            service_by_address = {
                key: by_address(rows) for key, rows in service_rows.items()
            }
            queue_by_name = {}
            for row in queue_rows:
                name = str(row.get("name") or "")
                if name:
                    queue_by_name.setdefault(name, []).append(row)

            devices = [
                {
                    "id": row.get("id"),
                    "name": row.get("comment") or "Unnamed device",
                    "address": row.get("address"),
                    "dynamic": _ros_bool(row.get("dynamic", False)),
                }
                for row in restricted_rows
                if row.get("address")
            ]
            devices.sort(key=lambda item: str(item.get("name") or "").lower())

            states = {}
            for device in devices:
                address = self._validate_ipv4(str(device["address"]))
                restricted = restricted_by_address.get(address, [])
                static_restricted = [
                    row for row in restricted if not _ros_bool(row.get("dynamic", False))
                ]
                if len(static_restricted) != 1:
                    states[address] = {
                        "error": (
                            f"{address} is not exactly one static {self.RESTRICTED_LIST} member"
                        )
                    }
                    continue
                if device_authority_error:
                    states[address] = {"error": device_authority_error}
                    continue

                blocked = blocked_by_address.get(address, [])
                slow = slow_by_address.get(address, [])
                slow_queue_name = self._device_slow_queue_name(address)
                slow_queues = queue_by_name.get(slow_queue_name, [])
                if not blocked and not slow and not slow_queues:
                    mode = "normal"
                elif len(blocked) == 1 and not slow and not slow_queues:
                    mode = "blocked"
                elif (
                    not blocked
                    and len(slow) == 1
                    and len(slow_queues) == 1
                    and not _ros_bool(slow_queues[0].get("disabled", False))
                ):
                    mode = "slow"
                else:
                    mode = "invalid"
                live_enforcement = {
                    "address": address,
                    "mode": mode,
                    "blocked": mode == "blocked",
                    "slow": mode == "slow",
                    "blocked_entries": len(blocked),
                    "slow_entries": len(slow),
                    "slow_queues": len(slow_queues),
                    "slow_queue": slow_queue_name,
                    "slow_limit": slow_queues[0].get("max-limit") if len(slow_queues) == 1 else None,
                }

                bandwidth_queue_name = self._device_bandwidth_queue_name(address)
                bandwidth_rows = queue_by_name.get(bandwidth_queue_name, [])
                if not bandwidth_rows:
                    live_bandwidth = {
                        "address": address,
                        "queue_name": bandwidth_queue_name,
                        "active": False,
                        "valid": True,
                        "max_limit": None,
                        "upload_bps": None,
                        "download_bps": None,
                        "error": None,
                    }
                elif len(bandwidth_rows) != 1:
                    live_bandwidth = {
                        "address": address,
                        "queue_name": bandwidth_queue_name,
                        "active": True,
                        "valid": False,
                        "max_limit": None,
                        "upload_bps": None,
                        "download_bps": None,
                        "error": f"Expected at most one {bandwidth_queue_name} queue, found {len(bandwidth_rows)}",
                    }
                else:
                    row = bandwidth_rows[0]
                    target = str(row.get("target") or "")
                    max_limit = str(row.get("max-limit") or row.get("max_limit") or "")
                    queue_type = str(row.get("queue") or "")
                    problems = []
                    if target != f"{address}/32":
                        problems.append(f"target={target!r}, expected {address + '/32'!r}")
                    if _ros_bool(row.get("disabled", False)):
                        problems.append("queue is disabled")
                    if queue_type and queue_type != "default-small/default-small":
                        problems.append(
                            f"queue={queue_type!r}, expected 'default-small/default-small'"
                        )
                    upload_bps = download_bps = None
                    try:
                        upload_bps, download_bps = parse_max_limit(max_limit)
                    except BandwidthRateError as exc:
                        problems.append(str(exc))
                    live_bandwidth = {
                        "address": address,
                        "queue_name": bandwidth_queue_name,
                        "active": True,
                        "valid": not problems,
                        "max_limit": max_limit or None,
                        "upload_bps": upload_bps,
                        "download_bps": download_bps,
                        "comment": row.get("comment") or "",
                        "error": "; ".join(problems) if problems else None,
                    }

                services = {}
                blocked_services = []
                unavailable_services = []
                for key, service in catalog.items():
                    entries = service_by_address.get(key, {}).get(address, [])
                    contract = contract_state[key]
                    available = bool(contract["available"])
                    error = contract.get("error")
                    if len(entries) > 1:
                        available = False
                        error = f"Multiple {service['source_list']} entries found for {address}"
                    if not available:
                        unavailable_services.append(key)
                    is_blocked = len(entries) == 1
                    if is_blocked:
                        blocked_services.append(key)
                    services[key] = {
                        "name": service["name"],
                        "available": available,
                        "error": error,
                        "blocked": is_blocked,
                        "entries": len(entries),
                        "source_list": service["source_list"],
                        "classification": service.get("classification", "TLS/SNI"),
                        "coverage_note": service.get("coverage_note", ""),
                        "detector_lists": [rule["detector_list"] for rule in service["rules"]],
                    }
                live_services = {
                    "address": address,
                    "blocked_services": sorted(blocked_services),
                    "unavailable_services": sorted(set(unavailable_services)),
                    "services": services,
                }

                states[address] = {
                    "live_enforcement": live_enforcement,
                    "live_services": live_services,
                    "live_bandwidth": live_bandwidth,
                }

            return {
                "devices": devices,
                "states": states,
                "query_plan": {
                    "restricted_list_reads": 1,
                    "mode_list_reads": 2,
                    "service_source_list_reads": len(catalog),
                    "queue_reads": 1,
                    "device_authority_validations": 1,
                    "service_authority_validations": 0 if health_map else len(catalog),
                    "cross_request_cache": False,
                    "write_validation_source": False,
                },
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to read managed-device observation snapshot: {exc}") from exc
        finally:
            pool.disconnect()

    def get_device_service_enforcement(self, address: str, service_catalog=None) -> dict:
        """Read live membership for the current approved concrete service catalogue."""
        address = self._validate_ipv4(address)
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        pool, api = self._connect()
        try:
            self._validate_restricted_device(api, address)
            address_list = api.get_resource("/ip/firewall/address-list")
            services = {}
            blocked_services = []
            unavailable_services = []
            for service_key, service in catalog.items():
                try:
                    self._validate_service_primitive(api, service_key, catalog)
                    available = True
                    contract_error = None
                except RouterError as exc:
                    available = False
                    contract_error = str(exc)
                    unavailable_services.append(service_key)
                entries = address_list.get(list=service["source_list"], address=address)
                if len(entries) > 1:
                    available = False
                    contract_error = f"Multiple {service['source_list']} entries found for {address}"
                    unavailable_services.append(service_key)
                blocked = len(entries) == 1
                if blocked:
                    blocked_services.append(service_key)
                services[service_key] = {
                    "name": service["name"], "available": available,
                    "error": contract_error, "blocked": blocked, "entries": len(entries),
                    "source_list": service["source_list"],
                    "classification": service.get("classification", "TLS/SNI"),
                    "coverage_note": service.get("coverage_note", ""),
                    "detector_lists": [rule["detector_list"] for rule in service["rules"]],
                }
            return {
                "address": address,
                "blocked_services": sorted(blocked_services),
                "unavailable_services": sorted(set(unavailable_services)),
                "services": services,
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to read service enforcement for {address}: {exc}") from exc
        finally:
            pool.disconnect()

    def set_device_services(self, address: str, blocked_services, description: str = "", service_catalog=None) -> dict:
        """Reconcile source-list membership for the current approved service catalogue."""
        address = self._validate_ipv4(address)
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        supported_keys = frozenset(catalog)
        desired = {str(value).strip().lower() for value in blocked_services}
        unsupported = desired - supported_keys
        if unsupported:
            raise RouterError("Unsupported live service key(s): " + ", ".join(sorted(unsupported)))
        description = description.strip()[:60]
        self._require_policy_write_gate()
        pool, api = self._connect()
        try:
            self._validate_restricted_device(api, address)
            address_list = api.get_resource("/ip/firewall/address-list")
            planned = []
            for service_key, service in catalog.items():
                entries = address_list.get(list=service["source_list"], address=address)
                should_block = service_key in desired
                needs_change = (should_block and len(entries) != 1) or (not should_block and len(entries) != 0)
                if not needs_change:
                    continue
                self._validate_service_primitive(api, service_key, catalog)
                planned.append((service_key, service, entries, should_block))
            newly_blocked = []
            # Fail restrictive across multi-service transitions: establish every
            # newly requested block before releasing any no-longer-requested block.
            # A mid-write RouterOS/API failure therefore cannot fail open for a
            # service that was supposed to become blocked in this transaction.
            for service_key, service, entries, should_block in planned:
                if not should_block:
                    continue
                for entry in entries:
                    entry_id = self._entry_id(entry)
                    if entry_id:
                        address_list.remove(id=entry_id)
                comment = f"MC - Block {service['name']}"
                if description:
                    comment += f" - {description}"
                address_list.add(list=service["source_list"], address=address, comment=comment)
                newly_blocked.append(service_key)

            for service_key, service, entries, should_block in planned:
                if should_block:
                    continue
                for entry in entries:
                    entry_id = self._entry_id(entry)
                    if entry_id:
                        address_list.remove(id=entry_id)
            terminated_connections = self._terminate_service_connections(
                api, address, newly_blocked, service_catalog=catalog
            )
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to set service policy for {address}: {exc}") from exc
        finally:
            pool.disconnect()
        result = self.get_device_service_enforcement(address, service_catalog=catalog)
        actual = set(result["blocked_services"])
        if actual != desired:
            missing_contracts = [
                key for key in desired
                if not result["services"].get(key, {}).get("available", False)
            ]
            suffix = "; unavailable contract(s): " + ", ".join(missing_contracts) if missing_contracts else ""
            raise RouterError(
                f"Requested service policy {sorted(desired)} but RouterOS reports {sorted(actual)} for {address}{suffix}"
            )
        result["terminated_connections"] = terminated_connections
        return result

    @staticmethod
    def _terminate_service_connections(api, address: str, service_keys, service_catalog=None) -> int:
        """Best-effort targeted connection reset for newly blocked services."""
        catalog = SERVICE_ENFORCEMENT if service_catalog is None else service_catalog
        service_keys = set(service_keys)
        if not service_keys:
            return 0
        address_list = api.get_resource("/ip/firewall/address-list")
        detector_addresses = set()
        for service_key in service_keys:
            service = catalog[service_key]
            for rule in service["rules"]:
                for entry in address_list.get(list=rule["detector_list"]):
                    detected = str(entry.get("address", "")).strip()
                    if detected:
                        detector_addresses.add(detected.split("/", 1)[0])
        if not detector_addresses:
            return 0
        connections = api.get_resource("/ip/firewall/connection")
        removed = 0
        try:
            for connection in connections.get():
                source = str(connection.get("src-address", "")).strip()
                destination = str(connection.get("dst-address", "")).strip()
                if source != address or destination not in detector_addresses:
                    continue
                connection_id = RouterOSAdapter._entry_id(connection)
                if connection_id:
                    connections.remove(id=connection_id)
                    removed += 1
        except Exception:
            return removed
        return removed

    def _validate_device_block_primitive(self, api) -> dict:
        """
        Verify that the router-side MC per-device block primitive exists
        and is enabled.

        The application never creates or reorders this firewall rule
        implicitly.
        """
        firewall = api.get_resource("/ip/firewall/filter")
        rules = firewall.get(comment=self.DEVICE_BLOCK_RULE_COMMENT)

        if len(rules) != 1:
            raise RouterError(
                f"Expected exactly one '{self.DEVICE_BLOCK_RULE_COMMENT}' rule, "
                f"found {len(rules)}"
            )

        rule = rules[0]
        enabled = not _ros_bool(rule.get("disabled", False))

        if not enabled:
            raise RouterError(
                f"'{self.DEVICE_BLOCK_RULE_COMMENT}' exists but is disabled"
            )

        return {
            "enabled": True,
            "rule_id": rule.get("id"),
        }

    def _validate_restricted_device(self, api, address: str) -> dict:
        """
        Live per-device enforcement is allowed only for an address already
        owned by ZEN Control through static Restricted_Devices membership.
        """
        entries = api.get_resource("/ip/firewall/address-list").get(
            list=self.RESTRICTED_LIST,
            address=address,
        )

        static_entries = [
            entry
            for entry in entries
            if not _ros_bool(entry.get("dynamic", False))
        ]

        if len(static_entries) != 1:
            raise RouterError(
                f"{address} is not exactly one static "
                f"{self.RESTRICTED_LIST} member"
            )

        return static_entries[0]

    @classmethod
    def _device_slow_queue_name(cls, address: str) -> str:
        return cls.DEVICE_SLOW_QUEUE_PREFIX + address.replace(".", "-")

    @classmethod
    def _device_bandwidth_queue_name(cls, address: str) -> str:
        return cls.DEVICE_BANDWIDTH_QUEUE_PREFIX + address.replace(".", "-")

    @classmethod
    def _device_temp_scheduler_name(cls, address: str) -> str:
        return cls.DEVICE_TEMP_SCHED_PREFIX + address.replace(".", "-")

    @classmethod
    def _device_temp_script_name(cls, address: str) -> str:
        return cls.DEVICE_TEMP_SCRIPT_PREFIX + address.replace(".", "-")

    @staticmethod
    def _parse_device_temp_comment(comment: str) -> dict:
        """Parse the app-owned per-device temporary scheduler metadata."""
        parts = str(comment or "").split("|")
        if len(parts) < 4 or parts[:2] != ["MC", "TEMP_DEVICE"]:
            return {}

        result = {"address": parts[2]}
        for part in parts[3:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            result[key.strip()] = value.strip()
        return result

    def _device_temp_restore_source(self, address: str, restore_mode: str) -> str:
        """Build a bounded RouterOS restore script for one managed device.

        The script only touches the same MC per-device mode resources already
        owned by the adapter. It intentionally does not touch service policy or
        Kid Control. Automatic reconciliation will converge any policy changes that
        occurred while temporary access was active after the scheduler fires.
        """
        address = self._validate_ipv4(address)
        restore_mode = str(restore_mode or "").strip().lower()
        if restore_mode not in {"normal", "slow", "blocked"}:
            raise RouterError(f"Invalid temporary restore mode '{restore_mode}'")

        try:
            parse_max_limit(self.device_slow_limit)
        except BandwidthRateError as exc:
            raise RouterError(
                f"Invalid MIKROTIK_DEVICE_SLOW_LIMIT '{self.device_slow_limit}': {exc}"
            ) from exc

        slow_queue = self._device_slow_queue_name(address)
        bandwidth_queue = self._device_bandwidth_queue_name(address)
        quoted_ip = f'"{address}"'

        remove_block = (
            f':foreach i in=[/ip firewall address-list find where list="{self.DEVICE_BLOCK_LIST}" '
            f'and address={quoted_ip}] do={{ /ip firewall address-list remove $i }};'
        )
        remove_slow_list = (
            f':foreach i in=[/ip firewall address-list find where list="{self.DEVICE_SLOW_LIST}" '
            f'and address={quoted_ip}] do={{ /ip firewall address-list remove $i }};'
        )
        remove_slow_queue = (
            f':foreach i in=[/queue simple find where name="{slow_queue}"] '
            f'do={{ /queue simple remove $i }};'
        )
        remove_bandwidth_queue = (
            f':foreach i in=[/queue simple find where name="{bandwidth_queue}"] '
            f'do={{ /queue simple remove $i }};'
        )

        if restore_mode == "normal":
            return remove_block + remove_slow_list + remove_slow_queue

        if restore_mode == "blocked":
            ensure_block = (
                f':if ([:len [/ip firewall address-list find where list="{self.DEVICE_BLOCK_LIST}" '
                f'and address={quoted_ip}]] = 0) do={{ /ip firewall address-list add '
                f'list="{self.DEVICE_BLOCK_LIST}" address={quoted_ip} '
                f'comment="MC - Temp Restore Block" }};'
            )
            # Fail closed: establish BLOCKED before releasing/removing SLOW.
            return ensure_block + remove_slow_list + remove_slow_queue + remove_bandwidth_queue

        ensure_slow_queue = (
            remove_slow_queue
            + f'/queue simple add name="{slow_queue}" target="{address}/32" '
              f'max-limit="{self.device_slow_limit}" queue="default-small/default-small" '
              f'comment="MC - Temp Restore Slow" disabled=no;'
        )
        ensure_slow_list = (
            remove_slow_list
            + f'/ip firewall address-list add list="{self.DEVICE_SLOW_LIST}" '
              f'address={quoted_ip} comment="MC - Temp Restore Slow";'
        )
        # Build SLOW fully before releasing BLOCKED, mirroring set_device_mode().
        return (
            ensure_slow_queue
            + ensure_slow_list
            + remove_bandwidth_queue
            + remove_block
        )

    def _cleanup_device_temp_resources(self, api, address: str) -> dict:
        """Remove only the scheduler/script names owned for this device."""
        scheduler_name = self._device_temp_scheduler_name(address)
        script_name = self._device_temp_script_name(address)
        sched = api.get_resource("/system/scheduler")
        scripts = api.get_resource("/system/script")
        removed_scheduler = 0
        removed_script = 0

        for entry in sched.get(name=scheduler_name):
            entry_id = entry.get("id")
            if entry_id:
                sched.remove(id=entry_id)
                removed_scheduler += 1

        for entry in scripts.get(name=script_name):
            entry_id = entry.get("id")
            if entry_id:
                scripts.remove(id=entry_id)
                removed_script += 1

        return {
            "removed_scheduler": removed_scheduler,
            "removed_script": removed_script,
        }

    def get_device_temporary_access(self, address: str) -> dict:
        """Read one RouterOS-backed temporary NORMAL override.

        A one-shot RouterOS scheduler executes the restore script, so expiry is
        independent of this web application and of the background reconciliation worker.
        """
        address = self._validate_ipv4(address)
        scheduler_name = self._device_temp_scheduler_name(address)
        script_name = self._device_temp_script_name(address)

        pool, api = self._connect()
        try:
            self._validate_restricted_device(api, address)
            sched = api.get_resource("/system/scheduler")
            scripts = api.get_resource("/system/script")
            matches = sched.get(name=scheduler_name)
            script_matches = scripts.get(name=script_name)

            if len(matches) > 1:
                raise RouterError(
                    f"Expected at most one {scheduler_name} scheduler, found {len(matches)}"
                )
            if len(script_matches) > 1:
                raise RouterError(
                    f"Expected at most one {script_name} script, found {len(script_matches)}"
                )

            if not matches:
                # A script without its scheduler is an app-owned stale artifact.
                for entry in script_matches:
                    if entry.get("id"):
                        scripts.remove(id=entry["id"])
                return {
                    "active": False,
                    "address": address,
                    "scheduler_name": scheduler_name,
                }

            entry = matches[0]
            metadata = self._parse_device_temp_comment(entry.get("comment", ""))
            if metadata.get("address") not in {None, "", address}:
                raise RouterError(
                    f"{scheduler_name} metadata belongs to {metadata.get('address')}, not {address}"
                )

            restore_mode = str(metadata.get("restore") or "unknown").lower()
            try:
                minutes = int(metadata.get("minutes") or 0)
            except (TypeError, ValueError):
                minutes = 0

            run_count = int(entry.get("run-count", "0") or 0)
            disabled = _ros_bool(entry.get("disabled", False))
            restore_time = (
                f"{entry.get('start-date', '')} {str(entry.get('start-time', ''))[:8]}".strip()
            )

            if run_count > 0:
                self._cleanup_device_temp_resources(api, address)
                return {
                    "active": False,
                    "expired": True,
                    "address": address,
                    "restore_mode": restore_mode,
                    "restore_time": restore_time,
                    "reference": metadata.get("reference"),
                    "scheduler_name": scheduler_name,
                }

            if disabled:
                # Disabled temp schedulers cannot provide a fail-safe expiry.
                self._cleanup_device_temp_resources(api, address)
                return {
                    "active": False,
                    "disabled": True,
                    "address": address,
                    "restore_mode": restore_mode,
                    "reference": metadata.get("reference"),
                    "scheduler_name": scheduler_name,
                }

            if restore_mode not in {"normal", "slow", "blocked"}:
                raise RouterError(
                    f"{scheduler_name} has invalid restore mode '{restore_mode}'"
                )

            if len(script_matches) != 1:
                raise RouterError(
                    f"Active {scheduler_name} requires exactly one {script_name} restore script"
                )

            return {
                "active": True,
                "address": address,
                "minutes": minutes,
                "restore_mode": restore_mode,
                "restore_time": restore_time,
                "restore_at": restore_time,
                "started_at": metadata.get("started"),
                "reference": metadata.get("reference"),
                "scheduler_name": scheduler_name,
                "script_name": script_name,
                "fail_safe": "RouterOS scheduler",
            }

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to read temporary access for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

    def set_device_temporary_normal(
        self,
        address: str,
        minutes: int,
        description: str = "",
        restore_mode: str | None = None,
        reference: str = "",
    ) -> dict:
        """Grant temporary per-device NORMAL mode with RouterOS fail-safe restore."""
        address = self._validate_ipv4(address)
        try:
            minutes = int(minutes)
        except (TypeError, ValueError) as exc:
            raise RouterError("Temporary access duration must be a number") from exc
        if minutes not in self.DEVICE_TEMP_DURATIONS:
            raise RouterError("Temporary access supports 15, 30 or 60 minutes")

        if restore_mode is not None and str(restore_mode).strip().lower() not in {"normal", "slow", "blocked"}:
            raise RouterError("Invalid restore mode")
        description = str(description or "").strip()[:40]
        reference = str(reference or "").strip()
        if reference and (len(reference) > 80 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", reference)):
            raise RouterError("Temporary access reference contains invalid characters")
        self._require_policy_write_gate()
        existing = self.get_device_temporary_access(address)
        current = self.get_device_enforcement(address)

        if current.get("mode") not in {"normal", "slow", "blocked"}:
            raise RouterError(
                f"Cannot start temporary access from invalid device state '{current.get('mode')}'"
            )

        # Extending an existing override must retain the original restore state,
        # not capture the currently-temporary NORMAL state. For a new override
        # callers may supply the effective desired mode so RouterOS fails back
        # to policy rather than merely to whatever live state happened to exist.
        requested_restore_mode = (
            str(restore_mode).strip().lower() if restore_mode is not None else None
        )
        restore_mode = (
            existing.get("restore_mode")
            if existing.get("active")
            else (requested_restore_mode or current["mode"])
        )
        if restore_mode not in {"normal", "slow", "blocked"}:
            raise RouterError(f"Invalid temporary restore mode '{restore_mode}'")

        target = datetime.now(ZoneInfo(self.timezone)) + timedelta(minutes=minutes)
        scheduler_name = self._device_temp_scheduler_name(address)
        script_name = self._device_temp_script_name(address)
        restore_source = self._device_temp_restore_source(address, restore_mode)
        started = datetime.now(ZoneInfo(self.timezone)).isoformat(timespec="seconds")
        # For a new reward-backed override, bind the durable redemption reference
        # only *after* NORMAL has been written and freshly verified. Before that
        # point the scheduler is merely a prepared fail-safe and must not be used
        # as proof that reward access was actually granted. Existing active
        # overrides keep their already-proven reference when extended.
        effective_reference = (
            str(existing.get("reference") or "").strip()
            if existing.get("active")
            else ""
        )

        def temp_comment(bound_reference=""):
            value = (
                f"MC|TEMP_DEVICE|{address}|restore={restore_mode}|minutes={minutes}|started={started}"
            )
            if bound_reference:
                value += f"|reference={bound_reference}"
            return value

        comment = temp_comment(effective_reference)

        pool, api = self._connect()
        try:
            self._validate_device_block_primitive(api)
            self._validate_restricted_device(api, address)

            scripts = api.get_resource("/system/script")
            sched = api.get_resource("/system/scheduler")

            if existing.get("active"):
                # Extend in place. Never remove the existing fail-safe before the
                # replacement expiry has been committed: an API failure must leave
                # the previous scheduler/script capable of restoring the device.
                scheduler_matches = sched.get(name=scheduler_name)
                script_matches = scripts.get(name=script_name)
                if len(scheduler_matches) != 1 or len(script_matches) != 1:
                    raise RouterError(
                        f"Cannot safely extend temporary access for {address}: "
                        "the existing fail-safe contract is incomplete"
                    )
                scripts.set(
                    id=self._entry_id(script_matches[0]),
                    comment=f"MC temporary restore for {address}",
                    source=restore_source,
                    policy="read,write,test",
                )
                sched.set(
                    id=self._entry_id(scheduler_matches[0]),
                    comment=comment,
                    start_date=target.strftime("%b/%d/%Y").lower(),
                    start_time=target.strftime("%H:%M:%S"),
                    interval="0s",
                    on_event=script_name,
                    policy="read,write,test",
                    disabled="false",
                )
            else:
                # A new override may clean stale app-owned artefacts first because
                # there is no active fail-safe to preserve.
                self._cleanup_device_temp_resources(api, address)
                scripts.add(
                    name=script_name,
                    comment=f"MC temporary restore for {address}",
                    source=restore_source,
                    policy="read,write,test",
                )
                sched.add(
                    name=scheduler_name,
                    comment=comment,
                    start_date=target.strftime("%b/%d/%Y").lower(),
                    start_time=target.strftime("%H:%M:%S"),
                    interval="0s",
                    on_event=script_name,
                    policy="read,write,test",
                    disabled="false",
                )
        except RouterError:
            raise
        except Exception as exc:
            if not existing.get("active"):
                try:
                    self._cleanup_device_temp_resources(api, address)
                except Exception:
                    pass
            operation = "extend" if existing.get("active") else "create"
            raise RouterError(
                f"Unable to {operation} temporary access fail-safe for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        try:
            self.set_device_mode(
                address,
                "normal",
                description=(description or "temporary access"),
            )
        except Exception:
            # New overrides have not granted access if the validated mode write
            # failed, so their prepared resources can be removed. Extensions are
            # different: preserve the previous fail-safe rather than destroying
            # an already-active override on an extension failure.
            if not existing.get("active"):
                try:
                    pool, api = self._connect()
                    self._cleanup_device_temp_resources(api, address)
                    pool.disconnect()
                except Exception:
                    pass
            raise

        if reference and not existing.get("active"):
            # The reference becomes recovery evidence only after set_device_mode
            # has completed its own fresh post-write validation. If this metadata
            # write fails, keep the working RouterOS fail-safe and let the reward
            # reservation remain pending rather than refunding potentially-used
            # access.
            pool, api = self._connect()
            try:
                sched = api.get_resource("/system/scheduler")
                matches = sched.get(name=scheduler_name)
                if len(matches) != 1:
                    raise RouterError(
                        f"Temporary access was granted for {address}, but its recovery reference "
                        f"could not be bound because {len(matches)} schedulers were found"
                    )
                sched.set(id=self._entry_id(matches[0]), comment=temp_comment(reference))
                effective_reference = reference
            except RouterError:
                raise
            except Exception as exc:
                raise RouterError(
                    f"Temporary access was granted for {address}, but binding recovery reference failed: {exc}"
                ) from exc
            finally:
                pool.disconnect()

        result = self.get_device_temporary_access(address)
        if not result.get("active"):
            raise RouterError(
                f"Temporary access scheduler did not become active for {address}"
            )
        result["extended"] = bool(existing.get("active"))
        result["previous_mode"] = current.get("mode")
        result["restore_mode"] = restore_mode
        result["reference"] = effective_reference or None
        result["restore_at_iso"] = target.isoformat(timespec="seconds")
        return result

    def cancel_device_temporary_access(
        self,
        address: str,
        *,
        restore: bool = True,
    ) -> dict:
        """Cancel a device override and optionally restore its captured mode now."""
        address = self._validate_ipv4(address)
        state = self.get_device_temporary_access(address)
        if not state.get("active"):
            return {
                "address": address,
                "removed": False,
                "restored": False,
                "restore_mode": state.get("restore_mode"),
            }

        restore_mode = state.get("restore_mode")
        scheduler_name = self._device_temp_scheduler_name(address)

        # Disable the fail-safe before performing an immediate restore so it
        # cannot race an operator cancellation. The resources are removed only
        # after the requested restoration succeeds.
        pool, api = self._connect()
        try:
            sched = api.get_resource("/system/scheduler")
            matches = sched.get(name=scheduler_name)
            if len(matches) != 1:
                raise RouterError(
                    f"Expected exactly one active {scheduler_name} scheduler, found {len(matches)}"
                )
            sched.set(id=matches[0]["id"], disabled="true")
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to disable temporary scheduler for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        if restore:
            try:
                self.set_device_mode(
                    address,
                    restore_mode,
                    description="temporary access cancelled",
                )
            except Exception:
                # Re-enable the scheduler when possible so a failed cancel does
                # not discard the RouterOS restore safety net.
                try:
                    pool, api = self._connect()
                    sched = api.get_resource("/system/scheduler")
                    for entry in sched.get(name=scheduler_name):
                        sched.set(id=entry["id"], disabled="false")
                    pool.disconnect()
                except Exception:
                    pass
                raise

        pool, api = self._connect()
        try:
            removed = self._cleanup_device_temp_resources(api, address)
        except Exception as exc:
            raise RouterError(
                f"Temporary mode restored for {address}, but cleanup failed: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        return {
            "address": address,
            "removed": True,
            "restored": bool(restore),
            "restore_mode": restore_mode,
            **removed,
        }

    def get_device_bandwidth(self, address: str) -> dict:
        """Read the app-managed per-device profile bandwidth queue."""
        address = self._validate_ipv4(address)
        queue_name = self._device_bandwidth_queue_name(address)

        pool, api = self._connect()
        try:
            self._validate_restricted_device(api, address)
            queues = api.get_resource("/queue/simple")
            entries = queues.get(name=queue_name)

            if len(entries) == 0:
                return {
                    "address": address,
                    "queue_name": queue_name,
                    "active": False,
                    "valid": True,
                    "max_limit": None,
                    "upload_bps": None,
                    "download_bps": None,
                    "error": None,
                }

            if len(entries) != 1:
                return {
                    "address": address,
                    "queue_name": queue_name,
                    "active": True,
                    "valid": False,
                    "max_limit": None,
                    "upload_bps": None,
                    "download_bps": None,
                    "error": f"Expected at most one {queue_name} queue, found {len(entries)}",
                }

            entry = entries[0]
            target = str(entry.get("target") or "")
            max_limit = str(entry.get("max-limit") or entry.get("max_limit") or "")
            queue_type = str(entry.get("queue") or "")
            disabled = _ros_bool(entry.get("disabled", False))
            expected_target = f"{address}/32"
            problems = []

            if target != expected_target:
                problems.append(f"target={target!r}, expected {expected_target!r}")
            if disabled:
                problems.append("queue is disabled")
            if queue_type and queue_type != "default-small/default-small":
                problems.append(
                    f"queue={queue_type!r}, expected 'default-small/default-small'"
                )

            upload_bps = None
            download_bps = None
            try:
                upload_bps, download_bps = parse_max_limit(max_limit)
            except BandwidthRateError as exc:
                problems.append(str(exc))

            return {
                "address": address,
                "queue_name": queue_name,
                "active": True,
                "valid": not problems,
                "max_limit": max_limit or None,
                "upload_bps": upload_bps,
                "download_bps": download_bps,
                "comment": entry.get("comment") or "",
                "error": "; ".join(problems) if problems else None,
            }

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to read device bandwidth for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

    def set_device_bandwidth(
        self,
        address: str,
        preset_key: str,
        upload: str,
        download: str,
        description: str = "",
    ) -> dict:
        """Synchronize one app-managed profile bandwidth queue.

        The ``normal`` preset means no MC-BW queue. Other presets create one
        simple queue named ``MC-BW-<IP>``. This queue is intentionally separate
        from the existing ``MC-SLOW-<IP>`` mode queue.
        """
        address = self._validate_ipv4(address)
        preset_key = str(preset_key or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{1,40}", preset_key):
            raise RouterError(f"Invalid bandwidth preset key '{preset_key}'")

        description = description.strip()[:50]
        queue_name = self._device_bandwidth_queue_name(address)
        expected_limit = None

        if preset_key != "normal":
            try:
                expected_limit = build_max_limit(upload, download)
            except BandwidthRateError as exc:
                raise RouterError(str(exc)) from exc

        self._require_policy_write_gate()
        pool, api = self._connect()
        try:
            self._validate_restricted_device(api, address)
            queues = api.get_resource("/queue/simple")
            entries = queues.get(name=queue_name)

            def remove_all() -> None:
                for entry in queues.get(name=queue_name):
                    entry_id = entry.get("id")
                    if entry_id:
                        queues.remove(id=entry_id)

            if preset_key == "normal":
                remove_all()
            else:
                comment = f"MC - Policy Bandwidth - preset:{preset_key}"
                if description:
                    comment += f" - {description}"

                if len(entries) == 1:
                    queues.set(
                        id=entries[0]["id"],
                        target=f"{address}/32",
                        max_limit=expected_limit,
                        queue="default-small/default-small",
                        comment=comment,
                        disabled="false",
                    )
                else:
                    remove_all()
                    queues.add(
                        name=queue_name,
                        target=f"{address}/32",
                        max_limit=expected_limit,
                        queue="default-small/default-small",
                        comment=comment,
                        disabled="false",
                    )

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to set device bandwidth for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        result = self.get_device_bandwidth(address)
        if preset_key == "normal":
            if result.get("active"):
                raise RouterError(
                    f"Requested unlimited bandwidth but {queue_name} still exists"
                )
            return result

        if not result.get("valid") or not result.get("active"):
            raise RouterError(
                f"Bandwidth queue did not converge for {address}: "
                f"{result.get('error') or 'queue missing'}"
            )
        if not limits_equal(result.get("max_limit"), expected_limit):
            raise RouterError(
                f"Requested max-limit {expected_limit} but router reports "
                f"{result.get('max_limit')} for {address}"
            )
        return result

    def get_device_enforcement(self, address: str) -> dict:
        """
        Read the live MC-managed per-device state.

        Valid states:
          normal
          slow
          blocked

        Partial or conflicting managed resources are surfaced as invalid.
        """
        address = self._validate_ipv4(address)

        pool, api = self._connect()
        try:
            self._validate_device_block_primitive(api)
            self._validate_restricted_device(api, address)

            address_list = api.get_resource("/ip/firewall/address-list")
            queues = api.get_resource("/queue/simple")

            blocked_entries = address_list.get(
                list=self.DEVICE_BLOCK_LIST,
                address=address,
            )

            slow_entries = address_list.get(
                list=self.DEVICE_SLOW_LIST,
                address=address,
            )

            queue_name = self._device_slow_queue_name(address)
            slow_queues = queues.get(name=queue_name)

            if (
                len(blocked_entries) == 0
                and len(slow_entries) == 0
                and len(slow_queues) == 0
            ):
                mode = "normal"

            elif (
                len(blocked_entries) == 1
                and len(slow_entries) == 0
                and len(slow_queues) == 0
            ):
                mode = "blocked"

            elif (
                len(blocked_entries) == 0
                and len(slow_entries) == 1
                and len(slow_queues) == 1
                and not _ros_bool(slow_queues[0].get("disabled", False))
            ):
                mode = "slow"

            else:
                mode = "invalid"

            return {
                "address": address,
                "mode": mode,
                "blocked": mode == "blocked",
                "slow": mode == "slow",
                "blocked_entries": len(blocked_entries),
                "slow_entries": len(slow_entries),
                "slow_queues": len(slow_queues),
                "slow_queue": queue_name,
                "slow_limit": (
                    slow_queues[0].get("max-limit")
                    if len(slow_queues) == 1
                    else None
                ),
            }

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to read device enforcement for {address}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

    def set_device_mode(
        self,
        address: str,
        mode: str,
        description: str = "",
    ) -> dict:
        """
        Apply one mutually-exclusive live enforcement state.

        Managed resources:
          MC_Mode_Blocked
          MC_Mode_Slow
          MC-SLOW-<IP>
        """
        address = self._validate_ipv4(address)
        mode = mode.strip().lower()

        if mode not in {"normal", "slow", "blocked"}:
            raise RouterError(
                f"Invalid device mode '{mode}'. "
                "Expected normal, slow or blocked."
            )

        description = description.strip()[:60]
        self._require_policy_write_gate()
        queue_name = self._device_slow_queue_name(address)
        bandwidth_queue_name = self._device_bandwidth_queue_name(address)

        pool, api = self._connect()
        try:
            self._validate_device_block_primitive(api)
            self._validate_restricted_device(api, address)

            address_list = api.get_resource("/ip/firewall/address-list")
            queues = api.get_resource("/queue/simple")

            def remove_list_entries(list_name: str) -> None:
                entries = address_list.get(
                    list=list_name,
                    address=address,
                )
                for entry in entries:
                    entry_id = entry.get("id")
                    if entry_id:
                        address_list.remove(id=entry_id)

            def remove_slow_queues() -> None:
                entries = queues.get(name=queue_name)
                for entry in entries:
                    entry_id = entry.get("id")
                    if entry_id:
                        queues.remove(id=entry_id)

            def remove_policy_bandwidth_queues() -> None:
                entries = queues.get(name=bandwidth_queue_name)
                for entry in entries:
                    entry_id = entry.get("id")
                    if entry_id:
                        queues.remove(id=entry_id)

            if mode == "normal":
                remove_list_entries(self.DEVICE_BLOCK_LIST)
                remove_list_entries(self.DEVICE_SLOW_LIST)
                remove_slow_queues()

            elif mode == "blocked":
                # Establish BLOCKED before removing SLOW. A failed transition
                # therefore does not accidentally fail open.
                blocked_entries = address_list.get(
                    list=self.DEVICE_BLOCK_LIST,
                    address=address,
                )

                if len(blocked_entries) != 1:
                    remove_list_entries(self.DEVICE_BLOCK_LIST)

                    comment = "MC - Device Block"
                    if description:
                        comment += f" - {description}"

                    address_list.add(
                        list=self.DEVICE_BLOCK_LIST,
                        address=address,
                        comment=comment,
                    )

                remove_list_entries(self.DEVICE_SLOW_LIST)
                remove_slow_queues()
                remove_policy_bandwidth_queues()

            elif mode == "slow":
                # Construct/repair SLOW completely while any existing BLOCKED
                # state is still active. BLOCKED is removed only at the end.
                queue_comment = "MC - Per Device Slow"
                if description:
                    queue_comment += f" - {description}"

                slow_queues = queues.get(name=queue_name)

                if len(slow_queues) == 1:
                    queues.set(
                        id=slow_queues[0]["id"],
                        target=f"{address}/32",
                        max_limit=self.device_slow_limit,
                        queue="default-small/default-small",
                        comment=queue_comment,
                        disabled="false",
                    )
                else:
                    remove_slow_queues()

                    queues.add(
                        name=queue_name,
                        target=f"{address}/32",
                        max_limit=self.device_slow_limit,
                        queue="default-small/default-small",
                        comment=queue_comment,
                        disabled="false",
                    )

                slow_entries = address_list.get(
                    list=self.DEVICE_SLOW_LIST,
                    address=address,
                )

                if len(slow_entries) != 1:
                    remove_list_entries(self.DEVICE_SLOW_LIST)

                    list_comment = "MC - Device Slow"
                    if description:
                        list_comment += f" - {description}"

                    address_list.add(
                        list=self.DEVICE_SLOW_LIST,
                        address=address,
                        comment=list_comment,
                    )

                # SLOW is fully constructed; remove any profile bandwidth
                # queue so two simple queues never compete for the same target.
                remove_policy_bandwidth_queues()

                # SLOW is fully constructed; release BLOCKED last.
                remove_list_entries(self.DEVICE_BLOCK_LIST)

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(
                f"Unable to set device {address} to {mode}: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        result = self.get_device_enforcement(address)

        if result["mode"] != mode:
            raise RouterError(
                f"Requested device mode '{mode}' but router reports "
                f"'{result['mode']}' for {address}"
            )

        return result

    def _find_mac_for_ip(self, api, address: str) -> tuple[str, dict | None]:
        leases = api.get_resource("/ip/dhcp-server/lease").get(address=address)
        if len(leases) > 1:
            raise RouterError(f"Multiple DHCP leases found for {address}")
        if leases:
            lease = leases[0]
            mac = lease.get("mac-address") or lease.get("active-mac-address")
            if not mac:
                raise RouterError(f"DHCP lease for {address} has no MAC address")
            return mac, lease

        arp_entries = api.get_resource("/ip/arp").get(address=address)
        arp_entries = [entry for entry in arp_entries if entry.get("mac-address")]
        if len(arp_entries) != 1:
            raise RouterError(
                f"No unique DHCP lease or ARP entry found for {address}. "
                "Make sure the device is online and using DHCP."
            )
        return arp_entries[0]["mac-address"], None


    @staticmethod
    def _validate_schedule_label(label: str) -> str:
        value = label.strip()
        if not value:
            raise RouterError("Schedule description is required")
        if len(value) > 50:
            raise RouterError("Schedule description must be 50 characters or fewer")
        if "|" in value:
            raise RouterError("Schedule description cannot contain '|'")
        return value

    @staticmethod
    def _validate_clock_time(value: str) -> str:
        try:
            parsed = datetime.strptime(value.strip(), "%H:%M")
        except ValueError as exc:
            raise RouterError("Time must be HH:MM") from exc
        return parsed.strftime("%H:%M:%S")

    def _next_weekday_date(self, day: str, clock_time: str) -> str:
        day_map = {
            "mon": 0,
            "tue": 1,
            "wed": 2,
            "thu": 3,
            "fri": 4,
            "sat": 5,
            "sun": 6,
        }
        if day not in day_map:
            raise RouterError(f"Unsupported weekday: {day}")

        now = datetime.now(ZoneInfo(self.timezone))
        hour, minute, second = [int(x) for x in clock_time.split(":")]
        days_ahead = (day_map[day] - now.weekday()) % 7
        candidate = (now + timedelta(days=days_ahead)).replace(
            hour=hour,
            minute=minute,
            second=second,
            microsecond=0,
        )
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate.strftime("%b/%d/%Y").lower()

    def get_managed_schedules(self) -> list[dict]:
        pool, api = self._connect()
        try:
            entries = api.get_resource("/system/scheduler").get()
            managed = [
                e for e in entries
                if str(e.get("name", "")).startswith(self.SCHED_PREFIX)
            ]

            groups = {}
            inverse_modes = {v: k for k, v in self.MODE_SCRIPTS.items()}

            for entry in managed:
                name = entry.get("name", "")
                match = re.match(
                    rf"^{re.escape(self.SCHED_PREFIX)}([A-Za-z0-9]+)-"
                    r"(mon|tue|wed|thu|fri|sat|sun)$",
                    name,
                )
                if not match:
                    continue

                group_id, day = match.groups()
                comment = entry.get("comment", "")
                parts = comment.split("|", 3)
                label = parts[2] if len(parts) >= 3 else group_id

                group = groups.setdefault(
                    group_id,
                    {
                        "id": group_id,
                        "label": label,
                        "mode": inverse_modes.get(entry.get("on-event"), "unknown"),
                        "time": str(entry.get("start-time", ""))[:5],
                        "days": [],
                        "enabled": True,
                    },
                )
                group["days"].append(day)
                if _ros_bool(entry.get("disabled", False)):
                    group["enabled"] = False

            order = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
            for group in groups.values():
                group["days"].sort(key=order.index)

            return sorted(groups.values(), key=lambda x: (x["time"], x["label"].lower()))
        except Exception as exc:
            raise RouterError(f"Unable to read managed schedules: {exc}") from exc
        finally:
            pool.disconnect()

    def add_managed_schedule(
        self,
        label: str,
        mode: str,
        clock_time: str,
        days: list[str],
    ) -> dict:
        label = self._validate_schedule_label(label)
        mode = mode.lower()
        if mode not in self.MODE_SCRIPTS:
            raise RouterError("Schedule mode must be normal, slow or blocked")

        clock_time = self._validate_clock_time(clock_time)
        allowed_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        clean_days = []
        for day in days:
            day = day.lower().strip()
            if day not in allowed_days:
                raise RouterError(f"Unsupported weekday: {day}")
            if day not in clean_days:
                clean_days.append(day)
        if not clean_days:
            raise RouterError("Select at least one weekday")

        self._require_policy_write_gate()
        group_id = secrets.token_hex(4)
        script_name = self.MODE_SCRIPTS[mode]

        pool, api = self._connect()
        created_ids = []
        try:
            sched = api.get_resource("/system/scheduler")
            for day in clean_days:
                entry = sched.add(
                    name=f"{self.SCHED_PREFIX}{group_id}-{day}",
                    comment=f"MC|{group_id}|{label}|{mode}",
                    start_date=self._next_weekday_date(day, clock_time),
                    start_time=clock_time,
                    interval="7d",
                    on_event=script_name,
                    policy="read,write,test",
                    disabled="false",
                )
                if isinstance(entry, dict) and entry.get("id"):
                    created_ids.append(entry["id"])
        except Exception as exc:
            # Best-effort rollback of entries created in this request.
            try:
                sched = api.get_resource("/system/scheduler")
                matches = sched.get()
                for item in matches:
                    if str(item.get("name", "")).startswith(
                        f"{self.SCHED_PREFIX}{group_id}-"
                    ):
                        sched.remove(id=item["id"])
            except Exception:
                pass
            raise RouterError(f"Unable to create schedule: {exc}") from exc
        finally:
            pool.disconnect()

        return {
            "id": group_id,
            "label": label,
            "mode": mode,
            "time": clock_time[:5],
            "days": clean_days,
        }

    def remove_managed_schedule(self, group_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9]+", group_id):
            raise RouterError("Invalid schedule id")

        pool, api = self._connect()
        try:
            sched = api.get_resource("/system/scheduler")
            matches = [
                e for e in sched.get()
                if str(e.get("name", "")).startswith(
                    f"{self.SCHED_PREFIX}{group_id}-"
                )
            ]
            if not matches:
                raise RouterError("Managed schedule not found")
            for entry in matches:
                sched.remove(id=entry["id"])
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to remove schedule: {exc}") from exc
        finally:
            pool.disconnect()

        return {"id": group_id, "removed": True}

    def get_temporary_access(self) -> dict:
        pool, api = self._connect()
        try:
            sched = api.get_resource("/system/scheduler")
            matches = sched.get(name=self.TEMP_SCHED_NAME)
            if not matches:
                return {"active": False}

            entry = matches[0]
            run_count = int(entry.get("run-count", "0") or 0)

            # Once RouterOS has executed the restore, clean up the stale entry.
            if run_count > 0:
                sched.remove(id=entry["id"])
                return {"active": False}

            return {
                "active": not _ros_bool(entry.get("disabled", False)),
                "restore_script": entry.get("on-event"),
                "start_date": entry.get("start-date"),
                "start_time": entry.get("start-time"),
            }
        except Exception as exc:
            raise RouterError(f"Unable to read temporary access state: {exc}") from exc
        finally:
            pool.disconnect()

    def set_temporary_normal(self, minutes: int, restore_mode: str) -> dict:
        if minutes not in {15, 30, 60}:
            raise RouterError("Temporary access supports 15, 30 or 60 minutes")

        restore_mode = restore_mode.lower()
        if restore_mode not in self.MODE_SCRIPTS:
            raise RouterError("Invalid restore mode")

        self._require_policy_write_gate()
        restore_script = self.MODE_SCRIPTS[restore_mode]
        target = datetime.now(ZoneInfo(self.timezone)) + timedelta(minutes=minutes)

        pool, api = self._connect()
        try:
            sched = api.get_resource("/system/scheduler")
            for old in sched.get(name=self.TEMP_SCHED_NAME):
                sched.remove(id=old["id"])

            sched.add(
                name=self.TEMP_SCHED_NAME,
                comment=f"MC temporary NORMAL; restore {restore_mode}",
                start_date=target.strftime("%b/%d/%Y").lower(),
                start_time=target.strftime("%H:%M:%S"),
                interval="0s",
                on_event=restore_script,
                policy="read,write,test",
                disabled="false",
            )
        except Exception as exc:
            raise RouterError(
                f"Unable to create RouterOS temporary restore schedule: {exc}"
            ) from exc
        finally:
            pool.disconnect()

        try:
            self.set_mode("normal")
        except Exception:
            # Do not leave an orphan restore entry if NORMAL could not be applied.
            try:
                pool, api = self._connect()
                sched = api.get_resource("/system/scheduler")
                for old in sched.get(name=self.TEMP_SCHED_NAME):
                    sched.remove(id=old["id"])
                pool.disconnect()
            except Exception:
                pass
            raise

        return {
            "active": True,
            "minutes": minutes,
            "restore_mode": restore_mode,
            "restore_at": target.isoformat(),
        }

    def cancel_temporary_access(self) -> dict:
        pool, api = self._connect()
        try:
            sched = api.get_resource("/system/scheduler")
            removed = 0
            for entry in sched.get(name=self.TEMP_SCHED_NAME):
                sched.remove(id=entry["id"])
                removed += 1
            return {"removed": removed}
        except Exception as exc:
            raise RouterError(f"Unable to cancel temporary access: {exc}") from exc
        finally:
            pool.disconnect()



    def get_legacy_kid_control_snapshot(self) -> dict:
        """Read the legacy MikroTik Kid Control configuration for migration.

        This is a deliberately bounded read-only inventory. Activity domains,
        traffic rates and byte counters are excluded because they are evidence,
        not policy configuration. No Kid Control resource is ever mutated here.
        """
        pool, api = self._connect()
        try:
            raw_profiles = api.get_resource("/ip/kid-control").get()
            raw_devices = api.get_resource("/ip/kid-control/device").get()
            raw_leases = api.get_resource("/ip/dhcp-server/lease").get()
            raw_arp = api.get_resource("/ip/arp").get()

            profiles = []
            for raw in raw_profiles:
                item = {
                    "id": self._entry_id(raw) or "",
                    "name": str(raw.get("name") or ""),
                    "disabled": _ros_bool(raw.get("disabled", False)),
                    "rate-limit": str(raw.get("rate-limit") or ""),
                }
                for day in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
                    item[day] = str(raw.get(day) or "")
                    item[f"tur-{day}"] = str(raw.get(f"tur-{day}") or "")
                profiles.append(item)

            devices = []
            for raw in raw_devices:
                devices.append({
                    "id": self._entry_id(raw) or "",
                    "name": str(raw.get("name") or ""),
                    "mac-address": str(raw.get("mac-address") or ""),
                    "user": str(raw.get("user") or ""),
                    "ip-address": str(raw.get("ip-address") or ""),
                    "dynamic": _ros_bool(raw.get("dynamic", False)),
                    "inactive": _ros_bool(raw.get("inactive", False)),
                    "disabled": _ros_bool(raw.get("disabled", False)),
                })

            leases = []
            for raw in raw_leases:
                leases.append({
                    "address": str(raw.get("address") or ""),
                    "mac": str(raw.get("mac-address") or ""),
                    "status": str(raw.get("status") or ""),
                    "dynamic": _ros_bool(raw.get("dynamic", False)),
                })

            arp_entries = []
            for raw in raw_arp:
                arp_entries.append({
                    "address": str(raw.get("address") or ""),
                    "mac": str(raw.get("mac-address") or ""),
                    "complete": str(raw.get("complete", "")).lower() not in {"false", "no", "0", ""},
                    "dynamic": _ros_bool(raw.get("dynamic", False)),
                })

            return {
                "captured_at": datetime.now(ZoneInfo("UTC")).isoformat(timespec="seconds"),
                "profiles": profiles,
                "devices": devices,
                "dhcp_leases": leases,
                "arp_entries": arp_entries,
            }
        except Exception as exc:
            raise RouterError(f"Unable to read legacy MikroTik Kid Control configuration: {exc}") from exc
        finally:
            pool.disconnect()

    def prepare_kid_control_migration_device(self, address: str, expected_mac: str, description: str) -> dict:
        """Adopt one already-static Kid Control device into ZEN's restricted list.

        The method deliberately refuses to create or mutate DHCP leases.  Kid
        Control tracks by MAC; ZEN's RouterOS enforcement is IP based, so an
        exact static DHCP lease is a precondition for safe authority transfer.
        """
        address = self._validate_ipv4(address)
        expected_mac = str(expected_mac or "").strip().upper().replace("-", ":")
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", expected_mac):
            raise RouterError("Expected migration MAC address is invalid")
        description = self._validate_description(description)
        self._require_policy_write_gate()

        pool, api = self._connect()
        try:
            leases = api.get_resource("/ip/dhcp-server/lease").get(address=address)
            if len(leases) != 1:
                raise RouterError(f"Expected exactly one DHCP lease for {address}")
            lease = leases[0]
            lease_mac = str(lease.get("mac-address") or "").strip().upper().replace("-", ":")
            if lease_mac != expected_mac:
                raise RouterError(f"DHCP lease MAC mismatch for {address}")
            if _ros_bool(lease.get("dynamic", False)):
                raise RouterError(
                    f"DHCP lease for {address} is dynamic; reserve it before Kid Control authority transfer"
                )

            resource = api.get_resource("/ip/firewall/address-list")
            existing = resource.get(list=self.RESTRICTED_LIST, address=address)
            static_existing = [item for item in existing if not _ros_bool(item.get("dynamic", False))]
            if len(static_existing) > 1:
                raise RouterError(f"Multiple static Restricted_Devices entries found for {address}")
            if static_existing:
                return {
                    "address": address, "mac_address": expected_mac,
                    "created": False, "entry_id": self._entry_id(static_existing[0]) or "",
                    "comment": str(static_existing[0].get("comment") or ""),
                }

            comment = f"ZEN migration - {description}"[:60]
            created = resource.add(list=self.RESTRICTED_LIST, address=address, comment=comment)
            verified = [
                item for item in resource.get(list=self.RESTRICTED_LIST, address=address)
                if not _ros_bool(item.get("dynamic", False))
            ]
            if len(verified) != 1:
                raise RouterError(f"Unable to verify migrated Restricted_Devices entry for {address}")
            return {
                "address": address, "mac_address": expected_mac, "created": True,
                "entry_id": self._entry_id(verified[0]) or (created.get("id") if isinstance(created, dict) else ""),
                "comment": str(verified[0].get("comment") or comment),
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to prepare Kid Control migration device {address}: {exc}") from exc
        finally:
            pool.disconnect()

    def rollback_kid_control_migration_device(self, address: str) -> dict:
        """Remove only a Restricted_Devices row created by the migration path."""
        address = self._validate_ipv4(address)
        self._require_policy_write_gate()
        pool, api = self._connect()
        try:
            resource = api.get_resource("/ip/firewall/address-list")
            matches = [
                item for item in resource.get(list=self.RESTRICTED_LIST, address=address)
                if not _ros_bool(item.get("dynamic", False))
                and str(item.get("comment") or "").startswith("ZEN migration - ")
            ]
            if len(matches) > 1:
                raise RouterError(f"Multiple migration-owned Restricted_Devices rows found for {address}")
            if not matches:
                return {"address": address, "removed": False}
            resource.remove(id=matches[0]["id"])
            return {"address": address, "removed": True}
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to roll back migration device {address}: {exc}") from exc
        finally:
            pool.disconnect()

    def set_legacy_kid_control_profile_disabled(
        self, profile_name: str, disabled: bool, *, expected_id: str = ""
    ) -> dict:
        """Bounded legacy authority write: toggle only Kid Control `disabled`.

        Schedule fields, device membership and legacy objects are never edited or
        deleted by this method.  Exact name/id re-validation prevents a stale
        migration preview from targeting a different RouterOS object.
        """
        profile_name = str(profile_name or "").strip()
        if not profile_name:
            raise RouterError("Kid Control profile name is required")
        self._require_policy_write_gate()
        pool, api = self._connect()
        try:
            resource = api.get_resource("/ip/kid-control")
            matches = [row for row in resource.get() if str(row.get("name") or "") == profile_name]
            if len(matches) != 1:
                raise RouterError(f"Expected exactly one Kid Control profile named '{profile_name}'")
            row = matches[0]
            row_id = self._entry_id(row) or ""
            if expected_id and row_id != str(expected_id):
                raise RouterError(f"Kid Control profile '{profile_name}' identity changed since validation")
            resource.set(id=row_id, disabled="true" if disabled else "false")
            verify = [item for item in resource.get() if str(item.get("name") or "") == profile_name]
            if len(verify) != 1 or _ros_bool(verify[0].get("disabled", False)) != bool(disabled):
                raise RouterError(f"Unable to verify Kid Control profile '{profile_name}' authority state")
            return {
                "id": row_id, "name": profile_name,
                "disabled": bool(disabled),
                "legacy_authority_active": not bool(disabled),
            }
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to change Kid Control authority for '{profile_name}': {exc}") from exc
        finally:
            pool.disconnect()

    def get_dhcp_leases(self) -> list[dict]:
        """Read-only DHCP lease inventory. No lease mutation is performed."""
        pool, api = self._connect()
        try:
            leases = api.get_resource("/ip/dhcp-server/lease").get()
            result = []
            for lease in leases:
                result.append(
                    {
                        "id": lease.get("id"),
                        "address": lease.get("address", ""),
                        "mac": lease.get("mac-address", ""),
                        "host_name": lease.get("host-name", ""),
                        "comment": lease.get("comment", ""),
                        "status": lease.get("status", ""),
                        "dynamic": _ros_bool(lease.get("dynamic", False)),
                        "server": lease.get("server", ""),
                        "last_seen": lease.get("last-seen", ""),
                    }
                )
            return result
        except Exception as exc:
            raise RouterError(f"Unable to read DHCP leases: {exc}") from exc
        finally:
            pool.disconnect()

    def get_arp_entries(self) -> list[dict]:
        """Read-only ARP inventory. No ARP mutation is performed."""
        pool, api = self._connect()
        try:
            entries = api.get_resource("/ip/arp").get()
            result = []
            for entry in entries:
                result.append(
                    {
                        "address": entry.get("address", ""),
                        "mac": entry.get("mac-address", ""),
                        "interface": entry.get("interface", ""),
                        "complete": str(entry.get("complete", "")).lower() not in {"false", "no", "0", ""},
                        "dynamic": _ros_bool(entry.get("dynamic", False)),
                    }
                )
            return result
        except Exception as exc:
            raise RouterError(f"Unable to read ARP table: {exc}") from exc
        finally:
            pool.disconnect()

    def get_discovered_devices(self) -> list[dict]:
        """Merge DHCP + ARP read-only inventory by IP address."""
        dhcp = {x["address"]: x for x in self.get_dhcp_leases() if x.get("address")}
        arp = {x["address"]: x for x in self.get_arp_entries() if x.get("address")}
        addresses = sorted(set(dhcp) | set(arp))
        result = []
        for address in addresses:
            lease = dhcp.get(address, {})
            arp_entry = arp.get(address, {})
            result.append(
                {
                    "address": address,
                    "mac": lease.get("mac") or arp_entry.get("mac", ""),
                    "name": lease.get("host_name") or lease.get("comment") or "",
                    "host_name": lease.get("host_name", ""),
                    "comment": lease.get("comment", ""),
                    "status": lease.get("status", ""),
                    "dynamic_lease": lease.get("dynamic"),
                    "last_seen": lease.get("last_seen", ""),
                    "source": "DHCP+ARP" if address in dhcp and address in arp else ("DHCP" if address in dhcp else "ARP"),
                }
            )
        return result

    def add_restricted_device(self, address: str, description: str) -> dict:
        address = self._validate_ipv4(address)
        description = self._validate_description(description)
        self._require_policy_write_gate()

        pool, api = self._connect()
        try:
            lease_resource = api.get_resource("/ip/dhcp-server/lease")
            list_resource = api.get_resource("/ip/firewall/address-list")

            mac, lease = self._find_mac_for_ip(api, address)

            if lease is not None:
                if _ros_bool(lease.get("dynamic", False)):
                    lease_resource.call("make-static", {"numbers": lease["id"]})
                    refreshed = lease_resource.get(address=address)
                    if len(refreshed) != 1:
                        raise RouterError(
                            f"Lease for {address} could not be verified after make-static"
                        )
                    lease = refreshed[0]

                lease_resource.set(
                    id=lease["id"],
                    comment=description,
                    address=address,
                )
            else:
                servers = api.get_resource("/ip/dhcp-server").get()
                active_servers = [
                    server
                    for server in servers
                    if not _ros_bool(server.get("disabled", False))
                ]
                if len(active_servers) != 1:
                    raise RouterError(
                        "The IP was found in ARP but not DHCP, and a single active "
                        "DHCP server could not be selected safely."
                    )
                lease_resource.add(
                    address=address,
                    mac_address=mac,
                    server=active_servers[0]["name"],
                    comment=description,
                )

            existing = list_resource.get(
                list=self.RESTRICTED_LIST,
                address=address,
            )
            static_existing = [
                item for item in existing if not _ros_bool(item.get("dynamic", False))
            ]
            if static_existing:
                list_resource.set(id=static_existing[0]["id"], comment=description)
            else:
                list_resource.add(
                    list=self.RESTRICTED_LIST,
                    address=address,
                    comment=description,
                )

        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to add restricted device: {exc}") from exc
        finally:
            pool.disconnect()

        # Re-apply SLOW/BLOCKED so a newly-added device takes effect immediately.
        current_mode = self.get_status()["mode"]
        if current_mode in {"slow", "blocked"}:
            self.set_mode(current_mode)

        return {
            "address": address,
            "mac_address": mac,
            "description": description,
            "dhcp_reserved": True,
        }

    def remove_restricted_device(self, address: str) -> dict:
        address = self._validate_ipv4(address)
        self._require_policy_write_gate()

        pool, api = self._connect()
        try:
            resource = api.get_resource("/ip/firewall/address-list")
            matches = resource.get(list=self.RESTRICTED_LIST, address=address)
            removable = [
                item for item in matches if not _ros_bool(item.get("dynamic", False))
            ]
            if not removable:
                raise RouterError(f"{address} is not a static restricted device")

            for entry in removable:
                resource.remove(id=entry["id"])
        except RouterError:
            raise
        except Exception as exc:
            raise RouterError(f"Unable to remove restricted device: {exc}") from exc
        finally:
            pool.disconnect()

        # If SLOW is active, rebuild the queue so the removed IP is released.
        current_mode = self.get_status()["mode"]
        if current_mode == "slow":
            self.set_mode("slow")

        return {
            "address": address,
            "removed": True,
            "dhcp_reservation_kept": True,
        }
