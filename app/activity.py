import ipaddress
import os
import re
from datetime import datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import psycopg
from psycopg.rows import dict_row

from app.bypass import BYPASS_PORTS, classify_doh_domain, classify_port_signal
from app.performance import perf_span, perf_sql
from app.policy_time import local_midnight, normalize_policy_datetime

class ActivityError(RuntimeError):
    pass

def _format_bytes(value):
    value = int(value or 0)
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or unit == "TB":
            return f"{int(number)} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024


def format_activity_bytes(value):
    """Public byte formatter shared by activity and parent-summary surfaces."""
    return _format_bytes(value)


def _service_token(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _parse_iso_date(value):
    value = str(value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("Dates must use YYYY-MM-DD") from exc


def resolve_activity_window(preset="7d", timezone_name="Europe/London", start=None, end=None, now=None):
    """Resolve parent-facing analytics windows in the configured household timezone.

    The returned end is exclusive. Today and rolling multi-day presets end at
    ``now`` so comparisons use an equally sized previous window instead of
    comparing a partial current day against a complete historical day.
    """
    try:
        tz = ZoneInfo(str(timezone_name or "Europe/London"))
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Unknown timezone: {timezone_name}") from exc
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    local_now = current.astimezone(tz)
    today = local_now.date()
    preset = str(preset or "7d").strip().lower()

    if preset == "custom":
        start_day = _parse_iso_date(start)
        end_day = _parse_iso_date(end)
        if not start_day or not end_day:
            raise ValueError("Custom activity range requires start and end dates")
        if end_day < start_day:
            raise ValueError("Custom activity end date cannot be before the start date")
        if (end_day - start_day).days > 30:
            raise ValueError("Custom activity ranges are limited to 31 days")
        start_local, _ = local_midnight(start_day, tz)
        end_local, _ = local_midnight(end_day + timedelta(days=1), tz)
        label = f"{start_day.isoformat()} to {end_day.isoformat()}"
    elif preset == "today":
        start_local, _ = local_midnight(today, tz)
        end_local = local_now
        label = "Today"
    elif preset == "yesterday":
        end_local, _ = local_midnight(today, tz)
        start_local, _ = local_midnight(today - timedelta(days=1), tz)
        label = "Yesterday"
    elif preset in {"7d", "30d"}:
        days = int(preset[:-1])
        start_day = today - timedelta(days=days - 1)
        start_local, _ = local_midnight(start_day, tz)
        end_local = local_now
        label = f"Last {days} days"
    else:
        raise ValueError("Activity period must be today, yesterday, 7d, 30d or custom")

    duration = end_local.astimezone(timezone.utc) - start_local.astimezone(timezone.utc)
    previous_end = start_local.astimezone(timezone.utc)
    previous_start = previous_end - duration
    return {
        "preset": preset,
        "label": label,
        "timezone": str(tz.key),
        "start": start_local.astimezone(timezone.utc),
        "end": end_local.astimezone(timezone.utc),
        "previous_start": previous_start,
        "previous_end": previous_end,
        "start_date": start_local.date().isoformat(),
        "end_date": (end_local - timedelta(microseconds=1)).date().isoformat(),
        "duration_hours": round(duration.total_seconds() / 3600, 2),
    }


def compare_activity_totals(current, previous):
    """Attach stable percent changes without pretending division by zero is data."""
    result = {}
    for key in ("total_bytes", "download_bytes", "upload_bytes", "flows", "dns_queries", "dns_blocked", "unique_domains"):
        now_value = int((current or {}).get(key) or 0)
        old_value = int((previous or {}).get(key) or 0)
        if old_value == 0:
            delta = None if now_value else 0.0
        else:
            delta = round((now_value - old_value) * 100 / old_value, 1)
        result[key] = {"current": now_value, "previous": old_value, "delta_percent": delta}
    return result


def build_policy_service_activity(service_defs, observed_rows, policy_groups=None, profiles=None):
    """Merge telemetry service totals with the live policy service catalogue.

    Reporting identity follows current policy definitions rather than a fixed UI
    list. Newly-created services therefore appear immediately. If telemetry later
    emits the service key or display name, the existing row starts accumulating
    activity automatically. Logical policy groups aggregate their concrete members.
    """
    policy_groups = policy_groups or {}
    profiles = profiles or []
    defs = [dict(item) for item in (service_defs or [])]
    existing_keys = {str(item.get("key") or "") for item in defs}
    for group_key, group in policy_groups.items():
        if group_key in existing_keys:
            continue
        defs.append({
            "key": group_key,
            "name": group.get("name") or group_key,
            "description": group.get("description") or "",
            "category": "aggregate",
            "builtin": bool(group.get("builtin", False)),
            "classifier_enabled": False,
            "routeros_managed": False,
        })
    by_key = {str(item.get("key") or ""): item for item in defs}

    observed = []
    for row in observed_rows or []:
        item = dict(row)
        name = str(item.get("service_name") or "Other")
        item["service_name"] = name
        item["total_bytes"] = int(item.get("total_bytes") or 0)
        item["flows"] = int(item.get("flows") or 0)
        item["token"] = _service_token(name)
        observed.append(item)

    total_observed = sum(item["total_bytes"] for item in observed) or 1
    used_tokens = set()
    rows = []

    def direct_totals(service):
        candidates = {_service_token(service.get("key")), _service_token(service.get("name"))}
        matches = [item for item in observed if item["token"] in candidates and item["token"]]
        for item in matches:
            used_tokens.add(item["token"] )
        return sum(item["total_bytes"] for item in matches), sum(item["flows"] for item in matches)

    for service in defs:
        key = str(service.get("key") or "")
        group = policy_groups.get(key)
        if group:
            member_keys = list(group.get("members") or ())
            member_tokens = set()
            for member_key in member_keys:
                member = by_key.get(member_key, {"key": member_key, "name": member_key})
                member_tokens.update({_service_token(member.get("key")), _service_token(member.get("name"))})
            matches = [item for item in observed if item["token"] in member_tokens and item["token"]]
            for item in matches:
                used_tokens.add(item["token"] )
            bytes_total = sum(item["total_bytes"] for item in matches)
            flows = sum(item["flows"] for item in matches)
            kind = "group"
            members = member_keys
        else:
            bytes_total, flows = direct_totals(service)
            kind = "builtin" if service.get("builtin") else "custom"
            members = []

        blocked_by = []
        for profile in profiles:
            blocked = set(profile.get("blocked_services") or [])
            if key in blocked or (members and blocked.intersection(members)):
                blocked_by.append(str(profile.get("name") or "Profile"))

        rows.append({
            "key": key,
            "name": str((group or {}).get("name") or service.get("name") or key),
            "kind": kind,
            "members": members,
            "policy_tracked": True,
            "observed": bytes_total > 0 or flows > 0,
            "total_bytes": bytes_total,
            "total_bytes_human": _format_bytes(bytes_total),
            "flows": flows,
            "percent": round(bytes_total * 100 / total_observed, 1) if bytes_total else 0.0,
            "blocked_by_profiles": blocked_by,
        })

    for item in observed:
        if not item["token"] or item["token"] in used_tokens or item["service_name"] == "Other":
            continue
        rows.append({
            "key": "",
            "name": item["service_name"],
            "kind": "observed",
            "members": [],
            "policy_tracked": False,
            "observed": True,
            "total_bytes": item["total_bytes"],
            "total_bytes_human": _format_bytes(item["total_bytes"]),
            "flows": item["flows"],
            "percent": round(item["total_bytes"] * 100 / total_observed, 1),
            "blocked_by_profiles": [],
        })

    rows.sort(key=lambda item: (not item["policy_tracked"], -item["total_bytes"], item["name"].lower()))
    return rows

class ActivityStore:
    def __init__(self):
        self.host = os.getenv("TELEMETRY_DB_HOST", "telemetry-db")
        self.port = int(os.getenv("TELEMETRY_DB_PORT", "5432"))
        self.database = os.getenv("TELEMETRY_DB_NAME", "mikrotik")
        self.username = os.getenv("TELEMETRY_DB_USER", "mikrotik")
        self.password = os.getenv("TELEMETRY_DB_PASSWORD", "change-me")
        self.timeout = int(os.getenv("TELEMETRY_DB_TIMEOUT", "3"))

    def _connect(self):
        with perf_span("postgres.connect"):
            return psycopg.connect(
                host=self.host, port=self.port, dbname=self.database,
                user=self.username, password=self.password,
                connect_timeout=self.timeout, row_factory=dict_row,
            )

    def _query(self, sql, params=()):
        try:
            with perf_sql(sql):
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql, params)
                        return cur.fetchall()
        except psycopg.Error as exc:
            raise ActivityError(f"Telemetry database unavailable: {exc}") from exc

    def health(self):
        rows = self._query("SELECT 1 AS ok")
        return bool(rows and rows[0]["ok"] == 1)

    def overview(self, hours=24):
        hours = max(1, min(int(hours), 24 * 31))
        row = self._query("""
            SELECT
              COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
              COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
              COALESCE(sum(bytes),0) AS total_bytes,
              COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NOT NULL),0) AS attributed_bytes,
              COALESCE(sum(flows),0) AS flows,
              count(DISTINCT client_ip) AS active_devices,
              count(DISTINCT NULLIF(service,'')) AS observed_services,
              max(bucket) AS latest_flow
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour')
        """, (hours,))[0]
        result = {k: int(row[k] or 0) for k in (
            "download_bytes", "upload_bytes", "total_bytes", "attributed_bytes",
            "flows", "active_devices", "observed_services"
        )}
        for key in ("download_bytes", "upload_bytes", "total_bytes"):
            result[key + "_human"] = _format_bytes(result[key])
        drow = self._query("""
            SELECT count(*) AS queries,
                   count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT domain) AS unique_domains,
                   max(event_time) AS latest_dns
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour')
        """, (hours,))[0]
        result["dns_queries"] = int(drow["queries"] or 0)
        result["dns_blocked"] = int(drow["blocked"] or 0)
        result["unique_domains"] = int(drow["unique_domains"] or 0)
        result["attributed_percent"] = round(result["attributed_bytes"] * 100 / max(result["total_bytes"], 1), 1)
        result["dns_block_percent"] = round(result["dns_blocked"] * 100 / max(result["dns_queries"], 1), 1)
        result["latest_flow"] = row["latest_flow"].isoformat() if row.get("latest_flow") else None
        result["latest_dns"] = drow["latest_dns"].isoformat() if drow.get("latest_dns") else None
        return result

    def top_devices(self, hours=24, limit=10):
        rows = self._query("""
            SELECT client_ip,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND client_ip <> ''
            GROUP BY client_ip ORDER BY total_bytes DESC LIMIT %s
        """, (int(hours), int(limit)))
        total = sum(int(r["total_bytes"] or 0) for r in rows) or 1
        for row in rows:
            for key in ("total_bytes", "download_bytes", "upload_bytes"):
                row[key] = int(row[key] or 0)
                row[key + "_human"] = _format_bytes(row[key])
            row["percent"] = round(row["total_bytes"] * 100 / total, 1)
        return rows

    def device_activity_summaries(self, client_ips, hours=24, service_limit=5, domain_limit=6):
        valid = []
        for value in client_ips or []:
            try:
                valid.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if not valid:
            return {}
        hours = max(1, min(int(hours), 24 * 31))
        service_limit = max(1, min(int(service_limit), 12))
        domain_limit = max(1, min(int(domain_limit), 20))
        summaries = {ip: {"client_ip": ip, "services": [], "domains": []} for ip in valid}

        flow_rows = self._query("""
            SELECT client_ip, COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(flows),0) AS flows, min(bucket) AS first_seen, max(bucket) AS last_seen
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND client_ip = ANY(%s)
            GROUP BY client_ip
        """, (hours, valid))
        for row in flow_rows:
            item = summaries.setdefault(str(row["client_ip"]), {"client_ip": str(row["client_ip"]), "services": [], "domains": []})
            for key in ("total_bytes", "download_bytes", "upload_bytes"):
                item[key] = int(row.get(key) or 0)
                item[key + "_human"] = _format_bytes(item[key])
            item["flows"] = int(row.get("flows") or 0)
            item["first_seen"] = row["first_seen"].isoformat() if row.get("first_seen") else None
            item["last_seen"] = row["last_seen"].isoformat() if row.get("last_seen") else None

        dns_rows = self._query("""
            SELECT client_ip, count(*) AS dns_queries,
                   count(*) FILTER (WHERE blocked) AS dns_blocked,
                   count(DISTINCT domain) AS unique_domains,
                   min(event_time) AS dns_first_seen, max(event_time) AS dns_last_seen
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour') AND client_ip = ANY(%s)
            GROUP BY client_ip
        """, (hours, valid))
        for row in dns_rows:
            item = summaries.setdefault(str(row["client_ip"]), {"client_ip": str(row["client_ip"]), "services": [], "domains": []})
            item["dns_queries"] = int(row.get("dns_queries") or 0)
            item["dns_blocked"] = int(row.get("dns_blocked") or 0)
            item["unique_domains"] = int(row.get("unique_domains") or 0)
            item["dns_first_seen"] = row["dns_first_seen"].isoformat() if row.get("dns_first_seen") else None
            item["dns_last_seen"] = row["dns_last_seen"].isoformat() if row.get("dns_last_seen") else None

        service_rows = self._query("""
            WITH totals AS (
              SELECT client_ip, CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                     COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
              FROM flow_5m
              WHERE bucket >= now() - (%s * interval '1 hour') AND client_ip = ANY(%s)
              GROUP BY client_ip, service_name
            ), ranked AS (
              SELECT *, row_number() OVER (PARTITION BY client_ip ORDER BY total_bytes DESC) AS rn
              FROM totals
            )
            SELECT * FROM ranked WHERE rn <= %s ORDER BY client_ip, rn
        """, (hours, valid, service_limit))
        for row in service_rows:
            summaries[str(row["client_ip"])]["services"].append({
                "service_name": str(row.get("service_name") or "Other"),
                "total_bytes": int(row.get("total_bytes") or 0),
                "total_bytes_human": _format_bytes(row.get("total_bytes") or 0),
                "flows": int(row.get("flows") or 0),
            })

        domain_rows = self._query("""
            WITH totals AS (
              SELECT client_ip, domain, COALESCE(max(NULLIF(service,'')),'') AS service,
                     count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked
              FROM dns_queries
              WHERE event_time >= now() - (%s * interval '1 hour')
                AND client_ip = ANY(%s) AND domain <> ''
              GROUP BY client_ip, domain
            ), ranked AS (
              SELECT *, row_number() OVER (PARTITION BY client_ip ORDER BY queries DESC) AS rn
              FROM totals
            )
            SELECT * FROM ranked WHERE rn <= %s ORDER BY client_ip, rn
        """, (hours, valid, domain_limit))
        for row in domain_rows:
            summaries[str(row["client_ip"])]["domains"].append({
                "domain": str(row.get("domain") or ""),
                "service": str(row.get("service") or ""),
                "queries": int(row.get("queries") or 0),
                "blocked": int(row.get("blocked") or 0),
            })

        for item in summaries.values():
            item.setdefault("total_bytes", 0)
            item.setdefault("download_bytes", 0)
            item.setdefault("upload_bytes", 0)
            item.setdefault("total_bytes_human", _format_bytes(item["total_bytes"]))
            item.setdefault("download_bytes_human", _format_bytes(item["download_bytes"]))
            item.setdefault("upload_bytes_human", _format_bytes(item["upload_bytes"]))
            item.setdefault("flows", 0)
            item.setdefault("dns_queries", 0)
            item.setdefault("dns_blocked", 0)
            item.setdefault("unique_domains", 0)
        return summaries

    def managed_activity_count(self, client_ips, hours=24):
        valid = []
        for value in client_ips or []:
            try:
                valid.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if not valid:
            return 0
        row = self._query("""
            SELECT count(DISTINCT client_ip) AS n
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND client_ip = ANY(%s)
        """, (max(1, min(int(hours), 24 * 31)), valid))[0]
        return int(row.get("n") or 0)

    def top_services(self, hours=24, limit=12, client_ip=None):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(int(limit))
        rows = self._query(f"""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour'){extra}
            GROUP BY service_name ORDER BY total_bytes DESC LIMIT %s
        """, tuple(params))
        total = sum(int(r["total_bytes"] or 0) for r in rows) or 1
        for row in rows:
            row["total_bytes"] = int(row["total_bytes"] or 0)
            row["total_bytes_human"] = _format_bytes(row["total_bytes"])
            row["percent"] = round(row["total_bytes"] * 100 / total, 1)
        return rows

    def top_destinations(self, hours=24, limit=15, client_ip=None):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(int(limit))
        rows = self._query(f"""
            SELECT remote_ip,
                   COALESCE(max(NULLIF(domain,'')),'') AS domain,
                   COALESCE(max(NULLIF(service,'')),'') AS service,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour'){extra} AND remote_ip <> ''
            GROUP BY remote_ip ORDER BY total_bytes DESC LIMIT %s
        """, tuple(params))
        for row in rows:
            row["total_bytes"] = int(row["total_bytes"] or 0)
            row["total_bytes_human"] = _format_bytes(row["total_bytes"])
        return rows

    def dns_top_domains(self, hours=24, limit=15, client_ip=None):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(int(limit))
        rows = self._query(f"""
            SELECT domain, COALESCE(max(NULLIF(service,'')),'') AS service,
                   count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour'){extra} AND domain <> ''
            GROUP BY domain ORDER BY queries DESC LIMIT %s
        """, tuple(params))
        for row in rows:
            row["queries"] = int(row["queries"])
            row["blocked"] = int(row["blocked"])
        return rows

    def dns_top_services(self, hours=24, limit=12, client_ip=None):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(int(limit))
        return self._query(f"""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour'){extra}
            GROUP BY service_name ORDER BY queries DESC LIMIT %s
        """, tuple(params))

    def recent_dns(self, hours=24, limit=50, client_ip=None):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(int(limit))
        return self._query(f"""
            SELECT to_char(event_time AT TIME ZONE 'Europe/London','YYYY-MM-DD HH24:MI:SS') AS ts,
                   client_ip, client_name, domain, service, blocked, status
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour'){extra}
            ORDER BY event_time DESC LIMIT %s
        """, tuple(params))

    def device_detail(self, client_ip, hours=24):
        ipaddress.ip_address(client_ip)
        row = self._query("""
            SELECT COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND client_ip=%s
        """, (int(hours), client_ip))[0]
        out = {"client_ip": client_ip}
        for key in ("total_bytes", "download_bytes", "upload_bytes", "flows"):
            out[key] = int(row[key] or 0)
        for key in ("total_bytes", "download_bytes", "upload_bytes"):
            out[key + "_human"] = _format_bytes(out[key])
        return out


    def daily_usage(self, client_ip, timezone_name="Europe/London", at=None):
        """Return today's Internet byte usage for one client in policy timezone.

        Uses flow_5m rather than UTC-date rollups so the quota reset follows the
        configured household policy timezone, including DST transitions.
        """
        ipaddress.ip_address(client_ip)
        try:
            zone = ZoneInfo(str(timezone_name or "Europe/London"))
        except ZoneInfoNotFoundError as exc:
            raise ActivityError(f"Invalid policy timezone: {timezone_name}") from exc

        if at is None:
            local_now = datetime.now(zone)
        else:
            try:
                local_now, _ = normalize_policy_datetime(at, zone)
            except ValueError as exc:
                raise ActivityError(str(exc)) from exc

        start_local, start_resolution = local_midnight(local_now.date(), zone)
        end_local, end_resolution = local_midnight(local_now.date() + timedelta(days=1), zone)
        start_utc = start_local.astimezone(timezone.utc)
        end_utc = end_local.astimezone(timezone.utc)

        row = self._query("""
            SELECT COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(flows),0) AS flows,
                   max(bucket) AS latest_bucket
            FROM flow_5m
            WHERE client_ip=%s AND bucket >= %s AND bucket < %s
        """, (client_ip, start_utc, end_utc))[0]

        services = self._query("""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE client_ip=%s AND bucket >= %s AND bucket < %s
            GROUP BY service_name
            ORDER BY total_bytes DESC
        """, (client_ip, start_utc, end_utc))

        service_bytes = {}
        service_flows = {}
        for item in services:
            name = str(item["service_name"] or "Other")
            service_bytes[name] = int(item["total_bytes"] or 0)
            service_flows[name] = int(item["flows"] or 0)

        latest = row.get("latest_bucket")
        return {
            "available": True,
            "client_ip": client_ip,
            "day": local_now.date().isoformat(),
            "timezone": str(zone.key),
            "window_start": start_local.isoformat(),
            "window_end": end_local.isoformat(),
            "window_hours": round(
                (end_utc - start_utc).total_seconds() / 3600.0, 2
            ),
            "window_resolution": {
                "start": start_resolution,
                "end": end_resolution,
            },
            "total_bytes": int(row["total_bytes"] or 0),
            "download_bytes": int(row["download_bytes"] or 0),
            "upload_bytes": int(row["upload_bytes"] or 0),
            "flows": int(row["flows"] or 0),
            "latest_bucket": latest.isoformat() if latest else None,
            "service_bytes": service_bytes,
            "service_flows": service_flows,
        }

    def bypass_evidence(self, client_ips, hours=24, limit=120):
        """Return evidence-led DNS/VPN/proxy bypass signals for managed clients.

        Port-based VPN/proxy results are explicitly heuristic. Domain-enriched
        known-DoH flows are stronger evidence, while Pi-hole endpoint lookups
        are only intent/interest signals. Generic HTTPS/443 is never guessed.
        """
        valid = []
        for value in client_ips or []:
            try:
                valid.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if not valid:
            return []

        hours = max(1, min(int(hours), 24 * 7))
        limit = max(1, min(int(limit), 400))
        evidence = []

        port_rows = self._query("""
            SELECT client_ip, remote_ip, dst_port, protocol,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(packets),0) AS packets,
                   count(*) AS flows,
                   max(event_time) AS last_seen
            FROM flows_raw
            WHERE event_time >= now() - (%s * interval '1 hour')
              AND direction='upload'
              AND client_ip = ANY(%s)
              AND dst_port = ANY(%s)
            GROUP BY client_ip, remote_ip, dst_port, protocol
            ORDER BY last_seen DESC
            LIMIT %s
        """, (hours, valid, list(BYPASS_PORTS), limit))

        for row in port_rows:
            signal = classify_port_signal(row.get("protocol"), row.get("dst_port"))
            if not signal:
                continue
            evidence.append({
                **signal,
                "client_ip": str(row.get("client_ip") or ""),
                "remote_ip": str(row.get("remote_ip") or ""),
                "domain": "",
                "total_bytes": int(row.get("total_bytes") or 0),
                "total_bytes_human": _format_bytes(row.get("total_bytes") or 0),
                "packets": int(row.get("packets") or 0),
                "flows": int(row.get("flows") or 0),
                "last_seen": row["last_seen"].isoformat() if row.get("last_seen") else None,
            })

        # Domain-enriched flows come from the existing Pi-hole -> IP correlation
        # in telemetry ingest. We read all managed-domain aggregates within the
        # bounded window and classify only the explicitly-known DoH suffixes.
        domain_rows = self._query("""
            SELECT client_ip, remote_ip, dst_port, protocol, domain,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(packets),0) AS packets,
                   count(*) AS flows,
                   max(event_time) AS last_seen
            FROM flows_raw
            WHERE event_time >= now() - (%s * interval '1 hour')
              AND direction='upload'
              AND client_ip = ANY(%s)
              AND domain <> ''
            GROUP BY client_ip, remote_ip, dst_port, protocol, domain
            ORDER BY last_seen DESC
            LIMIT %s
        """, (hours, valid, max(limit * 4, 400)))

        seen_doh_flows = set()
        for row in domain_rows:
            signal = classify_doh_domain(row.get("domain"), source="flow")
            if not signal:
                continue
            identity = (
                str(row.get("client_ip") or ""),
                str(row.get("remote_ip") or ""),
                str(row.get("domain") or "").lower(),
            )
            if identity in seen_doh_flows:
                continue
            seen_doh_flows.add(identity)
            evidence.append({
                **signal,
                "client_ip": identity[0],
                "remote_ip": identity[1],
                "domain": str(row.get("domain") or ""),
                "protocol": str(row.get("protocol") or ""),
                "dst_port": int(row.get("dst_port") or 0),
                "total_bytes": int(row.get("total_bytes") or 0),
                "total_bytes_human": _format_bytes(row.get("total_bytes") or 0),
                "packets": int(row.get("packets") or 0),
                "flows": int(row.get("flows") or 0),
                "last_seen": row["last_seen"].isoformat() if row.get("last_seen") else None,
            })

        # A resolver endpoint lookup is useful context, but it is weaker than a
        # correlated flow and is labelled MEDIUM rather than HIGH confidence.
        dns_rows = self._query("""
            SELECT client_ip, domain, count(*) AS queries, max(event_time) AS last_seen
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour')
              AND client_ip = ANY(%s)
              AND domain <> ''
            GROUP BY client_ip, domain
            ORDER BY last_seen DESC
            LIMIT %s
        """, (hours, valid, max(limit * 4, 400)))

        doh_flow_domains = {(row["client_ip"], str(row.get("domain") or "").lower()) for row in evidence if row.get("key") == "known_doh_flow"}
        for row in dns_rows:
            signal = classify_doh_domain(row.get("domain"), source="dns")
            if not signal:
                continue
            identity = (str(row.get("client_ip") or ""), str(row.get("domain") or "").lower())
            if identity in doh_flow_domains:
                continue
            evidence.append({
                **signal,
                "client_ip": identity[0],
                "remote_ip": "",
                "domain": str(row.get("domain") or ""),
                "protocol": "DNS",
                "dst_port": 0,
                "total_bytes": 0,
                "total_bytes_human": "0 B",
                "packets": 0,
                "flows": int(row.get("queries") or 0),
                "last_seen": row["last_seen"].isoformat() if row.get("last_seen") else None,
            })

        evidence.sort(key=lambda item: str(item.get("last_seen") or ""), reverse=True)
        return evidence[:limit]

    def bypass_attempts(self, client_ips, hours=24, limit=50):
        """Best-effort WAN DNS-bypass visibility from retained raw IPFIX flows.

        LAN-to-LAN traffic is excluded by the ingest path, so outbound port 53
        or 853 records represent clients reaching Internet resolvers rather than
        normal queries to a local Pi-hole. DoH on TCP/443 cannot be identified
        reliably from flow ports alone and is intentionally not guessed here.
        """
        valid = []
        for value in client_ips or []:
            try:
                valid.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if not valid:
            return []
        hours = max(1, min(int(hours), 24 * 7))
        limit = max(1, min(int(limit), 200))
        rows = self._query("""
            SELECT client_ip, remote_ip, dst_port, protocol,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(packets),0) AS packets,
                   count(*) AS flows,
                   max(event_time) AS last_seen
            FROM flows_raw
            WHERE event_time >= now() - (%s * interval '1 hour')
              AND direction='upload'
              AND client_ip = ANY(%s)
              AND dst_port IN (53,853)
            GROUP BY client_ip, remote_ip, dst_port, protocol
            ORDER BY last_seen DESC
            LIMIT %s
        """, (hours, valid, limit))
        for row in rows:
            row["total_bytes"] = int(row["total_bytes"] or 0)
            row["packets"] = int(row["packets"] or 0)
            row["flows"] = int(row["flows"] or 0)
            row["total_bytes_human"] = _format_bytes(row["total_bytes"])
            row["kind"] = "Encrypted DNS (853)" if int(row["dst_port"] or 0) == 853 else "External DNS (53)"
            if row.get("last_seen"):
                row["last_seen"] = row["last_seen"].isoformat()
        return rows

    def classification_coverage(self, hours=24):
        """Return recent classification coverage without conflating evidence sources."""
        hours = max(1, min(int(hours), 24 * 31))
        errors = []
        flow = None
        dns = None
        try:
            rows = self._query("""
                SELECT COALESCE(sum(bytes),0) AS total_bytes,
                       COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NOT NULL),0) AS classified_bytes,
                       COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NULL),0) AS unclassified_bytes,
                       count(DISTINCT NULLIF(service,'')) AS service_labels
                FROM flow_5m WHERE bucket >= now() - (%s * interval '1 hour')
            """, (hours,))
            flow = rows[0] if rows else {}
        except ActivityError as exc:
            errors.append({"source": "traffic", "error": str(exc)})
        try:
            rows = self._query("""
                SELECT count(*) AS queries,
                       count(*) FILTER (WHERE NULLIF(service,'') IS NOT NULL) AS classified_queries,
                       count(*) FILTER (WHERE NULLIF(service,'') IS NULL) AS unclassified_queries,
                       count(DISTINCT domain) FILTER (WHERE NULLIF(service,'') IS NULL) AS unknown_domains
                FROM dns_queries WHERE event_time >= now() - (%s * interval '1 hour')
            """, (hours,))
            dns = rows[0] if rows else {}
        except ActivityError as exc:
            errors.append({"source": "dns", "error": str(exc)})
        return self._classification_coverage_result(flow, dns, errors)

    @staticmethod
    def _classification_coverage_result(flow, dns, errors=None):
        """Normalize independent IPFIX/DNS coverage with explicit evidence semantics."""
        traffic_available = flow is not None
        dns_available = dns is not None
        flow = flow or {}
        dns = dns or {}

        raw_total_bytes = int(flow.get("total_bytes") or 0)
        raw_classified_bytes = int(flow.get("classified_bytes") or 0)
        raw_unclassified_bytes = int(flow.get("unclassified_bytes") or 0)
        raw_queries = int(dns.get("queries") or 0)
        raw_classified_queries = int(dns.get("classified_queries") or 0)
        raw_unclassified_queries = int(dns.get("unclassified_queries") or 0)

        traffic_nonnegative = all(
            value >= 0
            for value in (raw_total_bytes, raw_classified_bytes, raw_unclassified_bytes)
        )
        dns_nonnegative = all(
            value >= 0
            for value in (raw_queries, raw_classified_queries, raw_unclassified_queries)
        )

        # Keep presentation values bounded, but never let that sanitisation turn
        # malformed retained evidence into a plausible percentage.
        total_bytes = max(0, raw_total_bytes)
        classified_bytes = max(0, raw_classified_bytes)
        unclassified_bytes = max(0, raw_unclassified_bytes)
        queries = max(0, raw_queries)
        classified_queries = max(0, raw_classified_queries)
        unclassified_queries = max(0, raw_unclassified_queries)
        traffic_accounted = classified_bytes + unclassified_bytes
        dns_accounted = classified_queries + unclassified_queries
        traffic_observed = traffic_available and total_bytes > 0
        dns_observed = dns_available and queries > 0
        traffic_accounting_valid = (
            traffic_available
            and traffic_nonnegative
            and traffic_accounted == total_bytes
        )
        dns_accounting_valid = (
            dns_available
            and dns_nonnegative
            and dns_accounted == queries
        )

        def _source_status(available, observed, accounting_valid):
            if not available:
                return "unavailable"
            if not accounting_valid:
                return "inconsistent"
            if not observed:
                return "no_evidence"
            return "measured"

        traffic_evidence_status = _source_status(
            traffic_available, traffic_observed, traffic_accounting_valid
        )
        dns_evidence_status = _source_status(
            dns_available, dns_observed, dns_accounting_valid
        )
        source_statuses = {traffic_evidence_status, dns_evidence_status}
        if source_statuses == {"unavailable"}:
            evidence_status = "unavailable"
        elif "inconsistent" in source_statuses:
            evidence_status = "inconsistent"
        elif "unavailable" in source_statuses:
            evidence_status = "partial"
        elif source_statuses == {"no_evidence"}:
            evidence_status = "no_evidence"
        else:
            evidence_status = "measured"

        return {
            "total_bytes": total_bytes,
            "classified_bytes": classified_bytes,
            "classified_bytes_human": _format_bytes(classified_bytes),
            "unclassified_bytes": unclassified_bytes,
            "unclassified_bytes_human": _format_bytes(unclassified_bytes),
            "traffic_available": traffic_available,
            "traffic_observed": traffic_observed,
            "traffic_evidence_status": traffic_evidence_status,
            "traffic_accounted_bytes": traffic_accounted,
            "traffic_accounting_valid": traffic_accounting_valid,
            "traffic_percent": round(classified_bytes * 100 / total_bytes, 1) if traffic_observed and traffic_accounting_valid else None,
            "service_labels": max(0, int(flow.get("service_labels") or 0)),
            "dns_queries": queries,
            "dns_classified_queries": classified_queries,
            "dns_unclassified_queries": unclassified_queries,
            "dns_available": dns_available,
            "dns_observed": dns_observed,
            "dns_evidence_status": dns_evidence_status,
            "dns_accounted_queries": dns_accounted,
            "dns_accounting_valid": dns_accounting_valid,
            "dns_percent": round(classified_queries * 100 / queries, 1) if dns_observed and dns_accounting_valid else None,
            "unknown_domains": max(0, int(dns.get("unknown_domains") or 0)),
            "evidence_status": evidence_status,
            "evidence_errors": list(errors or []),
        }

    def unknown_domains(self, hours=24, limit=30):
        hours = max(1, min(int(hours), 24 * 31))
        limit = max(1, min(int(limit), 200))
        rows = self._query("""
            SELECT domain, count(*) AS queries,
                   count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS devices, max(event_time) AS last_seen
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour')
              AND domain <> '' AND NULLIF(service,'') IS NULL
            GROUP BY domain ORDER BY queries DESC LIMIT %s
        """, (hours, limit))
        for row in rows:
            row["queries"] = int(row.get("queries") or 0)
            row["blocked"] = int(row.get("blocked") or 0)
            row["devices"] = int(row.get("devices") or 0)
            row["last_seen"] = row["last_seen"].isoformat() if row.get("last_seen") else None
        return rows

    def classification_coverage_range(self, start, end):
        """Return classification coverage for one explicit retained window.

        Traffic/IPFIX and DNS are independent evidence sources. A failure on
        one source must not erase valid evidence from the other, and an empty
        denominator is NO EVIDENCE rather than a measured zero-percent result.
        """
        start, end = self._validate_range(start, end)
        errors = []
        flow = None
        dns = None
        try:
            rows = self._query("""
                SELECT COALESCE(sum(bytes),0) AS total_bytes,
                       COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NOT NULL),0) AS classified_bytes,
                       COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NULL),0) AS unclassified_bytes,
                       count(DISTINCT NULLIF(service,'')) AS service_labels
                FROM flow_5m WHERE bucket >= %s AND bucket < %s
            """, (start, end))
            flow = rows[0] if rows else {}
        except ActivityError as exc:
            errors.append({"source": "traffic", "error": str(exc)})
        try:
            rows = self._query("""
                SELECT count(*) AS queries,
                       count(*) FILTER (WHERE NULLIF(service,'') IS NOT NULL) AS classified_queries,
                       count(*) FILTER (WHERE NULLIF(service,'') IS NULL) AS unclassified_queries,
                       count(DISTINCT domain) FILTER (WHERE NULLIF(service,'') IS NULL) AS unknown_domains
                FROM dns_queries WHERE event_time >= %s AND event_time < %s
            """, (start, end))
            dns = rows[0] if rows else {}
        except ActivityError as exc:
            errors.append({"source": "dns", "error": str(exc)})
        return self._classification_coverage_result(flow, dns, errors)

    def service_attribution_changes(self, hours=168, limit=12):
        """Compare named service traffic with the immediately preceding window."""
        hours = max(1, min(int(hours), 24 * 30))
        limit = max(1, min(int(limit), 50))
        rows = self._query("""
            SELECT service AS service_name,
                   COALESCE(sum(bytes) FILTER (WHERE bucket >= now() - (%s * interval '1 hour')),0) AS current_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE bucket < now() - (%s * interval '1 hour')),0) AS previous_bytes
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour')
              AND NULLIF(service,'') IS NOT NULL
            GROUP BY service
        """, (hours, hours, hours * 2))
        result = []
        for row in rows:
            current = int(row.get("current_bytes") or 0)
            previous = int(row.get("previous_bytes") or 0)
            delta = current - previous
            if not delta:
                continue
            result.append({
                "service_name": str(row.get("service_name") or ""),
                "current_bytes": current,
                "previous_bytes": previous,
                "current_human": _format_bytes(current),
                "previous_human": _format_bytes(previous),
                "delta_bytes": delta,
                "delta_human": ("+" if delta > 0 else "-") + _format_bytes(abs(delta)),
                "delta_percent": None if previous == 0 else round(delta * 100 / previous, 1),
            })
        result.sort(key=lambda item: abs(item["delta_bytes"]), reverse=True)
        return result[:limit]

    def service_detail(self, service_name, hours=24):
        service_name = str(service_name or "").strip()
        if not service_name:
            raise ValueError("Service name is required")
        hours = max(1, min(int(hours), 24 * 31))
        flow = self._query("""
            SELECT COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows,
                   count(DISTINCT client_ip) AS devices, min(bucket) AS first_seen, max(bucket) AS last_seen
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND lower(service)=lower(%s)
        """, (hours, service_name))[0]
        dns = self._query("""
            SELECT count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS dns_devices, count(DISTINCT domain) AS domains,
                   min(event_time) AS dns_first_seen, max(event_time) AS dns_last_seen
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour') AND lower(service)=lower(%s)
        """, (hours, service_name))[0]
        devices = self._query("""
            SELECT client_ip, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows, max(bucket) AS last_seen
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND lower(service)=lower(%s)
            GROUP BY client_ip ORDER BY total_bytes DESC LIMIT 30
        """, (hours, service_name))
        domains = self._query("""
            SELECT domain, count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS devices, max(event_time) AS last_seen
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour') AND lower(service)=lower(%s) AND domain <> ''
            GROUP BY domain ORDER BY queries DESC LIMIT 50
        """, (hours, service_name))
        series = self._query("""
            SELECT date_trunc('hour', bucket) AS bucket, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour') AND lower(service)=lower(%s)
            GROUP BY 1 ORDER BY 1
        """, (hours, service_name))
        for item in devices:
            item["total_bytes"] = int(item.get("total_bytes") or 0)
            item["total_bytes_human"] = _format_bytes(item["total_bytes"])
            item["flows"] = int(item.get("flows") or 0)
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        for item in domains:
            for key in ("queries", "blocked", "devices"):
                item[key] = int(item.get(key) or 0)
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        for item in series:
            item["bucket"] = item["bucket"].isoformat() if item.get("bucket") else None
            item["total_bytes"] = int(item.get("total_bytes") or 0)
            item["total_bytes_human"] = _format_bytes(item["total_bytes"])
            item["flows"] = int(item.get("flows") or 0)
        total_bytes = int(flow.get("total_bytes") or 0)
        return {
            "service_name": service_name,
            "total_bytes": total_bytes,
            "total_bytes_human": _format_bytes(total_bytes),
            "flows": int(flow.get("flows") or 0),
            "devices": int(flow.get("devices") or 0),
            "dns_queries": int(dns.get("queries") or 0),
            "dns_blocked": int(dns.get("blocked") or 0),
            "dns_devices": int(dns.get("dns_devices") or 0),
            "domains": int(dns.get("domains") or 0),
            "first_seen": flow["first_seen"].isoformat() if flow.get("first_seen") else None,
            "last_seen": flow["last_seen"].isoformat() if flow.get("last_seen") else None,
            "dns_first_seen": dns["dns_first_seen"].isoformat() if dns.get("dns_first_seen") else None,
            "dns_last_seen": dns["dns_last_seen"].isoformat() if dns.get("dns_last_seen") else None,
            "top_devices": devices,
            "top_domains": domains,
            "hourly": series,
        }

    @staticmethod
    def _validate_range(start, end):
        if not isinstance(start, datetime) or not isinstance(end, datetime):
            raise ValueError("Activity range requires datetime boundaries")
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("Activity range boundaries must include timezone information")
        if end <= start:
            raise ValueError("Activity range end must be after start")
        if end - start > timedelta(days=32):
            raise ValueError("Detailed activity ranges are limited to 32 days")
        return start, end

    def overview_range(self, start, end, client_ip=None):
        start, end = self._validate_range(start, end)
        params = [start, end]
        flow_extra = ""
        dns_extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            flow_extra = " AND client_ip=%s"
            dns_extra = " AND client_ip=%s"
            params.append(client_ip)
        flow_params = tuple(params)
        dns_params = tuple(params)
        flow = self._query(f"""
            SELECT COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NOT NULL),0) AS attributed_bytes,
                   COALESCE(sum(flows),0) AS flows,
                   count(DISTINCT client_ip) AS active_devices,
                   count(DISTINCT NULLIF(service,'')) AS observed_services,
                   min(bucket) AS first_flow, max(bucket) AS last_flow
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s{flow_extra}
        """, flow_params)[0]
        dns = self._query(f"""
            SELECT count(*) AS queries,
                   count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT domain) AS unique_domains,
                   min(event_time) AS first_dns, max(event_time) AS last_dns
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{dns_extra}
        """, dns_params)[0]
        result = {
            "total_bytes": int(flow.get("total_bytes") or 0),
            "download_bytes": int(flow.get("download_bytes") or 0),
            "upload_bytes": int(flow.get("upload_bytes") or 0),
            "attributed_bytes": int(flow.get("attributed_bytes") or 0),
            "flows": int(flow.get("flows") or 0),
            "active_devices": int(flow.get("active_devices") or 0),
            "observed_services": int(flow.get("observed_services") or 0),
            "dns_queries": int(dns.get("queries") or 0),
            "dns_blocked": int(dns.get("blocked") or 0),
            "unique_domains": int(dns.get("unique_domains") or 0),
            "first_flow": flow["first_flow"].isoformat() if flow.get("first_flow") else None,
            "last_flow": flow["last_flow"].isoformat() if flow.get("last_flow") else None,
            "first_dns": dns["first_dns"].isoformat() if dns.get("first_dns") else None,
            "last_dns": dns["last_dns"].isoformat() if dns.get("last_dns") else None,
        }
        for key in ("total_bytes", "download_bytes", "upload_bytes", "attributed_bytes"):
            result[key + "_human"] = _format_bytes(result[key])
        result["attributed_percent"] = round(result["attributed_bytes"] * 100 / max(result["total_bytes"], 1), 1)
        result["dns_block_percent"] = round(result["dns_blocked"] * 100 / max(result["dns_queries"], 1), 1)
        return result

    def daily_history(self, start, end, timezone_name="Europe/London", client_ip=None):
        start, end = self._validate_range(start, end)
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone: {timezone_name}") from exc
        extra = ""
        flow_params = [timezone_name, start, end]
        dns_params = [timezone_name, start, end]
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            flow_params.append(client_ip)
            dns_params.append(client_ip)
        flow_rows = self._query(f"""
            SELECT (bucket AT TIME ZONE %s)::date AS day,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE NULLIF(service,'') IS NOT NULL),0) AS classified_bytes,
                   COALESCE(sum(flows),0) AS flows,
                   count(DISTINCT client_ip) AS devices
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s{extra}
            GROUP BY 1 ORDER BY 1
        """, tuple(flow_params))
        dns_rows = self._query(f"""
            SELECT (event_time AT TIME ZONE %s)::date AS day,
                   count(*) AS dns_queries,
                   count(*) FILTER (WHERE blocked) AS dns_blocked,
                   count(*) FILTER (WHERE NULLIF(service,'') IS NOT NULL) AS classified_queries,
                   count(DISTINCT domain) AS unique_domains
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{extra}
            GROUP BY 1 ORDER BY 1
        """, tuple(dns_params))
        merged = {}
        for row in flow_rows:
            key = row["day"].isoformat()
            merged[key] = {
                "day": key,
                "total_bytes": int(row.get("total_bytes") or 0),
                "download_bytes": int(row.get("download_bytes") or 0),
                "upload_bytes": int(row.get("upload_bytes") or 0),
                "classified_bytes": int(row.get("classified_bytes") or 0),
                "flows": int(row.get("flows") or 0),
                "devices": int(row.get("devices") or 0),
            }
        for row in dns_rows:
            key = row["day"].isoformat()
            item = merged.setdefault(key, {"day": key, "total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "classified_bytes": 0, "flows": 0, "devices": 0})
            item.update({
                "dns_queries": int(row.get("dns_queries") or 0),
                "dns_blocked": int(row.get("dns_blocked") or 0),
                "classified_queries": int(row.get("classified_queries") or 0),
                "unique_domains": int(row.get("unique_domains") or 0),
            })
        rows = [merged[key] for key in sorted(merged)]
        max_bytes = max([item["total_bytes"] for item in rows] or [1])
        for item in rows:
            item.setdefault("dns_queries", 0)
            item.setdefault("dns_blocked", 0)
            item.setdefault("classified_queries", 0)
            item.setdefault("unique_domains", 0)
            item["total_bytes_human"] = _format_bytes(item["total_bytes"])
            item["download_bytes_human"] = _format_bytes(item["download_bytes"])
            item["upload_bytes_human"] = _format_bytes(item["upload_bytes"])
            item["traffic_observed"] = item["total_bytes"] > 0
            item["dns_observed"] = item["dns_queries"] > 0
            item["traffic_percent"] = round(item["classified_bytes"] * 100 / item["total_bytes"], 1) if item["traffic_observed"] else None
            item["dns_percent"] = round(item["classified_queries"] * 100 / item["dns_queries"], 1) if item["dns_observed"] else None
            item["bar_percent"] = round(item["total_bytes"] * 100 / max_bytes, 1) if max_bytes else 0
        return rows

    def top_devices_range(self, start, end, limit=20):
        start, end = self._validate_range(start, end)
        limit = max(1, min(int(limit), 100))
        rows = self._query("""
            SELECT client_ip, COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   COALESCE(sum(flows),0) AS flows, min(bucket) AS first_seen, max(bucket) AS last_seen
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s AND client_ip <> ''
            GROUP BY client_ip ORDER BY total_bytes DESC LIMIT %s
        """, (start, end, limit))
        total = sum(int(item.get("total_bytes") or 0) for item in rows) or 1
        for item in rows:
            for key in ("total_bytes", "download_bytes", "upload_bytes"):
                item[key] = int(item.get(key) or 0)
                item[key + "_human"] = _format_bytes(item[key])
            item["flows"] = int(item.get("flows") or 0)
            item["percent"] = round(item["total_bytes"] * 100 / total, 1)
            item["first_seen"] = item["first_seen"].isoformat() if item.get("first_seen") else None
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        return rows

    def top_services_range(self, start, end, limit=20, client_ip=None):
        start, end = self._validate_range(start, end)
        params = [start, end]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(max(1, min(int(limit), 100)))
        rows = self._query(f"""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows,
                   min(bucket) AS first_seen, max(bucket) AS last_seen
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s{extra}
            GROUP BY service_name ORDER BY total_bytes DESC LIMIT %s
        """, tuple(params))
        total = sum(int(item.get("total_bytes") or 0) for item in rows) or 1
        for item in rows:
            item["total_bytes"] = int(item.get("total_bytes") or 0)
            item["total_bytes_human"] = _format_bytes(item["total_bytes"])
            item["flows"] = int(item.get("flows") or 0)
            item["percent"] = round(item["total_bytes"] * 100 / total, 1)
            item["first_seen"] = item["first_seen"].isoformat() if item.get("first_seen") else None
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        return rows

    def top_domains_range(self, start, end, limit=40, client_ip=None):
        start, end = self._validate_range(start, end)
        params = [start, end]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(max(1, min(int(limit), 200)))
        rows = self._query(f"""
            SELECT domain, COALESCE(max(NULLIF(service,'')),'') AS service,
                   count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS devices, min(event_time) AS first_seen, max(event_time) AS last_seen
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{extra} AND domain <> ''
            GROUP BY domain ORDER BY queries DESC LIMIT %s
        """, tuple(params))
        for item in rows:
            for key in ("queries", "blocked", "devices"):
                item[key] = int(item.get(key) or 0)
            item["first_seen"] = item["first_seen"].isoformat() if item.get("first_seen") else None
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        return rows

    def blocked_domains_range(self, start, end, limit=40, client_ip=None):
        """Return DNS names blocked during an explicit retained activity window."""
        start, end = self._validate_range(start, end)
        params = [start, end]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        params.append(max(1, min(int(limit), 200)))
        rows = self._query(f"""
            SELECT domain, COALESCE(max(NULLIF(service,'')),'') AS service,
                   count(*) AS queries, count(*) AS blocked,
                   count(DISTINCT client_ip) AS devices,
                   min(event_time) AS first_seen, max(event_time) AS last_seen
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{extra}
              AND blocked AND domain <> ''
            GROUP BY domain
            ORDER BY blocked DESC, last_seen DESC, domain ASC LIMIT %s
        """, tuple(params))
        for item in rows:
            for key in ("queries", "blocked", "devices"):
                item[key] = int(item.get(key) or 0)
            item["first_seen"] = item["first_seen"].isoformat() if item.get("first_seen") else None
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        return rows

    def new_domains_range(self, start, end, lookback_days=30, limit=40, client_ip=None):
        start, end = self._validate_range(start, end)
        lookback_days = max(1, min(int(lookback_days), 180))
        limit = max(1, min(int(limit), 200))
        params = [start, end]
        current_extra = ""
        old_extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            current_extra = " AND q.client_ip=%s"
            old_extra = " AND old.client_ip=%s"
            params.append(client_ip)
        params.extend([start - timedelta(days=lookback_days), start])
        if client_ip:
            params.append(client_ip)
        params.append(limit)
        rows = self._query(f"""
            SELECT q.domain, COALESCE(max(NULLIF(q.service,'')),'') AS service,
                   count(*) AS queries, count(*) FILTER (WHERE q.blocked) AS blocked,
                   count(DISTINCT q.client_ip) AS devices, min(q.event_time) AS first_seen, max(q.event_time) AS last_seen
            FROM dns_queries q
            WHERE q.event_time >= %s AND q.event_time < %s{current_extra}
              AND q.domain <> ''
              AND NOT EXISTS (
                  SELECT 1 FROM dns_queries old
                  WHERE old.domain=q.domain AND old.event_time >= %s AND old.event_time < %s{old_extra}
              )
            GROUP BY q.domain ORDER BY queries DESC, first_seen DESC LIMIT %s
        """, tuple(params))
        for item in rows:
            for key in ("queries", "blocked", "devices"):
                item[key] = int(item.get(key) or 0)
            item["first_seen"] = item["first_seen"].isoformat() if item.get("first_seen") else None
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
        return rows

    def active_periods(self, client_ip, start, end, gap_minutes=30, limit=40):
        ipaddress.ip_address(client_ip)
        start, end = self._validate_range(start, end)
        gap = max(10, min(int(gap_minutes), 120))
        rows = self._query("""
            SELECT bucket, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE client_ip=%s AND bucket >= %s AND bucket < %s
            GROUP BY bucket ORDER BY bucket
        """, (client_ip, start, end))
        periods = []
        current = None
        for row in rows:
            when = row.get("bucket")
            if not when:
                continue
            total_bytes = int(row.get("total_bytes") or 0)
            flows = int(row.get("flows") or 0)
            if current is None or when - current["last_bucket"] > timedelta(minutes=gap):
                if current:
                    periods.append(current)
                current = {"start_dt": when, "end_dt": when + timedelta(minutes=5), "last_bucket": when, "total_bytes": total_bytes, "flows": flows, "buckets": 1}
            else:
                current["end_dt"] = when + timedelta(minutes=5)
                current["last_bucket"] = when
                current["total_bytes"] += total_bytes
                current["flows"] += flows
                current["buckets"] += 1
        if current:
            periods.append(current)
        formatted = []
        for item in reversed(periods[-limit:]):
            duration = max(5, int((item["end_dt"] - item["start_dt"]).total_seconds() / 60))
            formatted.append({
                "start": item["start_dt"].isoformat(), "end": item["end_dt"].isoformat(),
                "duration_minutes": duration, "total_bytes": item["total_bytes"],
                "total_bytes_human": _format_bytes(item["total_bytes"]), "flows": item["flows"],
            })
        return formatted

    def policy_interval_usage(self, client_ip, intervals):
        """Aggregate retained traffic/DNS evidence for bounded policy intervals.

        Traffic/IPFIX and DNS are queried independently so one failed retained
        evidence source does not erase a healthy peer. Empty denominators are
        explicit NO EVIDENCE, query failure is UNAVAILABLE, and classification
        percentages are emitted only when the accounting reconciles.

        The caller supplies non-overlapping intervals. Two PostgreSQL queries
        cover the whole report, avoiding per-interval N+1 analytics queries.
        """
        ipaddress.ip_address(client_ip)
        clean = []
        for index, item in enumerate(intervals or []):
            raw_start, raw_end = item.get("start"), item.get("end")
            if isinstance(raw_start, str):
                raw_start = datetime.fromisoformat(raw_start)
            if isinstance(raw_end, str):
                raw_end = datetime.fromisoformat(raw_end)
            start, end = self._validate_range(raw_start, raw_end)
            clean.append((index, start, end))
        if not clean:
            return []
        if len(clean) > 800:
            raise ValueError("Policy correlation is limited to 800 state intervals")

        values = ",".join(["(%s,%s,%s)"] * len(clean))
        interval_params = []
        for index, start, end in clean:
            interval_params.extend([index, start, end])

        traffic_available = True
        dns_available = True
        try:
            flow_rows = self._query(f"""
                WITH intervals(idx, start_at, end_at) AS (VALUES {values})
                SELECT i.idx, COALESCE(sum(f.bytes),0) AS total_bytes,
                       COALESCE(sum(f.bytes) FILTER (WHERE f.direction='download'),0) AS download_bytes,
                       COALESCE(sum(f.bytes) FILTER (WHERE f.direction='upload'),0) AS upload_bytes,
                       COALESCE(sum(f.bytes) FILTER (WHERE NULLIF(f.service,'') IS NOT NULL),0) AS classified_bytes,
                       COALESCE(sum(f.bytes) FILTER (WHERE NULLIF(f.service,'') IS NULL),0) AS unclassified_bytes,
                       COALESCE(sum(f.flows),0) AS flows
                FROM intervals i
                LEFT JOIN flow_5m f ON f.client_ip=%s AND f.bucket >= i.start_at AND f.bucket < i.end_at
                GROUP BY i.idx ORDER BY i.idx
            """, tuple(interval_params + [str(client_ip)]))
        except ActivityError:
            traffic_available = False
            flow_rows = []

        try:
            dns_rows = self._query(f"""
                WITH intervals(idx, start_at, end_at) AS (VALUES {values})
                SELECT i.idx, count(d.event_time) AS dns_queries,
                       count(d.event_time) FILTER (WHERE NULLIF(d.service,'') IS NOT NULL) AS dns_classified_queries,
                       count(d.event_time) FILTER (WHERE NULLIF(d.service,'') IS NULL) AS dns_unclassified_queries,
                       count(d.event_time) FILTER (WHERE d.blocked) AS dns_blocked,
                       count(DISTINCT d.domain) AS unique_domains
                FROM intervals i
                LEFT JOIN dns_queries d ON d.client_ip=%s AND d.event_time >= i.start_at AND d.event_time < i.end_at
                GROUP BY i.idx ORDER BY i.idx
            """, tuple(interval_params + [str(client_ip)]))
        except ActivityError:
            dns_available = False
            dns_rows = []

        merged = {index: {"index": index} for index, _, _ in clean}
        for row in flow_rows:
            item = merged[int(row["idx"])]
            item.update({
                "total_bytes": int(row.get("total_bytes") or 0),
                "download_bytes": int(row.get("download_bytes") or 0),
                "upload_bytes": int(row.get("upload_bytes") or 0),
                "classified_bytes": int(row.get("classified_bytes") or 0),
                "unclassified_bytes": int(row.get("unclassified_bytes") or 0),
                "flows": int(row.get("flows") or 0),
            })
        for row in dns_rows:
            item = merged[int(row["idx"])]
            item.update({
                "dns_queries": int(row.get("dns_queries") or 0),
                "dns_classified_queries": int(row.get("dns_classified_queries") or 0),
                "dns_unclassified_queries": int(row.get("dns_unclassified_queries") or 0),
                "dns_blocked": int(row.get("dns_blocked") or 0),
                "unique_domains": int(row.get("unique_domains") or 0),
            })

        result = []
        for index, _, _ in clean:
            item = merged[index]

            if traffic_available:
                for key in (
                    "total_bytes", "download_bytes", "upload_bytes",
                    "classified_bytes", "unclassified_bytes", "flows",
                ):
                    item.setdefault(key, 0)
                flow = {
                    "total_bytes": item["total_bytes"],
                    "classified_bytes": item["classified_bytes"],
                    "unclassified_bytes": item["unclassified_bytes"],
                    "service_labels": 0,
                }
            else:
                for key in (
                    "total_bytes", "download_bytes", "upload_bytes",
                    "classified_bytes", "unclassified_bytes", "flows",
                ):
                    item[key] = None
                flow = None

            if dns_available:
                for key in (
                    "dns_queries", "dns_classified_queries",
                    "dns_unclassified_queries", "dns_blocked",
                    "unique_domains",
                ):
                    item.setdefault(key, 0)
                dns = {
                    "queries": item["dns_queries"],
                    "classified_queries": item["dns_classified_queries"],
                    "unclassified_queries": item["dns_unclassified_queries"],
                    "unknown_domains": 0,
                }
            else:
                for key in (
                    "dns_queries", "dns_classified_queries",
                    "dns_unclassified_queries", "dns_blocked",
                    "unique_domains",
                ):
                    item[key] = None
                dns = None

            coverage = self._classification_coverage_result(flow, dns)

            # Use the helper's bounded presentation counters as the retained
            # interval values too. The raw counters above are intentionally fed
            # into the helper first so malformed negative accounting remains
            # INCONSISTENT rather than being sanitised into a plausible ratio.
            if traffic_available:
                item["total_bytes"] = coverage["total_bytes"]
                item["classified_bytes"] = coverage["classified_bytes"]
                item["unclassified_bytes"] = coverage["unclassified_bytes"]
                item["download_bytes"] = max(0, int(item.get("download_bytes") or 0))
                item["upload_bytes"] = max(0, int(item.get("upload_bytes") or 0))
                item["flows"] = max(0, int(item.get("flows") or 0))
            if dns_available:
                item["dns_queries"] = coverage["dns_queries"]
                item["dns_classified_queries"] = coverage["dns_classified_queries"]
                item["dns_unclassified_queries"] = coverage["dns_unclassified_queries"]
                item["dns_blocked"] = max(0, int(item.get("dns_blocked") or 0))
                item["unique_domains"] = max(0, int(item.get("unique_domains") or 0))

            item.update({
                "traffic_available": coverage["traffic_available"],
                "traffic_observed": coverage["traffic_observed"],
                "traffic_evidence_status": coverage["traffic_evidence_status"],
                "traffic_accounting_valid": coverage["traffic_accounting_valid"],
                "dns_available": coverage["dns_available"],
                "dns_observed": coverage["dns_observed"],
                "dns_evidence_status": coverage["dns_evidence_status"],
                "dns_accounting_valid": coverage["dns_accounting_valid"],
                "evidence_status": coverage["evidence_status"],
                "classified_percent": coverage["traffic_percent"],
                "dns_classified_percent": coverage["dns_percent"],
            })

            for key in (
                "total_bytes", "download_bytes", "upload_bytes",
                "classified_bytes", "unclassified_bytes",
            ):
                item[key + "_human"] = (
                    _format_bytes(item[key]) if item[key] is not None else None
                )
            result.append(item)
        return result


    def evidence_timeline(self, start, end, client_ip=None, limit=140):
        start, end = self._validate_range(start, end)
        limit = max(20, min(int(limit), 300))
        flow_params = [start, end]
        dns_params = [start, end]
        flow_extra = ""
        dns_extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            flow_extra = " AND client_ip=%s"
            dns_extra = " AND client_ip=%s"
            flow_params.append(client_ip)
            dns_params.append(client_ip)
        flow_params.append(limit)
        dns_params.append(limit)
        flows = self._query(f"""
            SELECT date_bin(interval '30 minutes', bucket, timestamptz '2001-01-01') AS event_time,
                   client_ip, CASE WHEN service='' THEN 'Other' ELSE service END AS service,
                   COALESCE(max(NULLIF(domain,'')),'') AS domain,
                   COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s{flow_extra}
            GROUP BY 1, client_ip, service ORDER BY event_time DESC, total_bytes DESC LIMIT %s
        """, tuple(flow_params))
        blocked = self._query(f"""
            SELECT date_trunc('minute', event_time) AS event_time, client_ip, domain,
                   COALESCE(max(NULLIF(service,'')),'') AS service, count(*) AS blocked
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{dns_extra} AND blocked
            GROUP BY 1, client_ip, domain ORDER BY event_time DESC LIMIT %s
        """, tuple(dns_params))
        events = []
        for item in flows:
            events.append({
                "event_time": item["event_time"], "kind": "traffic", "client_ip": str(item.get("client_ip") or ""),
                "service": str(item.get("service") or "Other"), "domain": str(item.get("domain") or ""),
                "total_bytes": int(item.get("total_bytes") or 0), "total_bytes_human": _format_bytes(item.get("total_bytes") or 0),
                "flows": int(item.get("flows") or 0), "blocked": 0,
            })
        for item in blocked:
            events.append({
                "event_time": item["event_time"], "kind": "blocked_dns", "client_ip": str(item.get("client_ip") or ""),
                "service": str(item.get("service") or ""), "domain": str(item.get("domain") or ""),
                "total_bytes": 0, "total_bytes_human": "0 B", "flows": 0, "blocked": int(item.get("blocked") or 0),
            })
        events.sort(key=lambda item: item["event_time"], reverse=True)
        for item in events[:limit]:
            item["event_time"] = item["event_time"].isoformat() if item.get("event_time") else None
        return events[:limit]

    def classification_history(self, start, end, timezone_name="Europe/London", client_ip=None):
        return self.daily_history(start, end, timezone_name, client_ip)

    def traffic_series(self, client_ip=None, hours=24, bucket_minutes=30):
        params = [int(hours)]
        extra = ""
        if client_ip:
            ipaddress.ip_address(client_ip)
            extra = " AND client_ip=%s"
            params.append(client_ip)
        bucket = max(5, min(int(bucket_minutes), 240))
        rows = self._query(f"""
            SELECT date_bin(interval '{bucket} minutes', bucket, timestamptz '2001-01-01') AS bucket,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour'){extra}
            GROUP BY 1 ORDER BY 1
        """, tuple(params))
        max_value = max([int(r["download_bytes"]) + int(r["upload_bytes"]) for r in rows] or [1])
        for row in rows:
            row["bucket"] = row["bucket"].isoformat()
            row["download_bytes"] = int(row["download_bytes"])
            row["upload_bytes"] = int(row["upload_bytes"])
            row["download_human"] = _format_bytes(row["download_bytes"])
            row["upload_human"] = _format_bytes(row["upload_bytes"])
            row["height"] = max(3, round((row["download_bytes"] + row["upload_bytes"]) * 100 / max_value))
        return rows


def build_service_intelligence(
    service_defs,
    observed_rows,
    dns_rows,
    router_health=None,
    policy_groups=None,
    profiles=None,
):
    """Build a stats-heavy, policy-aware service classification view."""
    base = build_policy_service_activity(service_defs, observed_rows, policy_groups, profiles)
    defs = {str(item.get("key") or ""): dict(item) for item in service_defs or []}
    dns_by_token = {}
    for row in dns_rows or []:
        name = str(row.get("service_name") or "Other")
        token = _service_token(name)
        bucket = dns_by_token.setdefault(token, {"queries": 0, "blocked": 0})
        bucket["queries"] += int(row.get("queries") or 0)
        bucket["blocked"] += int(row.get("blocked") or 0)
    health_by_key = {
        str(item.get("key") or ""): dict(item)
        for item in (router_health or {}).get("services", [])
    }

    for row in base:
        key = str(row.get("key") or "")
        definition = defs.get(key, {})
        tokens = {_service_token(row.get("name")), _service_token(key)}
        for member_key in row.get("members") or []:
            member = defs.get(str(member_key), {})
            tokens.update({_service_token(member_key), _service_token(member.get("name"))})
        queries = blocked = 0
        for token in tokens:
            if token and token in dns_by_token:
                queries += dns_by_token[token]["queries"]
                blocked += dns_by_token[token]["blocked"]
        health = health_by_key.get(key)
        row.update({
            "category": definition.get("category") or "other",
            "dns_suffixes": list(definition.get("dns_suffixes") or []),
            "tls_patterns": list(definition.get("tls_patterns") or []),
            "classifier_enabled": bool(definition.get("classifier_enabled", True)),
            "routeros_managed": bool(definition.get("routeros_managed")),
            "dns_queries": queries,
            "dns_blocked": blocked,
            "router_health": health or {},
            "detector_addresses": int((health or {}).get("detector_addresses") or 0),
        })
        if row.get("kind") == "group":
            row["classification_status"] = "aggregate"
        elif health and health.get("status") in {"reporting", "absent"}:
            row["classification_status"] = "reporting"
        elif health and health.get("status") == "orphaned":
            row["classification_status"] = "degraded"
        elif health:
            row["classification_status"] = "healthy" if health.get("healthy") else "degraded"
        elif definition.get("dns_suffixes") or definition.get("tls_patterns"):
            row["classification_status"] = "reporting"
        elif row.get("policy_tracked"):
            row["classification_status"] = "unsigned"
        else:
            row["classification_status"] = "observed"
        row["last_signal"] = "TLS/SNI + DNS" if health and health.get("healthy") else (
            "DNS classification" if definition.get("dns_suffixes") else "Telemetry label"
        )
    return base
