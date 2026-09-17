import ipaddress
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
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
        self._session_connection = ContextVar(
            f"zen_activity_session_connection_{id(self)}", default=None
        )

    def _connect(self):
        with perf_span("postgres.connect"):
            return psycopg.connect(
                host=self.host, port=self.port, dbname=self.database,
                user=self.username, password=self.password,
                connect_timeout=self.timeout, row_factory=dict_row,
            )

    @contextmanager
    def coherent_session(self):
        """Reuse one PostgreSQL connection for one coherent read bundle.

        Activity preparation is read-only. Reusing the connection removes repeated
        TCP/authentication overhead while keeping every SQL statement visible to
        the existing performance instrumentation. Nested callers reuse the outer
        session, so helpers can opt in without creating connection ownership races.
        """
        existing = self._session_connection.get()
        if existing is not None:
            yield self
            return

        conn = None
        token = None
        try:
            conn = self._connect()
            token = self._session_connection.set(conn)
            yield self
            conn.commit()
        except psycopg.Error as exc:
            if conn is not None:
                try:
                    conn.rollback()
                except psycopg.Error:
                    pass
            raise ActivityError(f"Telemetry database unavailable: {exc}") from exc
        finally:
            if token is not None:
                self._session_connection.reset(token)
            if conn is not None:
                conn.close()

    def _query(self, sql, params=()):
        try:
            with perf_sql(sql):
                conn = self._session_connection.get()
                if conn is not None:
                    with conn.cursor() as cur:
                        cur.execute(sql, params)
                        return cur.fetchall()
                with self._connect() as owned_conn:
                    with owned_conn.cursor() as cur:
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

    def service_matrix(self, hours=24, limit=100):
        """Return bounded retained service aggregates for the concrete matrix.

        These are deliberately two catalogue-wide, parameterized aggregates --
        one per retained evidence source -- rather than a query per configured
        service.  The caller joins the results to the current configuration in
        memory, so opening Activity cannot turn a growing service catalogue into
        database or RouterOS fan-out.
        """
        hours = max(1, min(int(hours), 24 * 31))
        limit = max(1, min(int(limit), 200))
        traffic = self._query("""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows,
                   count(DISTINCT client_ip) AS traffic_devices, max(bucket) AS last_flow
            FROM flow_5m
            WHERE bucket >= now() - (%s * interval '1 hour')
            GROUP BY service_name ORDER BY total_bytes DESC LIMIT %s
        """, (hours, limit))
        dns = self._query("""
            SELECT CASE WHEN service='' THEN 'Other' ELSE service END AS service_name,
                   count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS dns_devices,
                   count(DISTINCT domain) AS domains, max(event_time) AS last_dns
            FROM dns_queries
            WHERE event_time >= now() - (%s * interval '1 hour')
            GROUP BY service_name ORDER BY queries DESC LIMIT %s
        """, (hours, limit))
        for row in traffic:
            row["total_bytes"] = int(row.get("total_bytes") or 0)
            row["flows"] = int(row.get("flows") or 0)
            row["traffic_devices"] = int(row.get("traffic_devices") or 0)
            row["last_flow"] = row["last_flow"].isoformat() if row.get("last_flow") else None
        for row in dns:
            row["queries"] = int(row.get("queries") or 0)
            row["blocked"] = int(row.get("blocked") or 0)
            row["dns_devices"] = int(row.get("dns_devices") or 0)
            row["domains"] = int(row.get("domains") or 0)
            row["last_dns"] = row["last_dns"].isoformat() if row.get("last_dns") else None
        return traffic, dns

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

    @staticmethod
    def _service_evidence(row, prefix, metrics):
        """Keep an empty retained source distinct from a measured zero.

        The aggregate queries include a record count as well as metric totals.
        That lets callers distinguish a real zero within observed samples (for
        example, zero blocked DNS queries) from a range for which the source
        supplied no retained samples at all.
        """
        records = row.get(prefix + "_records")
        if records is None:
            return {"status": "unavailable", "values": {key: None for key in metrics}}
        records = int(records or 0)
        values = {key: int(row.get(prefix + "_" + key) or 0) for key in metrics}
        if records < 0 or any(value < 0 for value in values.values()):
            return {"status": "inconsistent", "values": {key: None for key in metrics}}
        if not records:
            return {"status": "no_evidence", "values": {key: None for key in metrics}}
        return {"status": "measured", "values": values}

    @staticmethod
    def _service_change(current, previous):
        if current is None or previous is None:
            return {"current": current, "previous": previous, "delta": None, "delta_percent": None}
        delta = current - previous
        return {
            "current": current,
            "previous": previous,
            "delta": delta,
            # A percentage against a zero baseline is deliberately undefined.
            "delta_percent": round(delta * 100 / previous, 1) if previous else None,
        }

    def service_historical_analytics(self, start, end, timezone_name="Europe/London", client_ip=None, service_name=None, limit=30):
        """Return bounded per-service current/previous analytics in six queries.

        All services are compared from the same two aggregate scans.  The
        supporting device/domain and trend scans are likewise batched by
        service, avoiding per-service database fan-out for movers or detail.
        """
        start, end = self._validate_range(start, end)
        try:
            tz = ZoneInfo(str(timezone_name or "Europe/London"))
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone: {timezone_name}") from exc
        selected_client = str(client_ip or "").strip()
        if selected_client:
            selected_client = str(ipaddress.ip_address(selected_client))
        selected_service = str(service_name or "").strip()
        limit = max(1, min(int(limit), 100))
        previous_start = start - (end - start)
        service_filter = " AND lower(service)=lower(%s)" if selected_service else ""
        client_filter = " AND client_ip=%s" if selected_client else ""
        suffix_params = (() if not selected_service else (selected_service,)) + (() if not selected_client else (selected_client,))
        errors = []

        def query(source, sql, params):
            try:
                return self._query(sql, params)
            except ActivityError as exc:
                errors.append({"source": source, "error": str(exc)})
                return None

        # The first two queries each aggregate both equivalent windows.
        flow_rows = query("traffic", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   count(*) FILTER (WHERE bucket >= %s AND bucket < %s) AS current_records,
                   COALESCE(sum(bytes) FILTER (WHERE bucket >= %s AND bucket < %s),0) AS current_total_bytes,
                   COALESCE(sum(flows) FILTER (WHERE bucket >= %s AND bucket < %s),0) AS current_flows,
                   count(DISTINCT client_ip) FILTER (WHERE bucket >= %s AND bucket < %s) AS current_active_devices,
                   count(*) FILTER (WHERE bucket >= %s AND bucket < %s) AS previous_records,
                   COALESCE(sum(bytes) FILTER (WHERE bucket >= %s AND bucket < %s),0) AS previous_total_bytes,
                   COALESCE(sum(flows) FILTER (WHERE bucket >= %s AND bucket < %s),0) AS previous_flows,
                   count(DISTINCT client_ip) FILTER (WHERE bucket >= %s AND bucket < %s) AS previous_active_devices
            FROM flow_5m
            WHERE bucket >= %s AND bucket < %s{service_filter}{client_filter}
            GROUP BY service_name
        """, (start, end, start, end, start, end, start, end,
                previous_start, start, previous_start, start, previous_start, start, previous_start, start,
                previous_start, end) + suffix_params)
        dns_rows = query("dns", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s) AS current_records,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s) AS current_dns_queries,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s AND blocked) AS current_dns_blocked,
                   count(DISTINCT client_ip) FILTER (WHERE event_time >= %s AND event_time < %s) AS current_active_devices,
                   count(DISTINCT domain) FILTER (WHERE event_time >= %s AND event_time < %s) AS current_domains,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s) AS previous_records,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s) AS previous_dns_queries,
                   count(*) FILTER (WHERE event_time >= %s AND event_time < %s AND blocked) AS previous_dns_blocked,
                   count(DISTINCT client_ip) FILTER (WHERE event_time >= %s AND event_time < %s) AS previous_active_devices,
                   count(DISTINCT domain) FILTER (WHERE event_time >= %s AND event_time < %s) AS previous_domains
            FROM dns_queries
            WHERE event_time >= %s AND event_time < %s{service_filter}{client_filter}
            GROUP BY service_name
        """, (start, end, start, end, start, end, start, end, start, end,
                previous_start, start, previous_start, start, previous_start, start, previous_start, start, previous_start, start,
                previous_start, end) + suffix_params)

        device_rows = query("top_devices", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   client_ip, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows,
                   max(bucket) AS last_seen
            FROM flow_5m WHERE bucket >= %s AND bucket < %s{service_filter}{client_filter}
            GROUP BY service_name, client_ip ORDER BY total_bytes DESC
        """, (start, end) + suffix_params)
        domain_rows = query("top_domains", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   domain, count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS devices, max(event_time) AS last_seen
            FROM dns_queries WHERE event_time >= %s AND event_time < %s AND domain <> ''{service_filter}{client_filter}
            GROUP BY service_name, domain ORDER BY queries DESC
        """, (start, end) + suffix_params)
        flow_trends = query("traffic_trends", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   date_trunc('hour', bucket) AS bucket, count(*) AS records,
                   COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m WHERE bucket >= %s AND bucket < %s{service_filter}{client_filter}
            GROUP BY service_name, bucket ORDER BY bucket
        """, (start, end) + suffix_params)
        dns_trends = query("dns_trends", f"""
            SELECT CASE WHEN NULLIF(service,'') IS NULL THEN 'Other' ELSE service END AS service_name,
                   date_trunc('hour', event_time) AS bucket, count(*) AS records,
                   count(*) FILTER (WHERE blocked) AS dns_blocked, count(DISTINCT domain) AS domains
            FROM dns_queries WHERE event_time >= %s AND event_time < %s{service_filter}{client_filter}
            GROUP BY service_name, bucket ORDER BY bucket
        """, (start, end) + suffix_params)

        merged = {}
        names = set()
        for rows in (flow_rows or [], dns_rows or [], device_rows or [], domain_rows or [], flow_trends or [], dns_trends or []):
            names.update(str(row.get("service_name") or "Other") for row in rows)
        if selected_service:
            names.add(selected_service)
        for name in names:
            merged[name] = {"service_name": name, "_flow": {}, "_dns": {}, "top_devices": [], "top_domains": [], "hourly": {}}
        for row in flow_rows or []:
            merged[str(row.get("service_name") or "Other")]["_flow"] = row
        for row in dns_rows or []:
            merged[str(row.get("service_name") or "Other")]["_dns"] = row
        for row in device_rows or []:
            item = dict(row); item["total_bytes"] = int(item.get("total_bytes") or 0); item["flows"] = int(item.get("flows") or 0)
            item["total_bytes_human"] = _format_bytes(item["total_bytes"])
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
            merged[str(item.get("service_name") or "Other")]["top_devices"].append(item)
        for row in domain_rows or []:
            item = dict(row)
            for key in ("queries", "blocked", "devices"): item[key] = int(item.get(key) or 0)
            item["last_seen"] = item["last_seen"].isoformat() if item.get("last_seen") else None
            merged[str(item.get("service_name") or "Other")]["top_domains"].append(item)
        for rows, kind in ((flow_trends or [], "traffic"), (dns_trends or [], "dns")):
            for row in rows:
                name = str(row.get("service_name") or "Other")
                bucket = row.get("bucket")
                if not bucket: continue
                item = merged[name]["hourly"].setdefault(bucket, {"bucket": bucket, "traffic_records": None, "dns_records": None})
                if kind == "traffic": item.update({"traffic_records": int(row.get("records") or 0), "total_bytes": int(row.get("total_bytes") or 0), "flows": int(row.get("flows") or 0)})
                else: item.update({"dns_records": int(row.get("records") or 0), "dns_queries": int(row.get("records") or 0), "dns_blocked": int(row.get("dns_blocked") or 0), "domains": int(row.get("domains") or 0)})

        services = []
        for item in merged.values():
            flow = item.pop("_flow"); dns = item.pop("_dns")
            current_flow = self._service_evidence(flow, "current", ("total_bytes", "flows", "active_devices")) if flow_rows is not None else self._service_evidence({}, "current", ("total_bytes", "flows", "active_devices"))
            previous_flow = self._service_evidence(flow, "previous", ("total_bytes", "flows", "active_devices")) if flow_rows is not None else self._service_evidence({}, "previous", ("total_bytes", "flows", "active_devices"))
            current_dns = self._service_evidence(dns, "current", ("dns_queries", "dns_blocked", "active_devices", "domains")) if dns_rows is not None else self._service_evidence({}, "current", ("dns_queries", "dns_blocked", "active_devices", "domains"))
            previous_dns = self._service_evidence(dns, "previous", ("dns_queries", "dns_blocked", "active_devices", "domains")) if dns_rows is not None else self._service_evidence({}, "previous", ("dns_queries", "dns_blocked", "active_devices", "domains"))
            current = {**current_flow["values"], **current_dns["values"]}
            previous = {**previous_flow["values"], **previous_dns["values"]}
            current["active_devices"] = max((value for value in (current_flow["values"]["active_devices"], current_dns["values"]["active_devices"]) if value is not None), default=None)
            previous["active_devices"] = max((value for value in (previous_flow["values"]["active_devices"], previous_dns["values"]["active_devices"]) if value is not None), default=None)
            hourly = []
            for trend in item["hourly"].values():
                stamp = trend.pop("bucket")
                trend["traffic_evidence_status"] = "measured" if trend.get("traffic_records") else ("no_evidence" if flow_trends is not None else "unavailable")
                trend["dns_evidence_status"] = "measured" if trend.get("dns_records") else ("no_evidence" if dns_trends is not None else "unavailable")
                trend["bucket"] = stamp.isoformat()
                hourly.append(trend)
            hourly.sort(key=lambda row: row["bucket"])
            daily = {}
            for trend in hourly:
                day = datetime.fromisoformat(trend["bucket"]).astimezone(tz).date().isoformat()
                day_row = daily.setdefault(day, {"day": day, "total_bytes": 0, "flows": 0, "dns_queries": 0, "dns_blocked": 0, "traffic_records": 0, "dns_records": 0})
                for key in ("total_bytes", "flows", "dns_queries", "dns_blocked", "traffic_records", "dns_records"): day_row[key] += int(trend.get(key) or 0)
            item.update({
                "current": current, "previous": previous,
                "comparison": {key: self._service_change(current.get(key), previous.get(key)) for key in current},
                "traffic_evidence": {"current": current_flow["status"], "previous": previous_flow["status"]},
                "dns_evidence": {"current": current_dns["status"], "previous": previous_dns["status"]},
                "dns_blocked_evidence": "zero_when_proven" if current_dns["status"] == "measured" and current.get("dns_blocked") == 0 else current_dns["status"],
                "hourly": hourly, "daily": [daily[key] for key in sorted(daily)],
                "top_devices": item["top_devices"][:10], "top_domains": item["top_domains"][:20],
            })
            item["total_bytes"] = current.get("total_bytes")
            item["total_bytes_human"] = _format_bytes(item["total_bytes"]) if item["total_bytes"] is not None else None
            services.append(item)
        services.sort(key=lambda row: (row["current"].get("total_bytes") is not None, row["current"].get("total_bytes") or 0), reverse=True)
        movers = [row for row in services if row["comparison"]["total_bytes"]["delta"] is not None]
        movers.sort(key=lambda row: abs(row["comparison"]["total_bytes"]["delta"]), reverse=True)
        return {
            "schema": "zen_service_historical_analytics_v1", "query_count": 6,
            "window": {"start": start.isoformat(), "end": end.isoformat(), "previous_start": previous_start.isoformat(), "previous_end": start.isoformat(), "timezone": str(tz.key)},
            "services": services[:limit], "movers": movers[:limit], "errors": errors,
        }

    def service_detail(self, service_name, hours=24, start=None, end=None, client_ip=None):
        service_name = str(service_name or "").strip()
        if not service_name:
            raise ValueError("Service name is required")
        if (start is None) != (end is None):
            raise ValueError("Activity range requires both start and end boundaries")
        if start is not None:
            start, end = self._validate_range(start, end)
            flow_window = "bucket >= %s AND bucket < %s"
            dns_window = "event_time >= %s AND event_time < %s"
            window_params = (start, end)
        else:
            hours = max(1, min(int(hours), 24 * 31))
            flow_window = "bucket >= now() - (%s * interval '1 hour')"
            dns_window = "event_time >= now() - (%s * interval '1 hour')"
            window_params = (hours,)
        selected_client = str(client_ip or "").strip()
        if selected_client:
            import ipaddress
            selected_client = str(ipaddress.ip_address(selected_client))

        flow_conditions = [flow_window, "lower(service)=lower(%s)"]
        dns_conditions = [dns_window, "lower(service)=lower(%s)"]
        flow_params = window_params + (service_name,)
        dns_params = window_params + (service_name,)
        if selected_client:
            flow_conditions.append("client_ip=%s")
            dns_conditions.append("client_ip=%s")
            flow_params += (selected_client,)
            dns_params += (selected_client,)
        flow_where = " AND ".join(flow_conditions)
        dns_where = " AND ".join(dns_conditions)

        flow = self._query(f"""
            SELECT COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows,
                   count(DISTINCT client_ip) AS devices, min(bucket) AS first_seen, max(bucket) AS last_seen
            FROM flow_5m
            WHERE {flow_where}
        """, flow_params)[0]
        dns = self._query(f"""
            SELECT count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS dns_devices, count(DISTINCT domain) AS domains,
                   min(event_time) AS dns_first_seen, max(event_time) AS dns_last_seen
            FROM dns_queries
            WHERE {dns_where}
        """, dns_params)[0]
        devices = self._query(f"""
            SELECT client_ip, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows, max(bucket) AS last_seen
            FROM flow_5m
            WHERE {flow_where}
            GROUP BY client_ip ORDER BY total_bytes DESC LIMIT 30
        """, flow_params)
        domains = self._query(f"""
            SELECT domain, count(*) AS queries, count(*) FILTER (WHERE blocked) AS blocked,
                   count(DISTINCT client_ip) AS devices, max(event_time) AS last_seen
            FROM dns_queries
            WHERE {dns_where} AND domain <> ''
            GROUP BY domain ORDER BY queries DESC LIMIT 50
        """, dns_params)
        series = self._query(f"""
            SELECT date_trunc('hour', bucket) AS bucket, COALESCE(sum(bytes),0) AS total_bytes, COALESCE(sum(flows),0) AS flows
            FROM flow_5m
            WHERE {flow_where}
            GROUP BY 1 ORDER BY 1
        """, flow_params)
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

    def service_statistics(self, start, end, bucket_minutes=5):
        """Aggregate retained raw traffic samples by bucket and classification.

        ``flows_raw`` is deliberately the source of truth here: it retains the
        classifier category alongside the individual sample, so the returned
        byte and flow totals reconcile exactly with retained IPFIX evidence.
        """
        start, end = self._validate_range(start, end)
        try:
            bucket_minutes = int(bucket_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Statistics bucket size must be an integer number of minutes") from exc
        if not 1 <= bucket_minutes <= 24 * 60:
            raise ValueError("Statistics bucket size must be between 1 and 1440 minutes")

        rows = self._query(f"""
            SELECT date_bin(interval '{bucket_minutes} minutes', event_time,
                            timestamptz '2001-01-01') AS bucket,
                   COALESCE(NULLIF(category,''), 'unknown') AS category,
                   COALESCE(NULLIF(service,''), 'Unknown') AS service,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip,'')) AS active_clients
            FROM flows_raw
            WHERE event_time >= %s AND event_time < %s
            GROUP BY 1, 2, 3
            ORDER BY 1, 2, 3
        """, (start, end))
        total = self._query("""
            SELECT COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip,'')) AS active_clients
            FROM flows_raw
            WHERE event_time >= %s AND event_time < %s
        """, (start, end))[0]

        buckets = []
        for row in rows:
            buckets.append({
                "bucket": row["bucket"].isoformat(),
                "category": str(row.get("category") or "unknown"),
                "service": str(row.get("service") or "Unknown"),
                "download_bytes": int(row.get("download_bytes") or 0),
                "upload_bytes": int(row.get("upload_bytes") or 0),
                "flows": int(row.get("flows") or 0),
                "active_clients": int(row.get("active_clients") or 0),
            })
        return {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "bucket_minutes": bucket_minutes,
            "buckets": buckets,
            "totals": {
                "download_bytes": int(total.get("download_bytes") or 0),
                "upload_bytes": int(total.get("upload_bytes") or 0),
                "flows": int(total.get("flows") or 0),
                "active_clients": int(total.get("active_clients") or 0),
            },
        }

    def analytics_summary(self, start, end, category_limit=10):
        """Return stable overview KPIs and ranked traffic categories for a range.

        Raw samples retain the classification in effect when the traffic was
        observed.  Keeping this query on ``flows_raw`` therefore avoids applying
        today's catalogue to historical traffic.
        """
        start, end = self._validate_range(start, end)
        try:
            category_limit = int(category_limit)
        except (TypeError, ValueError) as exc:
            raise ValueError("Category limit must be an integer") from exc
        if not 1 <= category_limit <= 100:
            raise ValueError("Category limit must be between 1 and 100")

        categories = self._query("""
            SELECT CASE
                       WHEN lower(trim(COALESCE(category, ''))) IN ('', 'unknown', 'unclassified')
                           THEN 'unknown'
                       ELSE lower(trim(category))
                   END AS category,
                   COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip,'')) AS active_clients,
                   COALESCE(sum(bytes) FILTER (WHERE lower(trim(COALESCE(confidence, ''))) = 'low'),0) AS low_confidence_bytes
            FROM flows_raw
            WHERE event_time >= %s AND event_time < %s
            GROUP BY 1
        """, (start, end))
        totals_row = self._query("""
            SELECT COALESCE(sum(bytes),0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'),0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'),0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip,'')) AS active_clients
            FROM flows_raw
            WHERE event_time >= %s AND event_time < %s
        """, (start, end))[0]
        totals = {
            "total_bytes": int(totals_row.get("total_bytes") or 0),
            "download_bytes": int(totals_row.get("download_bytes") or 0),
            "upload_bytes": int(totals_row.get("upload_bytes") or 0),
            "flows": int(totals_row.get("flows") or 0),
            "active_clients": int(totals_row.get("active_clients") or 0),
        }
        denominator = totals["total_bytes"]
        rows = []
        for row in categories:
            total_bytes = int(row.get("total_bytes") or 0)
            rows.append({
                "category": str(row.get("category") or "unknown"),
                "total_bytes": total_bytes,
                "download_bytes": int(row.get("download_bytes") or 0),
                "upload_bytes": int(row.get("upload_bytes") or 0),
                "flows": int(row.get("flows") or 0),
                "active_clients": int(row.get("active_clients") or 0),
                "low_confidence_bytes": int(row.get("low_confidence_bytes") or 0),
                "percent": round(total_bytes * 100 / denominator, 1) if denominator else 0.0,
            })
        rows.sort(key=lambda item: (-item["total_bytes"], item["category"].casefold(), item["category"]))
        for rank, row in enumerate(rows, start=1):
            row["rank"] = rank
        unknown = next((row for row in rows if row["category"] == "unknown"), None)
        unclassified = {
            "total_bytes": 0,
            "download_bytes": 0,
            "upload_bytes": 0,
            "flows": 0,
            "percent": 0.0,
        }
        if unknown:
            unclassified.update({key: unknown[key] for key in unclassified})
        unknown_bytes = sum(row["total_bytes"] for row in rows if row["category"] == "unknown")
        low_confidence_bytes = sum(
            row["low_confidence_bytes"] for row in rows if row["category"] != "unknown"
        )
        return {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "totals": totals,
            "top_categories": rows[:category_limit],
            "unclassified": unclassified,
            "classification": {
                "classified_bytes": max(0, totals["total_bytes"] - unknown_bytes - low_confidence_bytes),
                "low_confidence_bytes": low_confidence_bytes,
                "unknown_bytes": unknown_bytes,
            },
        }

    def analytics_drilldown(self, start, end, category=None, service=None, client_ip=None, bucket_minutes=5):
        """Return service, client, and time views for one retained-traffic slice."""
        start, end = self._validate_range(start, end)
        try:
            bucket_minutes = int(bucket_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Drill-down bucket size must be an integer number of minutes") from exc
        if not 1 <= bucket_minutes <= 24 * 60:
            raise ValueError("Drill-down bucket size must be between 1 and 1440 minutes")

        category_key = str(category or "").strip().lower() or None
        if category_key in {"unclassified", "unknown"}:
            category_key = "unknown"
        service_key = str(service or "").strip().lower() or None
        requested_client = str(client_ip or "").strip() or None
        if requested_client:
            try:
                requested_client = str(ipaddress.ip_address(requested_client))
            except ValueError:
                return self._empty_analytics_drilldown(start, end, category_key, service_key, requested_client, bucket_minutes)

        category_sql = """CASE
            WHEN lower(trim(COALESCE(category, ''))) IN ('', 'unknown', 'unclassified') THEN 'unknown'
            ELSE lower(trim(category))
        END"""
        filters = ["event_time >= %s", "event_time < %s"]
        params = [start, end]
        if category_key:
            filters.append(f"{category_sql} = %s")
            params.append(category_key)
        if service_key:
            filters.append("COALESCE(NULLIF(lower(trim(service)), ''), 'unknown') = %s")
            params.append(service_key)
        if requested_client:
            filters.append("client_ip = %s")
            params.append(requested_client)
        where = " AND ".join(filters)
        query_params = tuple(params)

        services = self._query(f"""
            SELECT COALESCE(NULLIF(trim(service), ''), 'Unknown') AS service,
                   COALESCE(sum(bytes), 0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'), 0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'), 0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip, '')) AS active_clients
            FROM flows_raw WHERE {where}
            GROUP BY 1 ORDER BY total_bytes DESC, service ASC
        """, query_params)
        clients = self._query(f"""
            SELECT COALESCE(NULLIF(client_ip, ''), 'unknown') AS client_ip,
                   COALESCE(sum(bytes), 0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'), 0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'), 0) AS upload_bytes,
                   count(*) AS flows
            FROM flows_raw WHERE {where}
            GROUP BY 1 ORDER BY total_bytes DESC, client_ip ASC
        """, query_params)
        buckets = self._query(f"""
            SELECT date_bin(interval '{bucket_minutes} minutes', event_time,
                            timestamptz '2001-01-01') AS bucket,
                   COALESCE(sum(bytes), 0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'), 0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'), 0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip, '')) AS active_clients
            FROM flows_raw WHERE {where}
            GROUP BY 1 ORDER BY 1
        """, query_params)
        total = self._query(f"""
            SELECT COALESCE(sum(bytes), 0) AS total_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='download'), 0) AS download_bytes,
                   COALESCE(sum(bytes) FILTER (WHERE direction='upload'), 0) AS upload_bytes,
                   count(*) AS flows,
                   count(DISTINCT NULLIF(client_ip, '')) AS active_clients
            FROM flows_raw WHERE {where}
        """, query_params)[0]

        def metric_row(row, key=None):
            result = {
                "total_bytes": int(row.get("total_bytes") or 0),
                "download_bytes": int(row.get("download_bytes") or 0),
                "upload_bytes": int(row.get("upload_bytes") or 0),
                "flows": int(row.get("flows") or 0),
            }
            if "active_clients" in row:
                result["active_clients"] = int(row.get("active_clients") or 0)
            if key:
                result[key] = str(row.get(key) or "unknown")
            return result

        return {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "bucket_minutes": bucket_minutes,
            "filters": {"category": category_key, "service": service_key, "client_ip": requested_client},
            "services": [metric_row(row, "service") for row in services],
            "clients": [metric_row(row, "client_ip") for row in clients],
            "buckets": [{"bucket": row["bucket"].isoformat(), **metric_row(row)} for row in buckets],
            "totals": metric_row(total),
        }

    @staticmethod
    def _empty_analytics_drilldown(start, end, category, service, client_ip, bucket_minutes):
        return {
            "start": start.isoformat(), "end": end.isoformat(), "bucket_minutes": bucket_minutes,
            "filters": {"category": category, "service": service, "client_ip": client_ip},
            "services": [], "clients": [], "buckets": [],
            "totals": {"total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "flows": 0, "active_clients": 0},
        }


def build_service_intelligence(
    service_defs,
    observed_rows,
    dns_rows,
    router_health=None,
    policy_groups=None,
    profiles=None,
    router_observation_state="missing",
    router_observation_age_seconds=None,
):
    """Build a stats-heavy, policy-aware service classification view."""
    base = build_policy_service_activity(service_defs, observed_rows, policy_groups, profiles)
    defs = {str(item.get("key") or ""): dict(item) for item in service_defs or []}
    traffic_by_token = {}
    for item in observed_rows or []:
        token = _service_token(item.get("service_name"))
        if not token:
            continue
        bucket = traffic_by_token.setdefault(token, {
            "traffic_devices": 0, "last_flow": None,
        })
        bucket["traffic_devices"] = max(
            bucket["traffic_devices"], int(item.get("traffic_devices") or 0)
        )
        candidate_last_flow = item.get("last_flow")
        if candidate_last_flow and (not bucket["last_flow"] or str(candidate_last_flow) > str(bucket["last_flow"])):
            bucket["last_flow"] = candidate_last_flow
    dns_by_token = {}
    for row in dns_rows or []:
        name = str(row.get("service_name") or "Other")
        token = _service_token(name)
        bucket = dns_by_token.setdefault(token, {
            "queries": 0, "blocked": 0, "dns_devices": 0,
            "domains": 0, "last_dns": None,
        })
        bucket["queries"] += int(row.get("queries") or 0)
        bucket["blocked"] += int(row.get("blocked") or 0)
        # Each source's distinct count is retained separately.  Adding them
        # would invent a household-wide distinct-device/domain total.
        bucket["dns_devices"] = max(bucket["dns_devices"], int(row.get("dns_devices") or 0))
        bucket["domains"] += int(row.get("domains") or 0)
        candidate_last_dns = row.get("last_dns")
        if candidate_last_dns and (not bucket["last_dns"] or str(candidate_last_dns) > str(bucket["last_dns"])):
            bucket["last_dns"] = candidate_last_dns
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
        queries = blocked = dns_devices = domains = 0
        last_dns = None
        for token in tokens:
            if token and token in dns_by_token:
                queries += dns_by_token[token]["queries"]
                blocked += dns_by_token[token]["blocked"]
                dns_devices = max(dns_devices, dns_by_token[token]["dns_devices"])
                domains += dns_by_token[token]["domains"]
                candidate_last_dns = dns_by_token[token]["last_dns"]
                if candidate_last_dns and (not last_dns or str(candidate_last_dns) > str(last_dns)):
                    last_dns = candidate_last_dns
        health = health_by_key.get(key)
        tls_patterns = list(definition.get("tls_patterns") or [])
        dns_suffixes = list(definition.get("dns_suffixes") or [])
        has_tls = bool(tls_patterns)
        has_dns = bool(dns_suffixes)
        expects_routeros_contract = bool(definition.get("routeros_managed")) and has_tls
        traffic_devices = max(
            (traffic_by_token.get(token, {}).get("traffic_devices", 0) for token in tokens),
            default=0,
        )
        last_flow = max(
            (traffic_by_token.get(token, {}).get("last_flow") for token in tokens
             if traffic_by_token.get(token, {}).get("last_flow")),
            key=str,
            default=None,
        )
        last_activity = max(
            (value for value in (last_flow, last_dns) if value),
            key=str,
            default=None,
        )
        observation_state = str(router_observation_state or "missing").lower()
        if row.get("kind") == "group":
            contract_state = "not-applicable"
            capability = "aggregate-summary"
        elif not expects_routeros_contract:
            contract_state = "not-applicable"
            capability = (
                "combined" if has_tls and has_dns else "tls-only" if has_tls else
                "dns-only" if has_dns else "unsigned/telemetry-only"
            )
        elif observation_state == "fresh" and health:
            contract_state = "healthy" if health.get("healthy") else "degraded"
            capability = "combined" if has_dns else "tls-only"
        elif observation_state == "stale":
            contract_state = "stale"
            capability = "combined" if has_dns else "tls-only"
        elif observation_state == "missing":
            contract_state = "missing"
            capability = "combined" if has_dns else "tls-only"
        else:
            contract_state = "unverified"
            capability = "combined" if has_dns else "tls-only"
        row.update({
            "category": definition.get("category") or "other",
            "dns_suffixes": dns_suffixes,
            "tls_patterns": tls_patterns,
            "classifier_enabled": bool(definition.get("classifier_enabled", True)),
            "routeros_managed": bool(definition.get("routeros_managed")),
            "enforcement_approved": bool(definition.get("enforcement_approved")),
            "has_tls_signatures": has_tls,
            "has_dns_signatures": has_dns,
            "expects_routeros_contract": expects_routeros_contract,
            "dns_queries": queries,
            "dns_blocked": blocked,
            "traffic_devices": traffic_devices,
            "dns_devices": dns_devices,
            "distinct_devices": {
                "traffic": traffic_devices,
                "dns": dns_devices,
            },
            "distinct_domains": domains,
            "last_activity": last_activity,
            "evidence_freshness": "retained" if last_activity else "no-retained-evidence",
            # Keep a stable, descriptive filter value separate from the
            # detailed display provenance above.  This is retained-evidence
            # metadata only; it has no policy or RouterOS write meaning.
            "evidence_health": "fresh" if last_activity else "no-evidence",
            "signature_counts": {"tls": len(tls_patterns), "dns": len(dns_suffixes)},
            "signature_capability": capability,
            "routeros_contract_state": contract_state,
            "routeros_observation_state": observation_state,
            "routeros_observation_age_seconds": router_observation_age_seconds,
            "router_health": health or {},
            "detector_addresses": int((health or {}).get("detector_addresses") or 0),
        })
        if row.get("kind") == "group":
            row["classification_status"] = "aggregate"
        elif expects_routeros_contract and not health:
            # A RouterOS-managed TLS contract is not DNS reporting when its
            # current RouterOS observation is absent.  Its contract state is
            # unknown until the reconciler publishes matching evidence.
            row["classification_status"] = "unverified"
        elif expects_routeros_contract:
            # RouterOS contract results describe enforcement, not DNS.  An
            # explicit reporting/absent result still means the TLS contract is
            # degraded, even when DNS signatures happen to be configured too.
            row["classification_status"] = "healthy" if health.get("healthy") else "degraded"
        elif health and health.get("status") == "orphaned":
            row["classification_status"] = "degraded"
        elif has_dns or has_tls:
            row["classification_status"] = "reporting"
        elif row.get("policy_tracked"):
            row["classification_status"] = "unsigned"
        else:
            row["classification_status"] = "observed"
        row["last_signal"] = (
            "TLS/SNI + DNS" if has_tls and has_dns else
            "TLS/SNI" if has_tls else
            "DNS classification" if has_dns else
            "Telemetry label"
        )
    return base
