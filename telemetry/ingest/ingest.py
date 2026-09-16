import ipaddress, json, os, queue, socket, sqlite3, threading, time
from datetime import datetime, timezone
import dns.resolver
import psycopg
from service_map import CLASSIFIER_VERSION, classify_domain, classify_record, classifier_status

DB_HOST=os.getenv('TELEMETRY_DB_HOST','telemetry-db')
DB_PORT=int(os.getenv('TELEMETRY_DB_PORT','5432'))
DB_NAME=os.getenv('TELEMETRY_DB_NAME','mikrotik')
DB_USER=os.getenv('TELEMETRY_DB_USER','mikrotik')
DB_PASSWORD=os.getenv('TELEMETRY_DB_PASSWORD')

FLOW_PIPE=os.getenv('FLOW_PIPE','/flow/flows.pipe')
PIHOLE_DB=os.getenv('PIHOLE_DB','/pihole/pihole-FTL.db')
STATE_FILE=os.getenv('STATE_FILE','/state/ingest-state.json')
CLASSIFIER_STATUS_FILE=os.getenv('CLASSIFIER_STATUS_FILE','/state/classifier-status.json')
CLASSIFIER_STATUS_SECONDS=max(1,int(os.getenv('CLASSIFIER_STATUS_SECONDS','5')))
INGEST_STATUS_FILE=os.getenv('INGEST_STATUS_FILE','/state/ingest-status.json')
INGEST_STATUS_SECONDS=max(1,int(os.getenv('INGEST_STATUS_SECONDS','5')))
PIHOLE_DNS=os.getenv('PIHOLE_DNS','pihole')
LAN_CIDRS=[ipaddress.ip_network(x.strip()) for x in os.getenv('LAN_CIDRS','192.168.1.0/24').split(',') if x.strip()]
DNS_POLL_SECONDS=int(os.getenv('DNS_POLL_SECONDS','10'))
FLOW_BATCH=int(os.getenv('FLOW_BATCH','250'))
DOMAIN_IP_TTL=int(os.getenv('DOMAIN_IP_TTL','900'))
flow_queue=queue.Queue(maxsize=20000)
domain_ip_lock=threading.Lock()
domain_ip_map={}
source_status_lock=threading.Lock()
source_status={"dns_source":"unknown","ipfix_source":"unknown"}

def mark_source(name,state):
    if name not in source_status:return
    state=str(state or "unknown").strip().lower()
    if state not in {"available","unavailable","unknown"}:state="unknown"
    with source_status_lock:source_status[name]=state

def source_status_snapshot():
    with source_status_lock:return dict(source_status)

def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%S'),msg,flush=True)

def db_connect():
    return psycopg.connect(host=DB_HOST,port=DB_PORT,dbname=DB_NAME,user=DB_USER,password=DB_PASSWORD,connect_timeout=5)

def wait_database():
    while True:
        try:
            with db_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT 1'); cur.fetchone()
            log('PostgreSQL telemetry database ready'); return
        except Exception as exc:
            log(f'Waiting for PostgreSQL: {exc}'); time.sleep(3)

def normalize_ip(value):
    if value is None:
        return ""

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) in (4, 16):
            return str(ipaddress.ip_address(raw))

    value = str(value).strip()

    if not value:
        return ""

    # Normal textual IPv4/IPv6.
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    # GoFlow2 custom byte fields are rendered as hex in JSON.
    # IPv4 = 8 hex chars, IPv6 = 32 hex chars.
    if len(value) in (8, 32):
        try:
            raw = bytes.fromhex(value)
            if len(raw) in (4, 16):
                return str(ipaddress.ip_address(raw))
        except ValueError:
            pass

    return value

def is_lan(value):
    try:return any(ipaddress.ip_address(value) in network for network in LAN_CIDRS)
    except ValueError:return False

def ns_to_dt(value):
    try:
        ns=int(value or 0)
        return datetime.fromtimestamp(ns/1_000_000_000,tz=timezone.utc) if ns else datetime.now(timezone.utc)
    except Exception:return datetime.now(timezone.utc)

def lookup_domain(remote_ip):
    now=time.time()
    with domain_ip_lock:
        item=domain_ip_map.get(remote_ip)
        if not item:return '',''
        if item['expires']<now:
            domain_ip_map.pop(remote_ip,None); return '',''
        return item['domain'],item['service']

def resolve_domain(domain,service):
    try:
        resolver=dns.resolver.Resolver(configure=False)
        resolver.nameservers=[socket.gethostbyname(PIHOLE_DNS)]
        resolver.timeout=1.5; resolver.lifetime=2.5
        answers=set()
        for qtype in ('A','AAAA'):
            try:
                for answer in resolver.resolve(domain,qtype):answers.add(normalize_ip(str(answer)))
            except Exception:pass
        expires=time.time()+DOMAIN_IP_TTL
        with domain_ip_lock:
            for answer in answers:domain_ip_map[answer]={'domain':domain,'service':service,'expires':expires}
    except Exception:pass

def ns_to_iso(value):
    """
    Convert a Unix timestamp in nanoseconds to an ISO-8601 UTC timestamp.
    """
    try:
        ns = int(value or 0)
    except (TypeError, ValueError):
        ns = 0

    if ns <= 0:
        return datetime.now(timezone.utc).isoformat()

    return datetime.fromtimestamp(
        ns / 1_000_000_000,
        tz=timezone.utc,
    ).isoformat()

def transform_flow(raw):
    src = normalize_ip(raw.get("src_addr"))
    dst = normalize_ip(raw.get("dst_addr"))

    nat_src = normalize_ip(raw.get("nat_src_addr"))
    nat_dst = normalize_ip(raw.get("nat_dst_addr"))

    if not src or not dst:
        return None

    src_lan = is_lan(src)
    dst_lan = is_lan(dst)
    nat_src_lan = is_lan(nat_src) if nat_src else False
    nat_dst_lan = is_lan(nat_dst) if nat_dst else False

    # Normal pre-NAT outbound flow.
    if src_lan and not dst_lan:
        client_ip = src
        remote_ip = dst
        direction = "upload"

    # Direct inbound flow where the LAN destination is already visible.
    elif dst_lan and not src_lan:
        client_ip = dst
        remote_ip = src
        direction = "download"

    # Inbound flow as seen on WAN side:
    #
    # Internet -> public WAN IP
    # post-NAT destination -> LAN client
    elif not src_lan and not dst_lan and nat_dst_lan:
        client_ip = nat_dst
        remote_ip = src
        direction = "download"

    # Defensive handling if a device/exporter gives us a LAN-side
    # post-NAT source rather than the normal pre-NAT record.
    elif not src_lan and not dst_lan and nat_src_lan:
        client_ip = nat_src
        remote_ip = dst
        direction = "upload"

    else:
        # LAN<->LAN, router-local, multicast, etc. aren't part of
        # household Internet accounting.
        return None

    domain, _service = lookup_domain(remote_ip)

    proto = str(raw.get("proto") or "")
    if proto.isdigit():
        proto = {
            "6": "TCP",
            "17": "UDP",
            "1": "ICMP",
            "58": "ICMPv6",
        }.get(proto, proto)

    destination_port = int(raw.get("dst_port") or 0)
    classification = classify_record({
        "dns": {"domain": domain},
        "flow": {"protocol": proto, "destination_port": destination_port},
    })

    return {
        "event_time": ns_to_dt(raw.get("time_received_ns")),
        "flow_start": ns_to_dt(raw.get("time_flow_start_ns")),
        "flow_end": ns_to_dt(raw.get("time_flow_end_ns")),
        "sampler_address": normalize_ip(raw.get("sampler_address")),
        "client_ip": client_ip,
        "remote_ip": remote_ip,
        "direction": direction,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": int(raw.get("src_port") or 0),
        "dst_port": destination_port,
        "protocol": proto,
        "bytes": int(raw.get("bytes") or 0),
        "packets": int(raw.get("packets") or 0),
        "src_mac": str(raw.get("src_mac") or ""),
        "dst_mac": str(raw.get("dst_mac") or ""),
        "in_if": int(raw.get("in_if") or 0),
        "out_if": int(raw.get("out_if") or 0),
        "domain": domain,
        "category": classification["category"],
        "service": classification["service"],
        "confidence": classification["confidence"],
        "classifier_evidence": json.dumps(classification["evidence"], separators=(",", ":")),
        "classifier_version": CLASSIFIER_VERSION,
    }

def flow_reader():
    decoder = json.JSONDecoder()

    while True:
        try:
            log(f"Opening flow pipe {FLOW_PIPE}")

            with open(
                FLOW_PIPE,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as stream:

                mark_source("ipfix_source", "available")
                buffer = ""

                while True:
                    chunk = stream.read(4096)

                    if not chunk:
                        mark_source("ipfix_source", "unavailable")
                        break

                    buffer += chunk

                    while buffer:
                        buffer = buffer.lstrip()

                        if not buffer:
                            break

                        try:
                            raw, end = decoder.raw_decode(buffer)

                        except json.JSONDecodeError:
                            # Usually means the JSON object has only
                            # partially arrived. Wait for more data.
                            if len(buffer) > 1024 * 1024:
                                log(
                                    "Flow JSON buffer exceeded 1 MiB; "
                                    "discarding malformed input"
                                )
                                buffer = ""

                            break

                        buffer = buffer[end:]

                        try:
                            row = transform_flow(raw)

                            if row:
                                flow_queue.put(row)

                        except Exception as exc:
                            log(f"Flow decode error: {exc}")

        except Exception as exc:
            mark_source("ipfix_source", "unavailable")
            log(f"Flow reader error: {exc}")
            time.sleep(2)

def bucket5(dt):
    return dt.replace(minute=(dt.minute//5)*5,second=0,microsecond=0)


FLOW_RAW_FIELDS = (
    'event_time', 'flow_start', 'flow_end', 'sampler_address', 'client_ip',
    'remote_ip', 'direction', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'protocol', 'bytes', 'packets', 'src_mac', 'dst_mac', 'in_if', 'out_if',
    'domain', 'category', 'service', 'confidence', 'classifier_evidence',
    'classifier_version',
)


def flow_raw_values(row):
    """Return the persisted flow sample in the schema's column order."""
    return tuple(row[field] for field in FLOW_RAW_FIELDS)

def flow_writer():
    batch=[]; last=time.time()
    while True:
        try:batch.append(flow_queue.get(timeout=max(.2,2-(time.time()-last))))
        except queue.Empty:pass
        if batch and (len(batch)>=FLOW_BATCH or time.time()-last>=2):
            try:
                raw=[]; agg5={}; device_daily={}; service_daily={}
                for row in batch:
                    raw.append(flow_raw_values(row))
                    key=(bucket5(row['event_time']),row['client_ip'],row['direction'],row['service'],row['remote_ip'],row['domain'])
                    acc=agg5.setdefault(key,[0,0,0]); acc[0]+=row['bytes']; acc[1]+=row['packets']; acc[2]+=1
                    key=(row['event_time'].date(),row['client_ip'],row['direction'])
                    acc=device_daily.setdefault(key,[0,0,0]); acc[0]+=row['bytes']; acc[1]+=row['packets']; acc[2]+=1
                    key=(row['event_time'].date(),row['client_ip'],row['service'])
                    acc=service_daily.setdefault(key,[0,0,0]); acc[0]+=row['bytes']; acc[1]+=row['packets']; acc[2]+=1
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.executemany('INSERT INTO flows_raw(event_time,flow_start,flow_end,sampler_address,client_ip,remote_ip,direction,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,src_mac,dst_mac,in_if,out_if,domain,category,service,confidence,classifier_evidence,classifier_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',raw)
                        cur.executemany('INSERT INTO flow_5m(bucket,client_ip,direction,service,remote_ip,domain,bytes,packets,flows) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(bucket,client_ip,direction,service,remote_ip,domain) DO UPDATE SET bytes=flow_5m.bytes+EXCLUDED.bytes,packets=flow_5m.packets+EXCLUDED.packets,flows=flow_5m.flows+EXCLUDED.flows',[(*k,*v) for k,v in agg5.items()])
                        cur.executemany('INSERT INTO device_daily(day,client_ip,direction,bytes,packets,flows) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(day,client_ip,direction) DO UPDATE SET bytes=device_daily.bytes+EXCLUDED.bytes,packets=device_daily.packets+EXCLUDED.packets,flows=device_daily.flows+EXCLUDED.flows',[(*k,*v) for k,v in device_daily.items()])
                        cur.executemany('INSERT INTO service_daily(day,client_ip,service,bytes,packets,flows) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(day,client_ip,service) DO UPDATE SET bytes=service_daily.bytes+EXCLUDED.bytes,packets=service_daily.packets+EXCLUDED.packets,flows=service_daily.flows+EXCLUDED.flows',[(*k,*v) for k,v in service_daily.items()])
                batch.clear(); last=time.time()
            except Exception as exc:
                log(f'Flow insert error: {exc}'); time.sleep(2)

def load_state():
    try:
        with open(STATE_FILE) as f:return json.load(f)
    except Exception:return {'last_dns_id':0}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE),exist_ok=True)
    tmp=STATE_FILE+'.tmp'
    with open(tmp,'w') as f:json.dump(state,f)
    os.replace(tmp,STATE_FILE)

BLOCKED_STATUSES={1,4,5,6,7,8,9,10,11,15,16,18}

def dns_worker():
    state=load_state(); last_id=int(state.get('last_dns_id',0) or 0)
    while True:
        if not os.path.exists(PIHOLE_DB):
            mark_source('dns_source','unavailable')
            time.sleep(DNS_POLL_SECONDS)
            continue
        try:
            # The named volume can remain readable after the Pi-hole container
            # stops. Prove the DNS listener as well as the retained FTL store so
            # stale volume contents cannot masquerade as a healthy DNS source.
            with socket.create_connection((PIHOLE_DNS, 53), timeout=1.5):
                pass
            db=sqlite3.connect(f'file:{PIHOLE_DB}?mode=ro',uri=True,timeout=2); db.row_factory=sqlite3.Row
            try:
                rows=db.execute('SELECT id,timestamp,type,status,domain,client,reply_type,reply_time FROM queries WHERE id>? ORDER BY id LIMIT 5000',(last_id,)).fetchall()
            finally:
                db.close()
        except Exception as exc:
            # This boundary proves only the Pi-hole source. PostgreSQL failures
            # later in the pipeline must not make Pi-hole look unavailable.
            mark_source('dns_source','unavailable')
            log(f'DNS source read error: {exc}')
            time.sleep(DNS_POLL_SECONDS)
            continue

        mark_source('dns_source','available')
        if not rows:
            time.sleep(DNS_POLL_SECONDS)
            continue

        try:
            outgoing=[]
            for row in rows:
                client=normalize_ip(row['client']); domain=(row['domain'] or '').lower().rstrip('.'); service=classify_domain(domain); blocked=int(row['status'] or 0) in BLOCKED_STATUSES
                outgoing.append((int(row['id']),datetime.fromtimestamp(int(row['timestamp']),tz=timezone.utc),client,'',domain,int(row['type'] or 0),int(row['status'] or 0),blocked,int(row['reply_type'] or 0),float(row['reply_time'] or 0),service))
                if client and is_lan(client) and not blocked and domain:resolve_domain(domain,service)
                last_id=max(last_id,int(row['id']))
            with db_connect() as conn:
                with conn.cursor() as cur:
                    cur.executemany('INSERT INTO dns_queries(pihole_id,event_time,client_ip,client_name,domain,query_type,status,blocked,reply_type,reply_time,service) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(pihole_id) DO NOTHING',outgoing)
            state['last_dns_id']=last_id; save_state(state)
        except Exception as exc:
            # Destination/processing failures are independent from source
            # reachability. Keep the fresh Pi-hole source evidence intact.
            log(f'DNS ingest pipeline error: {exc}')
            time.sleep(DNS_POLL_SECONDS)


def publish_ingest_status():
    """Publish process/source liveness without household or exception detail."""
    while True:
        try:
            sources=source_status_snapshot()
            payload={
                "schema":"zen_telemetry_ingest_status_v1",
                "observed_at":datetime.now(timezone.utc).isoformat(),
                "dns_source":sources.get("dns_source","unknown"),
                "ipfix_source":sources.get("ipfix_source","unknown"),
                "flow_queue_depth":max(0,int(flow_queue.qsize())),
            }
            os.makedirs(os.path.dirname(INGEST_STATUS_FILE),exist_ok=True)
            tmp=INGEST_STATUS_FILE+'.tmp'
            with open(tmp,'w',encoding='utf-8') as f:json.dump(payload,f,separators=(',',':'))
            os.replace(tmp,INGEST_STATUS_FILE)
        except Exception as exc:
            log(f'Ingest status publish error: {exc}')
        time.sleep(INGEST_STATUS_SECONDS)

def publish_classifier_status():
    """Publish sanitized classifier-consumer health for the control UI."""
    while True:
        try:
            status=dict(classifier_status())
            payload={
                "schema":"zen_classifier_consumer_status_v1",
                "observed_at":datetime.now(timezone.utc).isoformat(),
                "source":str(status.get("source") or "unknown"),
                "services":max(0,int(status.get("services") or 0)),
                "signatures":max(0,int(status.get("signatures") or 0)),
                "has_live":bool(status.get("has_live")),
                "error":str(status.get("error") or "")[:500],
            }
            os.makedirs(os.path.dirname(CLASSIFIER_STATUS_FILE),exist_ok=True)
            tmp=CLASSIFIER_STATUS_FILE+'.tmp'
            with open(tmp,'w',encoding='utf-8') as f:json.dump(payload,f,separators=(',',':'))
            os.replace(tmp,CLASSIFIER_STATUS_FILE)
        except Exception as exc:
            log(f'Classifier status publish error: {exc}')
        time.sleep(CLASSIFIER_STATUS_SECONDS)

def retention_worker():
    while True:
        try:
            with db_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM flows_raw WHERE event_time<now()-interval '7 days'")
                    cur.execute("DELETE FROM flow_5m WHERE bucket<now()-interval '180 days'")
                    cur.execute("DELETE FROM dns_queries WHERE event_time<now()-interval '30 days'")
                    cur.execute("DELETE FROM device_daily WHERE day<current_date-365")
                    cur.execute("DELETE FROM service_daily WHERE day<current_date-365")
            log('Retention cleanup complete')
        except Exception as exc:log(f'Retention cleanup error: {exc}')
        time.sleep(3600)

def main():
    wait_database()
    for target in (flow_reader,flow_writer,dns_worker,publish_ingest_status,publish_classifier_status,retention_worker):threading.Thread(target=target,daemon=True).start()
    log('Traffic ingest running with PostgreSQL backend')
    while True:time.sleep(60)

if __name__=='__main__':main()
