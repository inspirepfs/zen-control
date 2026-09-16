CREATE TABLE IF NOT EXISTS flows_raw (
 id bigserial PRIMARY KEY,
 event_time timestamptz NOT NULL, flow_start timestamptz NOT NULL, flow_end timestamptz NOT NULL,
 sampler_address text NOT NULL DEFAULT '', client_ip text NOT NULL, remote_ip text NOT NULL,
 direction text NOT NULL CHECK(direction IN ('upload','download')),
 src_ip text NOT NULL, dst_ip text NOT NULL, src_port integer NOT NULL DEFAULT 0,
 dst_port integer NOT NULL DEFAULT 0, protocol text NOT NULL DEFAULT '',
 bytes bigint NOT NULL DEFAULT 0, packets bigint NOT NULL DEFAULT 0,
 src_mac text NOT NULL DEFAULT '', dst_mac text NOT NULL DEFAULT '',
 in_if integer NOT NULL DEFAULT 0, out_if integer NOT NULL DEFAULT 0,
 domain text NOT NULL DEFAULT '',
 category text NOT NULL DEFAULT 'unknown', service text NOT NULL DEFAULT 'Unknown',
 confidence text NOT NULL DEFAULT 'none',
 classifier_evidence jsonb NOT NULL DEFAULT '{"source":"fallback","matched_value":null,"precedence":"fallback"}'::jsonb,
 classifier_version text NOT NULL DEFAULT 'unknown'
);
-- Existing installations retain historical rows; their absent classification
-- metadata is represented by the same explicit unknown values as above.
ALTER TABLE flows_raw ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'unknown';
ALTER TABLE flows_raw ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT 'none';
ALTER TABLE flows_raw ADD COLUMN IF NOT EXISTS classifier_evidence jsonb NOT NULL DEFAULT '{"source":"fallback","matched_value":null,"precedence":"fallback"}'::jsonb;
ALTER TABLE flows_raw ADD COLUMN IF NOT EXISTS classifier_version text NOT NULL DEFAULT 'unknown';
CREATE INDEX IF NOT EXISTS flows_raw_event_brin ON flows_raw USING brin(event_time);
CREATE INDEX IF NOT EXISTS flows_raw_client_time ON flows_raw(client_ip,event_time DESC);

CREATE TABLE IF NOT EXISTS flow_5m (
 bucket timestamptz NOT NULL, client_ip text NOT NULL, direction text NOT NULL,
 service text NOT NULL DEFAULT '', remote_ip text NOT NULL DEFAULT '', domain text NOT NULL DEFAULT '',
 bytes bigint NOT NULL DEFAULT 0, packets bigint NOT NULL DEFAULT 0, flows bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(bucket,client_ip,direction,service,remote_ip,domain)
);
CREATE INDEX IF NOT EXISTS flow_5m_client_time ON flow_5m(client_ip,bucket DESC);
CREATE INDEX IF NOT EXISTS flow_5m_service_time ON flow_5m(service,bucket DESC);

CREATE TABLE IF NOT EXISTS device_daily (
 day date NOT NULL, client_ip text NOT NULL, direction text NOT NULL,
 bytes bigint NOT NULL DEFAULT 0, packets bigint NOT NULL DEFAULT 0, flows bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(day,client_ip,direction)
);
CREATE TABLE IF NOT EXISTS service_daily (
 day date NOT NULL, client_ip text NOT NULL, service text NOT NULL DEFAULT '',
 bytes bigint NOT NULL DEFAULT 0, packets bigint NOT NULL DEFAULT 0, flows bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(day,client_ip,service)
);
CREATE TABLE IF NOT EXISTS dns_queries (
 pihole_id bigint PRIMARY KEY, event_time timestamptz NOT NULL,
 client_ip text NOT NULL DEFAULT '', client_name text NOT NULL DEFAULT '',
 domain text NOT NULL DEFAULT '', query_type integer NOT NULL DEFAULT 0,
 status integer NOT NULL DEFAULT 0, blocked boolean NOT NULL DEFAULT false,
 reply_type integer NOT NULL DEFAULT 0, reply_time double precision NOT NULL DEFAULT 0,
 service text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dns_queries_event_brin ON dns_queries USING brin(event_time);
CREATE INDEX IF NOT EXISTS dns_queries_client_time ON dns_queries(client_ip,event_time DESC);
CREATE INDEX IF NOT EXISTS dns_queries_domain_time ON dns_queries(domain,event_time DESC);
