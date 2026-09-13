# Optional MikroTik split-DNS template for the ZEN HTTPS hostname.
# If Pi-hole is the LAN DNS authority, configure the local record there instead.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: set hostname/address then confirm" }

:local zenHost "zen.example.com"
:local zenAddress "192.0.2.10"
/ip dns static
:if ([:len [find where name=$zenHost type=A]] = 0) do={ add name=$zenHost type=A address=$zenAddress ttl=5m comment="ZEN local HTTPS" }
:put "ZEN local DNS record configured."
