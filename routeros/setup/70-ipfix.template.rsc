# ZEN Control IPFIX/Traffic Flow template for retained traffic analytics.
# MUTATING TEMPLATE: replace the collector address with the ZEN Docker host.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: set collector address then confirm" }

:local zenCollector "192.0.2.10"
:local zenCollectorPort 2055

/ip traffic-flow set enabled=yes interfaces=all
/ip traffic-flow target
:if ([:len [find where dst-address=$zenCollector port=$zenCollectorPort]] = 0) do={ add dst-address=$zenCollector port=$zenCollectorPort version=IPFIX }
:put "ZEN IPFIX target configured. Verify UDP/2055 reaches the GoFlow2 service."
