# ZEN Control focused read-only authority view.
# Review this output against ZEN Settings -> Security / Operational Diagnostics.

:put "=== Restricted_Devices ==="
/ip/firewall/address-list/print detail where list="Restricted_Devices"

:put "=== restricted-web chain ==="
/ip/firewall/filter/print detail where chain="restricted-web"

:put "=== FastTrack rules ==="
/ip/firewall/filter/print detail where action="fasttrack-connection"

:put "=== Kid Control profiles ==="
/ip/kid-control/print detail

:put "=== static DHCP leases ==="
/ip/dhcp-server/lease/print detail where dynamic=no
