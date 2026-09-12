# ZEN Control read-only RouterOS inspection helper.
# No credentials. No add/set/remove/move/enable/disable operations.

:put "=== ZEN Control RouterOS inspection ==="
:put "--- system/resource ---"
/system/resource/print
:put "--- ip/address ---"
/ip/address/print detail
:put "--- static DHCP leases ---"
/ip/dhcp-server/lease/print detail where dynamic=no
:put "--- firewall filter ---"
/ip/firewall/filter/print detail
:put "--- firewall address lists ---"
/ip/firewall/address-list/print detail
:put "--- Kid Control profiles ---"
/ip/kid-control/print detail
:put "--- Kid Control device rows ---"
/ip/kid-control/device/print detail
:put "--- traffic flow ---"
/ip/traffic-flow/print detail
