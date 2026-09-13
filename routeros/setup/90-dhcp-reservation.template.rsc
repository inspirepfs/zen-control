# Example stable DHCP identity for one ZEN-managed device.
# Copy/review per device. The example uses documentation-only values.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: set real MAC/IP/server/name then confirm" }

:local deviceMac "02:00:00:00:00:10"
:local deviceIp "192.0.2.20"
:local deviceName "example-managed-device"
:local dhcpServer "dhcp1"
/ip dhcp-server lease
:if ([:len [find where mac-address=$deviceMac]] = 0) do={ add mac-address=$deviceMac address=$deviceIp server=$dhcpServer comment=$deviceName }
:put "ZEN example DHCP reservation configured."
