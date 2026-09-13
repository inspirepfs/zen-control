# ZEN Control post-setup verification. READ ONLY.
:put "=== ZEN core forward authority ==="
/ip firewall filter print detail without-paging where comment="MASTER - Block Restricted Internet"
/ip firewall filter print detail without-paging where comment="MC - Per Device Block"
/ip firewall filter print detail without-paging where comment="Restricted Devices - Web Policy"
:put "=== ZEN restricted-web security ==="
/ip firewall filter print detail without-paging where chain="restricted-web"
:put "=== ZEN global mode ==="
/queue simple print detail without-paging where name="Restricted Slow Internet"
/system script print detail without-paging where name~"restricted-internet-"
:put "=== ZEN dynamic state ==="
/ip firewall address-list print detail without-paging where list~"MC_Mode_|MC_Block_"
/queue simple print detail without-paging where name~"MC-SLOW-|MC-BW-"
/system scheduler print detail without-paging where name~"MC-TEMP-|MC-SCHED-"
:put "=== ZEN FastTrack audit ==="
/ip firewall filter print detail without-paging where action=fasttrack-connection
:put "=== ZEN Traffic Flow ==="
/ip traffic-flow print detail
/ip traffic-flow target print detail
:put "=== Kid Control retained safety net ==="
/ip kid-control print detail without-paging
:put "=== Verification complete: compare with ZEN Settings -> Security ==="
