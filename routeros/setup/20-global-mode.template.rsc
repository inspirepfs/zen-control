# ZEN Control global NORMAL/SLOW/BLOCKED mode template.
# MUTATING TEMPLATE: review the target and rate first.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: set global SLOW target/rate then confirm" }

# RouterOS simple-queue target is deployment specific. Replace this documentation address.
:local slowTarget "192.0.2.0/24"
:local slowRate "128k/256k"

/queue simple
:if ([:len [find where name="Restricted Slow Internet"]] > 1) do={ :error "Duplicate Restricted Slow Internet queues" }
:if ([:len [find where name="Restricted Slow Internet"]] = 0) do={ add name="Restricted Slow Internet" target=$slowTarget max-limit=$slowRate disabled=yes }

/system script
:if ([:len [find where name="restricted-internet-on"]] > 1) do={ :error "Duplicate restricted-internet-on scripts" }
:if ([:len [find where name="restricted-internet-on"]] = 0) do={ add name="restricted-internet-on" policy=read,write,policy,test source="/ip firewall filter disable [find where comment=\"MASTER - Block Restricted Internet\"]; /queue simple disable [find where name=\"Restricted Slow Internet\"]" }

:if ([:len [find where name="restricted-internet-slow"]] > 1) do={ :error "Duplicate restricted-internet-slow scripts" }
:if ([:len [find where name="restricted-internet-slow"]] = 0) do={ add name="restricted-internet-slow" policy=read,write,policy,test source="/ip firewall filter disable [find where comment=\"MASTER - Block Restricted Internet\"]; /queue simple enable [find where name=\"Restricted Slow Internet\"]" }

:if ([:len [find where name="restricted-internet-off"]] > 1) do={ :error "Duplicate restricted-internet-off scripts" }
:if ([:len [find where name="restricted-internet-off"]] = 0) do={ add name="restricted-internet-off" policy=read,write,policy,test source="/queue simple disable [find where name=\"Restricted Slow Internet\"]; /ip firewall filter enable [find where comment=\"MASTER - Block Restricted Internet\"]" }

:put "ZEN global mode primitives installed. NORMAL is the safe initial state; verify before changing mode."
