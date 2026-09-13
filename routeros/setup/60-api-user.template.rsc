# ZEN Control RouterOS API account template.
# MUTATING TEMPLATE: choose a unique local password and restrict API reachability.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: set password/source restriction then confirm" }

:local zenUser "mikrotik-control"
:local zenPassword "REPLACE-WITH-A-LONG-RANDOM-PASSWORD"
:local zenHost "192.0.2.10/32"

# ZEN currently needs read/write API access to its documented firewall lists,
# queues, scripts and schedulers. Use a dedicated group/account; do not reuse an
# administrator login. Review RouterOS policy semantics for your release.
/user group
:if ([:len [find where name="zen-control"]] = 0) do={ add name="zen-control" policy=read,write,api,policy,test }
/user
:if ([:len [find where name=$zenUser]] = 0) do={ add name=$zenUser group="zen-control" password=$zenPassword address=$zenHost }

# API is plaintext at the current application boundary (default TCP/8728), so it
# MUST remain on a trusted/restricted management path. Add/adjust an input-chain
# firewall rule appropriate to your router so only the ZEN host can reach it.
/ip service set api disabled=no port=8728
:put "ZEN API account template applied. Verify source restriction and router input firewall before use."
