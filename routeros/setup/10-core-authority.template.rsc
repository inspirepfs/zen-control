# ZEN Control core RouterOS authority template.
# MUTATING TEMPLATE: review on your router first.
# Set this guard to true only after checking the forward-chain anchor and WAN list.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: review then set ZEN_SETUP_CONFIRMED=true" }

:local wanList "WAN"
:local establishedComment "defconf: accept established,related,untracked"

/ip firewall filter
:local established [find where chain="forward" comment=$establishedComment]
:if ([:len $established] != 1) do={ :error "Expected exactly one reviewed forward established/related anchor" }

:if ([:len [find where comment="MASTER - Block Restricted Internet"]] > 1) do={ :error "Duplicate MASTER authority rule" }
:if ([:len [find where comment="MASTER - Block Restricted Internet"]] = 0) do={ add chain=forward action=drop src-address-list=Restricted_Devices out-interface-list=$wanList disabled=yes comment="MASTER - Block Restricted Internet" place-before=$established }

:if ([:len [find where comment="MC - Per Device Block"]] > 1) do={ :error "Duplicate per-device block rule" }
:if ([:len [find where comment="MC - Per Device Block"]] = 0) do={ add chain=forward action=drop src-address-list=MC_Mode_Blocked out-interface-list=$wanList disabled=no comment="MC - Per Device Block" place-before=$established }

:if ([:len [find where comment="Restricted Devices - Web Policy"]] > 1) do={ :error "Duplicate restricted-web jump" }
:if ([:len [find where comment="Restricted Devices - Web Policy"]] = 0) do={ add chain=forward action=jump jump-target=restricted-web src-address-list=Restricted_Devices disabled=no comment="Restricted Devices - Web Policy" place-before=$established }

:if ([:len [find where comment="RW99 - Return"]] > 1) do={ :error "Duplicate RW99 return" }
:if ([:len [find where comment="RW99 - Return"]] = 0) do={ add chain=restricted-web action=return disabled=no comment="RW99 - Return" }
:local rwReturn [find where comment="RW99 - Return"]

:if ([:len [find where comment="RW01 - Block QUIC HTTP3"]] > 1) do={ :error "Duplicate QUIC rule" }
:if ([:len [find where comment="RW01 - Block QUIC HTTP3"]] = 0) do={ add chain=restricted-web action=drop protocol=udp dst-port=443 disabled=no comment="RW01 - Block QUIC HTTP3" place-before=$rwReturn }

:if ([:len [find where comment="MC - Block Restricted DoT"]] > 1) do={ :error "Duplicate DoT rule" }
:if ([:len [find where comment="MC - Block Restricted DoT"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp dst-port=853 src-address-list=Restricted_Devices log=yes log-prefix="MC-DOT " disabled=no comment="MC - Block Restricted DoT" place-before=$rwReturn }

:if ([:len [find where comment="MC - Block Restricted DoQ"]] > 1) do={ :error "Duplicate DoQ rule" }
:if ([:len [find where comment="MC - Block Restricted DoQ"]] = 0) do={ add chain=restricted-web action=drop protocol=udp dst-port=853 src-address-list=Restricted_Devices log=yes log-prefix="MC-DOQ " disabled=no comment="MC - Block Restricted DoQ" place-before=$rwReturn }

:put "ZEN core authority primitives installed. Run 99-verify.rsc and ZEN Security posture before enabling writes."
