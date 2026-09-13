# ZEN Control narrow known-DoH TLS/SNI hardening.
# Idempotent/create-or-normalize. This is warning-level hardening, NOT complete coverage.
# ECH, unknown providers and IP-literal endpoints can evade SNI inspection.
/ip firewall filter
:if ([:len [find where comment="RW99 - Return"]] != 1) do={ :error "Expected exactly one RW99 - Return anchor" }
:local rwReturn [find where comment="RW99 - Return"]
:if ([:len [find where comment="MC - Block DoH Google"]] > 1) do={ :error "Duplicate MC - Block DoH Google" }
:if ([:len [find where comment="MC - Block DoH Google"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.google" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH Google" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH Google"]] = 1) do={ set [find where comment="MC - Block DoH Google"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.google" disabled=no }
:if ([:len [find where comment="MC - Block DoH Cloudflare"]] > 1) do={ :error "Duplicate MC - Block DoH Cloudflare" }
:if ([:len [find where comment="MC - Block DoH Cloudflare"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="*cloudflare-dns.com" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH Cloudflare" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH Cloudflare"]] = 1) do={ set [find where comment="MC - Block DoH Cloudflare"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="*cloudflare-dns.com" disabled=no }
:if ([:len [find where comment="MC - Block DoH Quad9"]] > 1) do={ :error "Duplicate MC - Block DoH Quad9" }
:if ([:len [find where comment="MC - Block DoH Quad9"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.quad9.net" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH Quad9" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH Quad9"]] = 1) do={ set [find where comment="MC - Block DoH Quad9"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.quad9.net" disabled=no }
:if ([:len [find where comment="MC - Block DoH Quad9 Secure"]] > 1) do={ :error "Duplicate MC - Block DoH Quad9 Secure" }
:if ([:len [find where comment="MC - Block DoH Quad9 Secure"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns10.quad9.net" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH Quad9 Secure" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH Quad9 Secure"]] = 1) do={ set [find where comment="MC - Block DoH Quad9 Secure"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns10.quad9.net" disabled=no }
:if ([:len [find where comment="MC - Block DoH Quad9 ECS"]] > 1) do={ :error "Duplicate MC - Block DoH Quad9 ECS" }
:if ([:len [find where comment="MC - Block DoH Quad9 ECS"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns11.quad9.net" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH Quad9 ECS" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH Quad9 ECS"]] = 1) do={ set [find where comment="MC - Block DoH Quad9 ECS"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns11.quad9.net" disabled=no }
:if ([:len [find where comment="MC - Block DoH OpenDNS"]] > 1) do={ :error "Duplicate MC - Block DoH OpenDNS" }
:if ([:len [find where comment="MC - Block DoH OpenDNS"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="doh.opendns.com" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH OpenDNS" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH OpenDNS"]] = 1) do={ set [find where comment="MC - Block DoH OpenDNS"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="doh.opendns.com" disabled=no }
:if ([:len [find where comment="MC - Block DoH NextDNS"]] > 1) do={ :error "Duplicate MC - Block DoH NextDNS" }
:if ([:len [find where comment="MC - Block DoH NextDNS"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.nextdns.io" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH NextDNS" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH NextDNS"]] = 1) do={ set [find where comment="MC - Block DoH NextDNS"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.nextdns.io" disabled=no }
:if ([:len [find where comment="MC - Block DoH AdGuard"]] > 1) do={ :error "Duplicate MC - Block DoH AdGuard" }
:if ([:len [find where comment="MC - Block DoH AdGuard"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.adguard-dns.com" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH AdGuard" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH AdGuard"]] = 1) do={ set [find where comment="MC - Block DoH AdGuard"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="dns.adguard-dns.com" disabled=no }
:if ([:len [find where comment="MC - Block DoH CleanBrowsing"]] > 1) do={ :error "Duplicate MC - Block DoH CleanBrowsing" }
:if ([:len [find where comment="MC - Block DoH CleanBrowsing"]] = 0) do={ add chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="doh.cleanbrowsing.org" log=yes log-prefix="ZEN-DOH " disabled=no comment="MC - Block DoH CleanBrowsing" place-before=$rwReturn }
:if ([:len [find where comment="MC - Block DoH CleanBrowsing"]] = 1) do={ set [find where comment="MC - Block DoH CleanBrowsing"] chain=restricted-web action=drop protocol=tcp src-address-list=Restricted_Devices dst-port=443 tls-host="doh.cleanbrowsing.org" disabled=no }

:put "ZEN known-DoH SNI hardening installed/normalized"
