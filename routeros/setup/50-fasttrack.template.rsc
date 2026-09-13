# ZEN Control FastTrack compatibility template.
# FastTrack is optional. ZEN fail-closes enforcement if an enabled FastTrack rule
# can bypass Restricted_Devices. Review your existing rule before changing it.
:local ZEN_SETUP_CONFIRMED false
:if (!$ZEN_SETUP_CONFIRMED) do={ :error "ZEN TEMPLATE ONLY: review FastTrack policy before confirming" }

# OPTION A (simplest): disable enabled FastTrack rules while commissioning ZEN.
/ip firewall filter disable [find where action=fasttrack-connection]

# OPTION B: if you later re-enable/use FastTrack, ZEN's security contract requires
# BOTH of these exclusions on every enabled FastTrack rule:
#   src-address-list=!Restricted_Devices
#   dst-address-list=!Restricted_Devices
# Preserve your existing connection-state / hardware-offload semantics and verify
# rule ordering for your own firewall. Do not blindly replace a customized rule.
