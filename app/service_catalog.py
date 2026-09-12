"""RouterOS-backed service enforcement catalogue.

The policy layer speaks in logical service keys. This module maps built-in
services onto manually-managed RouterOS TLS/SNI classifier rules and MC source
address-lists. Those built-in firewall contracts remain read-only authority: the
application manages source-list membership only and never creates, reorders or
silently repairs their critical RW rules. Explicitly approved custom services use
a separate deterministic MC-owned contract implemented by service_provisioning.

Broad categories such as ``gaming`` and ``social_media`` are not direct
RouterOS classifiers. :mod:`app.policy_groups` expands them into explicit
concrete services from this catalogue.
"""


def _service(name, source_list, detector_list, block_comment, learners, coverage_note=""):
    return {
        "name": name,
        "source_list": source_list,
        "classification": "TLS/SNI",
        "coverage_note": coverage_note,
        "rules": [
            {
                "comment": block_comment,
                "detector_list": detector_list,
            }
        ],
        "learners": [
            {
                "comment": comment,
                "address_list": detector_list,
                "tls_host": tls_host,
            }
            for comment, tls_host in learners
        ],
    }


SERVICE_ENFORCEMENT = {
    "youtube": {
        "name": "YouTube",
        "source_list": "MC_Block_YouTube",
        "classification": "TLS/SNI",
        "coverage_note": "Uses the existing YouTube and GoogleVideo detector lists.",
        "rules": [
            {
                "comment": "RW10 - Block YouTube",
                "detector_list": "Detected_YouTube",
            },
            {
                "comment": "RW11 - Block GoogleVideo",
                "detector_list": "Detected_GoogleVideo",
            },
        ],
        "learners": [
            {
                "comment": "RW03 - Learn YouTube",
                "address_list": "Detected_YouTube",
                "tls_host": "*youtube*",
            },
            {
                "comment": "RW04 - Learn GoogleVideo",
                "address_list": "Detected_GoogleVideo",
                "tls_host": "*googlevideo*",
            },
        ],
    },
    "chatgpt": _service(
        "ChatGPT",
        "MC_Block_ChatGPT",
        "Detected_ChatGPT",
        "RW12 - Block ChatGPT",
        [("RW06 - Learn ChatGPT", "*chatgpt*")],
    ),
    "openai": _service(
        "OpenAI",
        "MC_Block_OpenAI",
        "Detected_OpenAI",
        "RW13 - Block OpenAI",
        [("RW05 - Learn OpenAI", "*openai*")],
    ),
    "netflix": _service(
        "Netflix",
        "MC_Block_Netflix",
        "Detected_Netflix",
        "RW14 - Block Netflix",
        [
            ("RW30 - Learn Netflix", "*netflix*"),
            ("RW31 - Learn Netflix CDN", "*nflx*"),
        ],
    ),
    "prime_video": _service(
        "Prime Video",
        "MC_Block_PrimeVideo",
        "Detected_PrimeVideo",
        "RW15 - Block Prime Video",
        [
            ("RW32 - Learn Prime Video", "*primevideo*"),
            ("RW33 - Learn Amazon Video", "*amazonvideo*"),
            ("RW34 - Learn AIV CDN", "*aiv-cdn*"),
        ],
        "Conservative Prime Video-specific hostnames; shared Amazon infrastructure is not broadly blocked.",
    ),
    "bbc_iplayer": _service(
        "BBC iPlayer",
        "MC_Block_BBCiPlayer",
        "Detected_BBCiPlayer",
        "RW16 - Block BBC iPlayer",
        [
            ("RW35 - Learn BBC iPlayer", "*iplayer*"),
            ("RW36 - Learn BBC iPlayer Format", "*bbcfmt*"),
            ("RW37 - Learn BBC iPlayer Media", "*bbcmedia*"),
        ],
        "Conservative iPlayer/media-specific SNI matching; shared BBC/CDN traffic is deliberately not blanket-blocked.",
    ),
    "tiktok": _service(
        "TikTok",
        "MC_Block_TikTok",
        "Detected_TikTok",
        "RW17 - Block TikTok",
        [
            ("RW38 - Learn TikTok", "*tiktok*"),
            ("RW39 - Learn MusicalLy", "*musical.ly*"),
            ("RW40 - Learn TikTok Media", "*muscdn*"),
        ],
        "Primary TikTok-owned hostnames only; deliberately avoids broad ByteDance shared-domain matching.",
    ),
    "discord": _service(
        "Discord",
        "MC_Block_Discord",
        "Detected_Discord",
        "RW18 - Block Discord",
        [("RW41 - Learn Discord", "*discord*")],
    ),
    "roblox": _service(
        "Roblox",
        "MC_Block_Roblox",
        "Detected_Roblox",
        "RW19 - Block Roblox",
        [
            ("RW42 - Learn Roblox", "*roblox*"),
            ("RW43 - Learn Roblox CDN", "*rbxcdn*"),
        ],
        "Covers Roblox HTTPS/API/CDN endpoints. Experience traffic can also use high UDP ports.",
    ),
    "steam": _service(
        "Steam",
        "MC_Block_Steam",
        "Detected_Steam",
        "RW20 - Block Steam",
        [("RW44 - Learn Steam", "*steam*")],
        "Covers Steam HTTPS endpoints; Steam/game traffic can also use non-HTTPS TCP/UDP ports.",
    ),
    "xbox": _service(
        "Xbox",
        "MC_Block_Xbox",
        "Detected_Xbox",
        "RW21 - Block Xbox",
        [("RW45 - Learn Xbox", "*xbox*")],
        "Covers Xbox HTTPS service endpoints; console/game traffic can also use other protocols.",
    ),
    "playstation": _service(
        "PlayStation",
        "MC_Block_PlayStation",
        "Detected_PlayStation",
        "RW22 - Block PlayStation",
        [
            ("RW46 - Learn PlayStation", "*playstation*"),
            (
                "RW47 - Learn Sony Entertainment Network",
                "*sonyentertainmentnetwork*",
            ),
        ],
        "Covers PlayStation/PSN HTTPS endpoints; console/game traffic can also use other protocols.",
    ),
}

SUPPORTED_SERVICE_KEYS = frozenset(SERVICE_ENFORCEMENT)

# DNS suffixes mirror the service evidence used by telemetry. Keeping this
# alongside the RouterOS TLS/SNI contract gives the application one canonical
# built-in classifier definition instead of separate UI/telemetry lists.
SERVICE_DNS_SUFFIXES = {
    "youtube": ("youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com"),
    "netflix": ("netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxso.net"),
    "prime_video": ("primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net"),
    "bbc_iplayer": ("bbc.co.uk", "bbc.com", "bbci.co.uk", "bbcmedia.co.uk", "bbcmedia.net"),
    "chatgpt": ("chatgpt.com", "oaistatic.com", "oaiusercontent.com"),
    "openai": ("openai.com",),
    "tiktok": ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "muscdn.com", "musical.ly"),
    "discord": ("discord.com", "discord.gg", "discordapp.com", "discordapp.net"),
    "roblox": ("roblox.com", "rbxcdn.com"),
    "steam": ("steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com"),
    "xbox": ("xboxlive.com", "xbox.com", "xboxservices.com"),
    "playstation": ("playstation.net", "playstation.com", "sonyentertainmentnetwork.com"),
}

SERVICE_CATEGORIES = {
    "youtube": "video",
    "netflix": "video",
    "prime_video": "video",
    "bbc_iplayer": "video",
    "chatgpt": "ai",
    "openai": "ai",
    "tiktok": "social",
    "discord": "social",
    "roblox": "gaming",
    "steam": "gaming",
    "xbox": "gaming",
    "playstation": "gaming",
}

for _key, _service_def in SERVICE_ENFORCEMENT.items():
    _service_def["dns_suffixes"] = list(SERVICE_DNS_SUFFIXES.get(_key, ()))
    _service_def["tls_patterns"] = [
        str(item.get("tls_host") or "")
        for item in _service_def.get("learners", ())
        if item.get("tls_host")
    ]
    _service_def["category"] = SERVICE_CATEGORIES.get(_key, "other")


def builtin_service_metadata(service_key):
    item = SERVICE_ENFORCEMENT.get(str(service_key or ""))
    if not item:
        return None
    return {
        "key": service_key,
        "name": item["name"],
        "category": item.get("category", "other"),
        "dns_suffixes": list(item.get("dns_suffixes") or ()),
        "tls_patterns": list(item.get("tls_patterns") or ()),
        "routeros_managed": True,
        "source_list": item.get("source_list", ""),
        "detector_lists": [rule.get("detector_list", "") for rule in item.get("rules", ())],
        "coverage_note": item.get("coverage_note", ""),
    }

