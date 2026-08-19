from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from .models import Handoff


SC_MAX_EACH_POST_BYTES = 1_000_000


BEGIN_MARKER = "# BEGIN XHTTP-SETUP MANAGED BLOCK"
END_MARKER = "# END XHTTP-SETUP MANAGED BLOCK"


def render_xray_server_config(
    *, client_id: str, decryption: str, port: int, path: str
) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
                "1.1.1.1",
                "8.8.8.8",
            ],
        },
        "inbounds": [
            {
                "tag": "VLESS_XHTTP_FRONT",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": client_id, "email": "xhttp-front"}],
                    "decryption": decryption,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": False,
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "mode": "packet-up",
                        "path": path,
                        "scMaxEachPostBytes": SC_MAX_EACH_POST_BYTES,
                    },
                },
            }
        ],
        "outbounds": [
            {
                "tag": "DIRECT",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
            },
            {"tag": "BLOCK", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "BLOCK",
                },
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "BLOCK",
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "DIRECT",
                },
            ],
        },
    }


def render_xray_client_config(
    *, handoff: Handoff, domain: str, socks_port: int, front_address: str | None = None
) -> dict:
    tls_settings = {
        "serverName": domain,
        "fingerprint": handoff.tls_fingerprint,
    }
    if handoff.pinned_peer_cert_sha256:
        tls_settings["pinnedPeerCertSha256"] = handoff.pinned_peer_cert_sha256
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [
            {
                "tag": "XHTTP_TLS",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": front_address or domain,
                            "port": 443,
                            "users": [
                                {
                                    "id": handoff.client_id,
                                    "encryption": handoff.encryption,
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": tls_settings,
                    "xhttpSettings": {
                        "host": domain,
                        "path": handoff.xhttp_path,
                        "mode": "packet-up",
                        "scMaxEachPostBytes": SC_MAX_EACH_POST_BYTES,
                        "scMinPostsIntervalMs": 30,
                    },
                },
            }
        ],
    }


def render_htaccess_block(*, exit_address: str, exit_port: int, path: str) -> str:
    relative = path.lstrip("/")
    upstream = f"http://{exit_address}:{exit_port}{path}"
    return "\n".join(
        [
            BEGIN_MARKER,
            "RewriteEngine On",
            "RewriteCond %{REQUEST_METHOD} ^(?:GET|POST)$",
            f"RewriteRule ^{relative}$ {upstream} [P,L]",
            "RewriteCond %{REQUEST_METHOD} ^(?:GET|POST)$",
            f"RewriteRule ^{relative}/(.*)$ {upstream}/$1 [P,L]",
            END_MARKER,
        ]
    )


def merge_managed_block(existing: str, managed_block: str) -> str:
    begins = existing.count(BEGIN_MARKER)
    ends = existing.count(END_MARKER)
    if begins != ends or begins > 1:
        raise ValueError("Повреждены или продублированы managed-маркеры в .htaccess")
    if begins == 0:
        prefix = existing.rstrip()
        return f"{prefix}\n\n{managed_block}\n" if prefix else f"{managed_block}\n"
    start = existing.index(BEGIN_MARKER)
    finish = existing.index(END_MARKER, start) + len(END_MARKER)
    return existing[:start] + managed_block + existing[finish:]


def render_vless_uri(
    handoff: Handoff, domain: str, *, front_address: str | None = None
) -> str:
    extra = json.dumps(
        {
            "scMaxEachPostBytes": SC_MAX_EACH_POST_BYTES,
            "scMinPostsIntervalMs": 30,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    parameters = [
        ("type", "xhttp"),
        ("encryption", handoff.encryption),
        ("security", "tls"),
        ("sni", domain),
        ("fp", handoff.tls_fingerprint),
    ]
    if handoff.pinned_peer_cert_sha256:
        parameters.append(("pcs", handoff.pinned_peer_cert_sha256))
    parameters.extend(
        [
            ("host", domain),
            ("path", handoff.xhttp_path),
            ("mode", "packet-up"),
            ("extra", extra),
        ]
    )
    query = urlencode(parameters, quote_via=quote, safe="")
    label = quote(handoff.label, safe="")
    address = front_address or domain
    return f"vless://{handoff.client_id}@{address}:443?{query}#{label}"


def pretty_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
