"""Thu thập thông tin TLS cơ bản bằng socket tiêu chuẩn."""

from __future__ import annotations

import socket
import ssl
from typing import Dict, List
from urllib.parse import urlparse


def _format_name(rdns: List[tuple]) -> str:
    """Gộp tên trong subject/issuer thành chuỗi dễ đọc."""
    parts = []
    for rdn in rdns:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def fetch_tls_details(url: str) -> Dict[str, object]:
    """Kết nối TLS tới host và trả về meta dữ liệu chứng chỉ."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {"error": "Không xác định được hostname."}
    port = parsed.port or (80 if parsed.scheme == "http" else 443)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cipher_name, cipher_protocol, cipher_bits = tls.cipher()
                cert = tls.getpeercert()
                subject_alt_names = [
                    value for key, value in cert.get("subjectAltName", []) if key == "DNS"
                ]
                return {
                    "protocol": tls.version(),
                    "cipher": {
                        "name": cipher_name,
                        "protocol": cipher_protocol,
                        "bits": cipher_bits,
                    },
                    "certificate": {
                        "subject": _format_name(cert.get("subject", [])),
                        "issuer": _format_name(cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "subject_alt_names": ", ".join(subject_alt_names)
                        if subject_alt_names
                        else None,
                    },
                }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
