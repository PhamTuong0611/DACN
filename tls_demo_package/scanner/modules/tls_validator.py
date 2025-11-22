"""Advanced TLS/SSL validation and security analysis."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    x509 = None
    default_backend = None


# Mapping weak ciphers và mức độ nghiêm trọng
WEAK_CIPHERS = {
    "RC4": {"severity": "CRITICAL", "reason": "RC4 is cryptographically broken"},
    "DES-CBC": {"severity": "CRITICAL", "reason": "DES has 56-bit key, easily brute-forceable"},
    "3DES": {"severity": "HIGH", "reason": "3DES is deprecated and has weak security margins"},
    "CAMELLIA": {"severity": "LOW", "reason": "Camellia is acceptable but less common"},
    "IDEA": {"severity": "HIGH", "reason": "IDEA has limited support and weaker than modern ciphers"},
    "EXPORT": {"severity": "CRITICAL", "reason": "Export-grade cipher with intentional weak key"},
    "NULL": {"severity": "CRITICAL", "reason": "NULL cipher provides no encryption"},
    "ANON": {"severity": "CRITICAL", "reason": "Anonymous cipher suite has no authentication"},
}

WEAK_TLS_VERSIONS = {
    "TLSv1.0": {"severity": "CRITICAL", "reason": "TLS 1.0 is deprecated (RFC 8996)"},
    "TLSv1.1": {"severity": "HIGH", "reason": "TLS 1.1 is deprecated (RFC 8996)"},
}

STRONG_CIPHERS = {
    "AES": {"bits": 128, "security": "HIGH"},
    "AES-GCM": {"bits": 128, "security": "CRITICAL"},
    "CHACHA20": {"bits": 256, "security": "CRITICAL"},
}


def check_weak_cipher(cipher_name: str, bits: int) -> Optional[Dict[str, str]]:
    """Phát hiện cipher yếu."""
    for weak_pattern, details in WEAK_CIPHERS.items():
        if weak_pattern.upper() in cipher_name.upper():
            return {
                "cipher": cipher_name,
                "bits": str(bits),
                "severity": details["severity"],
                "reason": details["reason"],
            }
    
    # Check key length
    if bits < 128:
        return {
            "cipher": cipher_name,
            "bits": str(bits),
            "severity": "HIGH",
            "reason": f"Cipher key is only {bits} bits, should be at least 128",
        }
    
    return None


def check_weak_tls_version(protocol: str) -> Optional[Dict[str, str]]:
    """Phát hiện TLS version lỗi thời."""
    for weak_version, details in WEAK_TLS_VERSIONS.items():
        if weak_version in protocol:
            return {
                "version": protocol,
                "severity": details["severity"],
                "reason": details["reason"],
            }
    return None


def parse_certificate_date(date_str: str) -> Optional[datetime]:
    """Parse certificate date string (format: 'Jan  1 00:00:00 2024 GMT')."""
    try:
        # Standard SSL format: 'Jan  1 00:00:00 2024 GMT'
        return datetime.strptime(date_str.replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
    except (ValueError, TypeError):
        return None


def check_certificate_expiry(cert: Dict) -> Dict[str, object]:
    """Kiểm tra chứng chỉ đã hết hạn hay sắp hết hạn."""
    not_after_str = cert.get("notAfter")
    if not not_after_str:
        return {"status": "UNKNOWN", "message": "Cannot determine expiry"}
    
    try:
        not_after = parse_certificate_date(not_after_str)
        if not not_after:
            return {"status": "UNKNOWN", "message": f"Invalid date format: {not_after_str}"}
        
        now = datetime.utcnow()
        delta = (not_after - now).days
        
        if delta < 0:
            return {
                "status": "EXPIRED",
                "severity": "CRITICAL",
                "expiry": not_after_str,
                "days_expired": abs(delta),
                "message": f"Certificate expired {abs(delta)} days ago",
            }
        elif delta < 30:
            return {
                "status": "EXPIRING_SOON",
                "severity": "HIGH",
                "expiry": not_after_str,
                "days_remaining": delta,
                "message": f"Certificate expires in {delta} days",
            }
        elif delta < 90:
            return {
                "status": "EXPIRING_WARN",
                "severity": "MEDIUM",
                "expiry": not_after_str,
                "days_remaining": delta,
                "message": f"Certificate expires in {delta} days (renew soon)",
            }
        else:
            return {
                "status": "VALID",
                "severity": "INFO",
                "expiry": not_after_str,
                "days_remaining": delta,
                "message": f"Certificate valid for {delta} days",
            }
    except Exception as exc:  # noqa: BLE001
        return {"status": "ERROR", "message": str(exc)}


def check_hostname_match(cert: Dict, hostname: str) -> Dict[str, object]:
    """Kiểm tra hostname match với CN/SAN."""
    findings = []
    
    # Get subject CN
    subject = cert.get("subject", [])
    cn_values = []
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                cn_values.append(value)
    
    # Get SAN values
    san_values = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
    
    all_names = cn_values + san_values
    
    if not all_names:
        findings.append({
            "type": "NO_CN_SAN",
            "severity": "HIGH",
            "message": "Certificate has no CN or SAN",
        })
        return {"matches": False, "findings": findings}
    
    # Simple wildcard matching
    def matches_pattern(name: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            # Wildcard matching
            domain_parts = name.split(".")
            pattern_parts = pattern.split(".")
            if len(domain_parts) != len(pattern_parts):
                return False
            for domain_part, pattern_part in zip(domain_parts, pattern_parts):
                if pattern_part == "*":
                    continue
                if domain_part.lower() != pattern_part.lower():
                    return False
            return True
        else:
            return name.lower() == pattern.lower()
    
    hostname_lower = hostname.lower()
    matched = any(matches_pattern(hostname_lower, name.lower()) for name in all_names)
    
    if not matched:
        findings.append({
            "type": "HOSTNAME_MISMATCH",
            "severity": "CRITICAL",
            "hostname": hostname,
            "certificate_names": all_names,
            "message": f"Hostname {hostname} not found in certificate names",
        })
    
    return {
        "matches": matched,
        "certificate_names": all_names,
        "findings": findings,
    }


def get_certificate_from_server(host: str, port: int = 443, timeout: int = 10) -> Optional[Dict]:
    """Lấy certificate từ server."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()
    except Exception as exc:  # noqa: BLE001
        return None


def validate_self_signed(cert: Dict) -> Dict[str, object]:
    """Kiểm tra chứng chỉ tự ký (self-signed)."""
    subject = cert.get("subject", [])
    issuer = cert.get("issuer", [])
    
    # Convert to comparable format
    subject_str = str(subject)
    issuer_str = str(issuer)
    
    is_self_signed = subject_str == issuer_str
    
    return {
        "is_self_signed": is_self_signed,
        "severity": "HIGH" if is_self_signed else "INFO",
        "message": "Self-signed certificate" if is_self_signed else "Signed by CA",
    }


def analyze_certificate_chain(host: str, port: int = 443) -> Dict[str, object]:
    """Phân tích certificate chain (simplified - cần thêm cert chain extraction)."""
    cert = get_certificate_from_server(host, port)
    if not cert:
        return {"error": "Could not retrieve certificate"}
    
    findings = []
    
    # Check self-signed
    self_signed = validate_self_signed(cert)
    if self_signed.get("is_self_signed"):
        findings.append({
            "type": "SELF_SIGNED",
            "severity": "HIGH",
            "message": self_signed.get("message"),
        })
    
    # Check expiry
    expiry_check = check_certificate_expiry(cert)
    if expiry_check.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
        findings.append({
            "type": "EXPIRY",
            "severity": expiry_check.get("severity"),
            "message": expiry_check.get("message"),
        })
    
    # Check hostname
    hostname_check = check_hostname_match(cert, host)
    findings.extend(hostname_check.get("findings", []))
    
    return {
        "certificate": cert,
        "chain_issues": findings,
        "self_signed": self_signed,
        "expiry": expiry_check,
        "hostname": hostname_check,
    }


def analyze_tls_security(
    host: str,
    port: int = 443,
    protocol: str = "",
    cipher_name: str = "",
    cipher_bits: int = 0,
) -> Dict[str, object]:
    """Phân tích toàn bộ TLS security posture."""
    
    findings = []
    issues = []
    
    # 1. Check TLS version
    if protocol:
        weak_version = check_weak_tls_version(protocol)
        if weak_version:
            findings.append({
                "type": "WEAK_TLS_VERSION",
                "severity": weak_version["severity"],
                "data": weak_version,
            })
            issues.append(f"Weak TLS version: {protocol}")
    
    # 2. Check cipher strength
    if cipher_name:
        weak_cipher = check_weak_cipher(cipher_name, cipher_bits)
        if weak_cipher:
            findings.append({
                "type": "WEAK_CIPHER",
                "severity": weak_cipher["severity"],
                "data": weak_cipher,
            })
            issues.append(f"Weak cipher: {cipher_name}")
    
    # 3. Check certificate chain
    cert_analysis = analyze_certificate_chain(host, port)
    chain_issues = cert_analysis.get("chain_issues", [])
    findings.extend([
        {"type": issue["type"], "severity": issue["severity"], "data": issue}
        for issue in chain_issues
    ])
    
    overall_severity = "INFO"
    if any(f["severity"] == "CRITICAL" for f in findings):
        overall_severity = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        overall_severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        overall_severity = "MEDIUM"
    elif any(f["severity"] == "LOW" for f in findings):
        overall_severity = "LOW"
    
    return {
        "protocol": protocol,
        "cipher": cipher_name,
        "cipher_bits": cipher_bits,
        "findings": findings,
        "issues": issues,
        "overall_severity": overall_severity,
        "certificate_analysis": cert_analysis,
    }
