"""Đánh giá mức rủi ro và đề xuất cải thiện cấu hình."""

from typing import Dict, List


# Critical security headers - missing these is HIGH/CRITICAL risk
CRITICAL_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "reason": "Enforce HTTPS - prevents MITM attacks",
        "recommendation": "Set-Header max-age=31536000; includeSubDomains; preload"
    },
}

# Important security headers - missing is MEDIUM risk
IMPORTANT_SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "reason": "Prevent MIME type sniffing",
        "recommendation": "Set header to 'nosniff'"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "reason": "Prevent clickjacking",
        "recommendation": "Set to 'DENY' or 'SAMEORIGIN'"
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "reason": "Mitigate XSS and injection attacks",
        "recommendation": "Define strict CSP policy"
    },
}

# Optional/Best practice headers - missing is LOW/INFO
OPTIONAL_SECURITY_HEADERS = {
    "Referrer-Policy": {
        "severity": "LOW",
        "reason": "Control referrer information leakage",
        "recommendation": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "reason": "Legacy XSS protection (deprecated but helpful for older browsers)",
        "recommendation": "Set to '1; mode=block' for older browsers"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "reason": "Control browser features",
        "recommendation": "Restrict unnecessary permissions"
    },
}


def check_security_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Kiểm tra security headers - phân loại theo tầm quan trọng."""
    findings: List[Dict[str, str]] = []
    headers_lower = {key.lower(): (key, value) for key, value in headers.items()}
    
    all_headers = {
        **CRITICAL_SECURITY_HEADERS,
        **IMPORTANT_SECURITY_HEADERS,
        **OPTIONAL_SECURITY_HEADERS,
    }
    
    for header_name, header_info in all_headers.items():
        header_lower = header_name.lower()
        if header_lower not in headers_lower:
            findings.append({
                "rule": f"{header_name.upper()}_MISSING",
                "severity": header_info["severity"],
                "detail": f"Missing {header_name}: {header_info['reason']}",
                "recommendation": header_info["recommendation"],
            })
        else:
            actual_key, value = headers_lower[header_lower]
            findings.append({
                "rule": f"{header_name.upper()}_PRESENT",
                "severity": "INFO",
                "detail": f"{actual_key}: {value}",
            })
    
    return findings


def check_cookie_attributes(set_cookie: str) -> List[Dict[str, str]]:
    """Kiểm tra cookie attributes chi tiết."""
    findings: List[Dict[str, str]] = []
    cookie_lower = set_cookie.lower()
    
    required_attrs = {
        "Secure": {"severity": "HIGH", "reason": "Cookie transmitted only over HTTPS", "key": "secure"},
        "HttpOnly": {"severity": "MEDIUM", "reason": "Cookie not accessible via JavaScript", "key": "httponly"},
        "SameSite": {"severity": "MEDIUM", "reason": "Protection against CSRF attacks", "key": "samesite"},
    }
    
    for attr, info in required_attrs.items():
        attr_key = info["key"]
        if attr_key not in cookie_lower:
            findings.append({
                "rule": f"COOKIE_{attr.upper()}_MISSING",
                "severity": info["severity"],
                "detail": f"Cookie missing {attr} attribute",
                "recommendation": f"Add {attr} flag to Set-Cookie header",
            })
        elif attr == "SameSite":
            if "samesite=strict" in cookie_lower or "samesite=lax" in cookie_lower:
                findings.append({
                    "rule": "COOKIE_SAMESITE_VALID",
                    "severity": "INFO",
                    "detail": "Cookie has valid SameSite",
                })
            elif "samesite=none" in cookie_lower:
                if "secure" in cookie_lower:
                    findings.append({
                        "rule": "COOKIE_SAMESITE_NONE_SECURE",
                        "severity": "LOW",
                        "detail": "SameSite=None with Secure (acceptable for third-party)",
                    })
                else:
                    findings.append({
                        "rule": "COOKIE_SAMESITE_NONE_INSECURE",
                        "severity": "MEDIUM",
                        "detail": "SameSite=None without Secure (risky)",
                    })
        else:
            findings.append({
                "rule": f"COOKIE_{attr.upper()}_PRESENT",
                "severity": "INFO",
                "detail": f"Cookie has {attr}",
            })
    
    return findings


def score_findings(findings: List[Dict[str, str]]) -> int:
    """Tính điểm dựa trên mức độ nghiêm trọng."""
    score = 0
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        score += weights.get(severity, 0)
    return score


def classify_risk(score: int) -> str:
    """Phân loại ngưỡng rủi ro dựa trên điểm số."""
    if score >= 40:
        return "CRITICAL"
    if score >= 20:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def suggestions_from_findings(findings: List[Dict[str, str]]) -> List[str]:
    """Sinh danh sách gợi ý khắc phục từ các phát hiện."""
    messages: List[str] = []
    processed_rules = set()
    
    for finding in findings:
        rule = finding.get("rule")
        if rule in processed_rules:
            continue
        processed_rules.add(rule)
        
        # Security headers suggestions
        if rule == "STRICT-TRANSPORT-SECURITY_MISSING":
            messages.append("⚠️ CRITICAL: Enable Strict-Transport-Security (HSTS) to force HTTPS. Use: max-age=31536000; includeSubDomains; preload")
        elif rule == "X-CONTENT-TYPE-OPTIONS_MISSING":
            messages.append("✓ Add X-Content-Type-Options: nosniff to prevent MIME sniffing")
        elif rule == "X-FRAME-OPTIONS_MISSING":
            messages.append("✓ Add X-Frame-Options to prevent clickjacking (use DENY or SAMEORIGIN)")
        elif rule == "CONTENT-SECURITY-POLICY_MISSING":
            messages.append("✓ Implement Content-Security-Policy to mitigate XSS and injection attacks")
        elif rule == "REFERRER-POLICY_MISSING":
            messages.append("✓ Add Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage")
        elif rule == "X-XSS-PROTECTION_MISSING":
            messages.append("✓ Add X-XSS-Protection: 1; mode=block (legacy but helpful for older browsers)")
        
        # Cookie suggestions
        elif rule == "COOKIE_SECURE_MISSING":
            messages.append("⚠️ HIGH: Set Secure flag on cookies to prevent transmission over HTTP")
        elif rule == "COOKIE_HTTPONLY_MISSING":
            messages.append("⚠️ Add HttpOnly flag to sensitive cookies to prevent XSS theft")
        elif rule == "COOKIE_SAMESITE_MISSING":
            messages.append("✓ Set SameSite=Lax or SameSite=Strict to mitigate CSRF attacks")
        elif rule == "COOKIE_SAMESITE_WEAK":
            messages.append("✓ Upgrade SameSite to Strict or Lax instead of None")
        elif rule == "NO_SET_COOKIE":
            messages.append("ℹ️ No cookies set; verify this is intentional")
    
    return messages
