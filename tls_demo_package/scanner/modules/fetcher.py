"""Các hàm tương tác mạng để lấy dữ liệu từ mục tiêu."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from modules.rule_engine import classify_risk, score_findings, suggestions_from_findings, check_security_headers, check_cookie_attributes
from modules.tls_engine import fetch_tls_details
from modules.tls_validator import analyze_tls_security
from modules.cert_chain import get_certificate_chain, analyze_chain_security, validate_certificate_chain_integrity




async def fetch_target(session: aiohttp.ClientSession, url: str) -> Dict[str, object]:
    """Gửi HTTP GET để lấy status, header."""
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            return {
                "url": url,
                "status": response.status,
                "headers": dict(response.headers),
            }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": str(exc)}


def analyze_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Áp dụng quy tắc kiểm tra header bảo mật."""
    findings: List[Dict[str, str]] = []
    
    header_findings = check_security_headers(headers)
    findings.extend(header_findings)
    
    set_cookie_headers = [
        value for key, value in headers.items()
        if key.lower() == "set-cookie"
    ]
    
    if set_cookie_headers:
        for set_cookie in set_cookie_headers:
            cookie_findings = check_cookie_attributes(set_cookie)
            findings.extend(cookie_findings)
    else:
        findings.append({
            "rule": "NO_SET_COOKIE",
            "severity": "INFO",
            "detail": "No Set-Cookie header returned.",
        })
    
    return findings


async def scan_targets(urls: List[str], log_content: Optional[bytes] = None) -> List[Dict[str, object]]:
    """Quét HTTP, TLS và phân tích bảo mật."""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_target(session, url) for url in urls]
        raw_results = await asyncio.gather(*tasks)

    aggregated: List[Dict[str, object]] = []
    for result in raw_results:
        entry: Dict[str, object] = {"url": result.get("url")}
        if "error" in result:
            entry["error"] = result["error"]
            aggregated.append(entry)
            continue

        headers: Dict[str, str] = result.get("headers", {})
        entry["status"] = result.get("status")
        entry["headers"] = headers
        entry["findings"] = analyze_headers(headers)
        entry["score"] = score_findings(entry["findings"])
        entry["risk"] = classify_risk(entry["score"])
        entry["suggestions"] = suggestions_from_findings(entry["findings"])
        entry["tls"] = fetch_tls_details(entry["url"] or "")
        
        parsed_url = urlparse(entry["url"] or "")
        host = parsed_url.hostname or ""
        port = parsed_url.port or 443
        
        if host:
            entry["cert_chain"] = get_certificate_chain(host, port, timeout=10)
            entry["chain_security"] = analyze_chain_security(entry["cert_chain"])
            entry["chain_integrity"] = validate_certificate_chain_integrity(entry["cert_chain"])
        
        if isinstance(entry["tls"], dict) and "error" not in entry["tls"]:
            protocol = entry["tls"].get("protocol", "")
            cipher = entry["tls"].get("cipher", {})
            cipher_name = cipher.get("name", "")
            cipher_bits = cipher.get("bits", 0)
            
            if all([host, protocol, cipher_name]):
                tls_analysis = analyze_tls_security(host, port, protocol, cipher_name, cipher_bits)
                entry["tls_analysis"] = tls_analysis
                
                for tls_finding in tls_analysis.get("findings", []):
                    entry["findings"].append({
                        "rule": tls_finding.get("type", "TLS_ISSUE"),
                        "severity": tls_finding.get("severity", "INFO"),
                        "detail": str(tls_finding.get("data", {})),
                    })
                
                entry["score"] = score_findings(entry["findings"])
                entry["risk"] = classify_risk(entry["score"])
                entry["suggestions"] = suggestions_from_findings(entry["findings"])

        aggregated.append(entry)

    return aggregated


async def scan_single_target(url: str) -> Dict[str, object]:
    """Tiện ích quét một mục tiêu duy nhất."""
    results = await scan_targets([url], None)
    if results:
        return results[0]
    return {"url": url, "error": "Không có dữ liệu."}
