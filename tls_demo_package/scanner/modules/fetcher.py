"""Các hàm tương tác mạng để lấy dữ liệu từ mục tiêu."""

from __future__ import annotations

import asyncio
import subprocess
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from modules.rule_engine import classify_risk, score_findings, suggestions_from_findings
from modules.tls_engine import fetch_tls_details
from attack_detection import analyze_attack_surface


def extract_hostport(url: str) -> str:
    """Rút trích host:port để chạy công cụ bên ngoài như SSLyze."""
    parsed = urlparse(url)
    host = parsed.hostname or url
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "http":
        port = 80
    else:
        port = 443
    return f"{host}:{port}"


def run_sslyze(target: str) -> Dict[str, str]:
    """Thực thi sslyze và thu thập stdout/stderr."""
    try:
        process = subprocess.run(
            ["sslyze", target],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        stdout = process.stdout or ""
        stderr = process.stderr or ""
        if not stdout and not stderr:
            stdout = "SSLyze hoàn tất nhưng không có dữ liệu đầu ra."
        return {
            "output": stdout,
            "error": stderr,
            "return_code": str(process.returncode),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


async def fetch_target(session: aiohttp.ClientSession, url: str) -> Dict[str, object]:
    """Gửi HTTP GET để lấy status, header và một phần nội dung."""
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            body = await response.text()
            return {
                "url": url,
                "status": response.status,
                "headers": dict(response.headers),
                "body_snippet": body[:500],
            }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": str(exc)}


def analyze_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Áp dụng quy tắc kiểm tra header cơ bản."""
    findings: List[Dict[str, str]] = []
    hsts = headers.get("Strict-Transport-Security")
    if not hsts:
        findings.append({
            "rule": "HSTS_MISSING",
            "severity": "HIGH",
            "detail": "Strict-Transport-Security header missing.",
        })
    else:
        findings.append({
            "rule": "HSTS_PRESENT",
            "severity": "INFO",
            "detail": hsts,
        })

    set_cookie = headers.get("Set-Cookie")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            findings.append({
                "rule": "COOKIE_HTTPONLY_MISSING",
                "severity": "MEDIUM",
                "detail": set_cookie,
            })
        if "Secure" not in set_cookie:
            findings.append({
                "rule": "COOKIE_SECURE_MISSING",
                "severity": "MEDIUM",
                "detail": set_cookie,
            })
        if "SameSite" not in set_cookie:
            findings.append({
                "rule": "COOKIE_SAMESITE_MISSING",
                "severity": "LOW",
                "detail": set_cookie,
            })
    else:
        findings.append({
            "rule": "NO_SET_COOKIE",
            "severity": "INFO",
            "detail": "No Set-Cookie header returned.",
        })
    return findings


async def scan_targets(urls: List[str], log_content: Optional[bytes] = None) -> List[Dict[str, object]]:
    """Chạy gom thông tin từ HTTP, TLS và công cụ phụ trợ."""
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

        hostport = extract_hostport(entry["url"] or "")
        entry["sslyze"] = run_sslyze(hostport)

        attack_summary = analyze_attack_surface(entry["url"] or "", log_content)
        entry["attack_detection"] = {
            "status": attack_summary.status,
            "findings": [
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "summary": finding.summary,
                    "indicators": finding.indicators,
                }
                for finding in attack_summary.findings
            ],
            "notes": attack_summary.notes,
        }
        aggregated.append(entry)

    return aggregated


async def scan_single_target(url: str) -> Dict[str, object]:
    """Tiện ích quét một mục tiêu duy nhất."""
    results = await scan_targets([url], None)
    if results:
        first = results[0]
        first.setdefault("sslyze", {})
        return first
    return {"url": url, "error": "Không có dữ liệu."}
