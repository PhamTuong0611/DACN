"""Mô-đun phân tích dấu hiệu tấn công (bản demo)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AttackFinding:
    """Đại diện một phát hiện liên quan tới tấn công."""

    category: str
    severity: str
    summary: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class AttackSummary:
    """Thông tin tổng hợp sau khi phân tích."""

    status: str
    findings: List[AttackFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def analyze_attack_surface(target: str, log_content: Optional[bytes] = None) -> AttackSummary:
    """Placeholder phân tích tấn công cho từng mục tiêu.

    Hiện chưa có nguồn log thời gian thực, nên hàm trả về thông tin
    hướng dẫn để người dùng biết cần tích hợp log hoặc IDS.
    """

    if log_content:
        # Giả lập phân tích log đơn giản
        log_text = log_content.decode('utf-8', errors='ignore')
        log_lines = [line for line in log_text.split('\n') if line.strip()]
        findings = []
        
        # Kiểm tra một số dấu hiệu cơ bản
        not_found_count = log_text.count('404') if '404' in log_text else 0
        if not_found_count > 30:
            findings.append(AttackFinding(
                category="Path Scanning",
                severity="MEDIUM", 
                summary=f"Phát hiện {not_found_count} lỗi 404 - có thể là quét thư mục",
                indicators=["HTTP 404", "Directory scanning"]
            ))
        elif not_found_count >= 5:
            findings.append(AttackFinding(
                category="Path Scanning",
                severity="LOW",
                summary=f"Phát hiện {not_found_count} lỗi 404 bất thường - cần theo dõi thêm",
                indicators=["HTTP 404"]
            ))

        probing_keywords = [
            "wp-admin", "phpmyadmin", "config.php", "backup", "secret", "private",
            "internal", "uploads", "files", "download",
        ]
        probe_hits = sum(1 for line in log_lines if any(keyword in line for keyword in probing_keywords))
        if probe_hits and probe_hits < 20:
            findings.append(AttackFinding(
                category="Reconnaissance",
                severity="LOW",
                summary=f"Ghi nhận {probe_hits} truy vấn tới tài nguyên nhạy cảm.",
                indicators=probing_keywords,
            ))
        
        if '500' in log_text and log_text.count('500') > 5:
            findings.append(AttackFinding(
                category="Application Error",
                severity="HIGH",
                summary=f"Nhiều lỗi 500 ({log_text.count('500')} lần) - có thể bị khai thác",
                indicators=["HTTP 500", "Server errors"]
            ))
            
        # Kiểm tra SQL injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', 'exec(', 'script>']
        sql_count = sum(log_text.lower().count(pattern) for pattern in sql_patterns)
        if sql_count > 0:
            findings.append(AttackFinding(
                category="SQL Injection",
                severity="HIGH",
                summary=f"Phát hiện {sql_count} mẫu SQL injection trong log",
                indicators=sql_patterns
            ))
        
        # Phát hiện DDoS - đếm số request và IP
        ip_count = {}
        total_requests = len(log_lines)

        for line in log_lines:
            parts = line.split()
            if parts:
                ip = parts[0]
                ip_count[ip] = ip_count.get(ip, 0) + 1
        
        # Kiểm tra ngưỡng DDoS
        if total_requests > 1000:
            findings.append(AttackFinding(
                category="DDoS Suspicion",
                severity="HIGH",
                summary=f"Tổng {total_requests} request - vượt ngưỡng bình thường",
                indicators=[f"Total requests: {total_requests}"]
            ))
        
        # Kiểm tra IP có lưu lượng bất thường
        for ip, count in ip_count.items():
            if count > 100:  # Ngưỡng request/IP
                findings.append(AttackFinding(
                    category="Rate Limiting",
                    severity="MEDIUM" if count < 500 else "HIGH",
                    summary=f"IP {ip} gửi {count} request - có thể tấn công flood",
                    indicators=[f"IP: {ip}", f"Requests: {count}"]
                ))
        
        if findings:
            return AttackSummary(status="THREATS_DETECTED", findings=findings)
        else:
            return AttackSummary(
                status="ANALYZED", 
                findings=[], 
                notes=[f"Đã phân tích {len(log_text)} ký tự log, không phát hiện dấu hiệu đáng ngờ."]
            )

    notes = [
        "Chưa nhận được log lưu lượng hay cảnh báo IDS cho mục tiêu này.",
        "Tích hợp log truy cập, WAF/IDS hoặc nguồn NetFlow để kích hoạt phân tích tự động.",
    ]
    return AttackSummary(status="NO_DATA", findings=[], notes=notes)
