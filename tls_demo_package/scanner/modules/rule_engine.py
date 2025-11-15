"""Đánh giá mức rủi ro và đề xuất cải thiện cấu hình."""

from typing import Dict, List


def score_findings(findings: List[Dict[str, str]]) -> int:
    """Cộng điểm dựa trên mức độ nghiêm trọng của từng phát hiện."""
    score = 0
    weights = {"HIGH": 10, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        score += weights.get(severity, 0)
    return score


def classify_risk(score: int) -> str:
    """Phân loại ngưỡng rủi ro tổng thể dựa trên điểm."""
    if score >= 15:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def suggestions_from_findings(findings: List[Dict[str, str]]) -> List[str]:
    """Sinh danh sách gợi ý khắc phục từ các phát hiện."""
    messages: List[str] = []
    for finding in findings:
        rule = finding.get("rule")
        if rule == "HSTS_MISSING":
            messages.append("Bật Strict-Transport-Security để ép HTTPS.")
        elif rule == "COOKIE_HTTPONLY_MISSING":
            messages.append("Thêm thuộc tính HttpOnly cho cookie nhạy cảm.")
        elif rule == "COOKIE_SECURE_MISSING":
            messages.append("Đặt cờ Secure cho cookie khi dùng HTTPS.")
        elif rule == "COOKIE_SAMESITE_MISSING":
            messages.append("Thiết lập SameSite cho cookie để giảm CSRF.")
        elif rule == "NO_SET_COOKIE":
            messages.append("Không có cookie; xác nhận nếu đây là hành vi mong muốn.")
    return messages
