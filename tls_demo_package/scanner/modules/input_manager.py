"""Xử lý và chuẩn hóa danh sách mục tiêu nhập vào."""

from typing import Iterable, List, Optional


def normalize_target(raw: str) -> Optional[str]:
    """Chuẩn hóa chuỗi nhập thành URL hợp lệ."""
    candidate = raw.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return candidate


def prepare_targets(entries: Iterable[str]) -> List[str]:
    """Loại bỏ bản ghi trống/trùng và trả về danh sách mục tiêu hợp lệ."""
    seen: set[str] = set()
    prepared: List[str] = []
    for entry in entries:
        normalized = normalize_target(entry)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        prepared.append(normalized)
    return prepared
