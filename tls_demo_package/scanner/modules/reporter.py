"""Định dạng kết quả quét cho CLI."""

from typing import Dict, List

import typer


def print_summary(results: List[Dict[str, object]]) -> None:
    """In kết quả bằng tiếng Việt."""
    for item in results:
        typer.echo()
        typer.echo(f"Mục tiêu: {item.get('url')}")
        if item.get("error"):
            typer.echo(f"  Lỗi: {item['error']}")
            continue
        
        typer.echo(f"  Trạng thái HTTP: {item.get('status')}")
        typer.echo(f"  Điểm đánh giá: {item.get('score')} (Mức rủi ro: {item.get('risk')})")
        
        for finding in item.get("findings", []):
            typer.echo(f"    - {finding['severity']}: {finding['rule']} ({finding['detail']})")
        
        suggestions = item.get("suggestions", [])
        if suggestions:
            typer.echo("  Gợi ý cải thiện:")
            for suggestion in suggestions:
                typer.echo(f"    • {suggestion}")
        
        tls_details = item.get("tls") or {}
        if tls_details.get("error"):
            typer.echo(f"  Lỗi TLS: {tls_details['error']}")
        else:
            cipher = tls_details.get("cipher", {})
            typer.echo(
                "  TLS: protocol={} cipher={}".format(
                    tls_details.get("protocol"), cipher.get("name")
                )
            )

