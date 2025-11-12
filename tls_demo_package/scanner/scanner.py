#!/usr/bin/env python3
"""Interactive TLS configuration scanner with optional web UI."""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

from modules.fetcher import scan_targets
from modules.input_manager import prepare_targets
from modules.reporter import print_summary
from attack_detection.engine import analyze_attack_surface

app = typer.Typer(help="Quét kiểm tra header bảo mật và thông tin TLS cho domain mục tiêu.")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(str(BASE_DIR)),
    autoescape=select_autoescape(),
)


@app.command()
def scan(
    target: List[str] = typer.Option([], "--target", "-t", help="Target URL or hostname (repeatable)."),
) -> None:
    prepared = prepare_targets(target)
    if not prepared:
        typer.echo("Vui lòng cung cấp ít nhất một mục tiêu bằng --target.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Đang quét {len(prepared)} mục tiêu...")
    results = asyncio.run(scan_targets(prepared, None))
    print_summary(results)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host interface for the UI."),
    port: int = typer.Option(8080, "--port", "-p", help="Port for the UI."),
) -> None:
    template = TEMPLATE_ENV.get_template("ui_template.html")

    ui_state: Dict[str, object] = {
        "targets_text": "",
        "results": [],
        "log_result": None,
    }

    async def render_page(
        message: Optional[str],
        log_message: Optional[str],
    ):
        return web.Response(
            text=template.render(
                message=message,
                log_message=log_message,
                targets_text=ui_state["targets_text"],
                results=ui_state["results"],
                log_result=ui_state.get("log_result"),
            ),
            content_type="text/html",
        )

    async def handle_index(_: web.Request) -> web.Response:
        return await render_page(None, None)

    async def handle_scan(request: web.Request) -> web.Response:
        reader = await request.post()
        raw_targets = reader.get("targets", "")

        ui_state["targets_text"] = raw_targets
        prepared = prepare_targets(raw_targets.splitlines())
        if not prepared:
            return await render_page(
                "Hãy nhập ít nhất một domain hoặc URL hợp lệ.",
                None,
            )

        results = await scan_targets(prepared, None)
        ui_state["results"] = results
        message = f"Hoàn tất quét {len(prepared)} mục tiêu."
        return await render_page(message, None)

    async def handle_log_scan(request: web.Request) -> web.Response:
        reader = await request.multipart()
        log_content = None
        filename = ""

        async for field in reader:
            if field.name == "logfile" and field.filename:
                filename = field.filename
                log_content = await field.read()

        if not log_content:
            return await render_page(None, "Hãy chọn file log trước khi phân tích.")

        summary = analyze_attack_surface("uploaded-log", log_content)
        ui_state["log_result"] = {
            "status": summary.status,
            "findings": [
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "summary": finding.summary,
                    "indicators": finding.indicators,
                }
                for finding in summary.findings
            ],
            "notes": summary.notes,
        }

        log_message = (
            f"Đã phân tích log {filename}." if filename else "Đã phân tích file log tải lên."
        )
        return await render_page(None, log_message)

    web_app = web.Application()
    web_app.router.add_get("/", handle_index)
    web_app.router.add_post("/scan", handle_scan)
    web_app.router.add_post("/analyze-log", handle_log_scan)
    typer.echo(f"Mở trình duyệt tới http://{host}:{port} để dùng giao diện.")
    web.run_app(web_app, host=host, port=port)


if __name__ == "__main__":
    app()
