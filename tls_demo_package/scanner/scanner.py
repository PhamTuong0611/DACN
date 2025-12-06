#!/usr/bin/env python3
"""Interactive TLS configuration scanner with optional web UI."""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

from modules.exporter import export_results
from modules.fetcher import scan_targets
from modules.input_manager import prepare_targets
from modules.reporter import print_summary

app = typer.Typer(help="Quét kiểm tra header bảo mật và thông tin TLS cho domain mục tiêu.")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(str(BASE_DIR)),
    autoescape=select_autoescape(),
)


@app.command()
def scan(
    target: List[str] = typer.Option([], "--target", "-t", help="Target URL or hostname (repeatable)."),
    export_format: Optional[str] = typer.Option(
        None,
        "--export",
        "-e",
        help="Export format: json,csv,markdown (comma-separated)"
    ),
    output_dir: str = typer.Option(
        "./reports",
        "--output-dir",
        "-o",
        help="Output directory for exported reports"
    ),
) -> None:
    prepared = prepare_targets(target)
    if not prepared:
        typer.echo("Vui lòng cung cấp ít nhất một mục tiêu bằng --target.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Đang quét {len(prepared)} mục tiêu...")
    results = asyncio.run(scan_targets(prepared, None))
    print_summary(results)
    
    # Export results if requested
    if export_format:
        formats = [fmt.strip() for fmt in export_format.split(",")]
        typer.echo(f"\nExporting to {', '.join(formats)}...")
        try:
            exported = export_results(results, output_dir, formats)
            for fmt, filepath in exported.items():
                typer.echo(f"✓ {fmt.upper()}: {filepath}")
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"Export error: {exc}", err=True)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host interface for the UI."),
    port: int = typer.Option(8080, "--port", "-p", help="Port for the UI."),
) -> None:
    template = TEMPLATE_ENV.get_template("ui_template.html")

    ui_state: Dict[str, object] = {
        "targets_text": "",
        "results": [],
    }

    async def render_page(
        message: Optional[str],
    ):
        return web.Response(
            text=template.render(
                message=message,
                targets_text=ui_state["targets_text"],
                results=ui_state["results"],
            ),
            content_type="text/html",
        )

    async def handle_index(_: web.Request) -> web.Response:
        return await render_page(None)

    async def handle_scan(request: web.Request) -> web.Response:
        reader = await request.post()
        raw_targets = reader.get("targets", "")

        ui_state["targets_text"] = raw_targets
        prepared = prepare_targets(raw_targets.splitlines())
        if not prepared:
            return await render_page(
                "Hãy nhập ít nhất một domain hoặc URL hợp lệ.",
            )

        results = await scan_targets(prepared, None)
        ui_state["results"] = results
        message = f"Hoàn tất quét {len(prepared)} mục tiêu."
        return await render_page(message)

    async def handle_export(request: web.Request) -> web.Response:
        """Export scan results in multiple formats."""
        if not ui_state.get("results"):
            return await render_page("Không có dữ liệu để xuất. Vui lòng thực hiện quét trước.")
        
        try:
            reader = await request.post()
            formats = reader.getall("formats") if "formats" in reader else []
            
            if not formats:
                formats = ["json", "csv", "markdown"]
            
            exported = export_results(
                ui_state["results"],
                output_dir="./reports",
                formats=formats,
            )
            
            links_html = "<br>".join([
                f"✓ {fmt.upper()}: <code>{path}</code>"
                for fmt, path in exported.items()
            ])
            message = f"Xuất báo cáo thành công! Các tập tin đã được lưu:<br>{links_html}"
            
            return await render_page(message)
        except Exception as exc:  # noqa: BLE001
            return await render_page(f"Lỗi xuất báo cáo: {exc}")

    web_app = web.Application()
    web_app.router.add_get("/", handle_index)
    web_app.router.add_post("/scan", handle_scan)
    web_app.router.add_post("/export", handle_export)
    typer.echo(f"Mở trình duyệt tới http://{host}:{port} để dùng giao diện.")
    web.run_app(web_app, host=host, port=port)


if __name__ == "__main__":
    app()
