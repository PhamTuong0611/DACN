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

    web_app = web.Application()
    web_app.router.add_get("/", handle_index)
    web_app.router.add_post("/scan", handle_scan)
    typer.echo(f"Mở trình duyệt tới http://{host}:{port} để dùng giao diện.")
    web.run_app(web_app, host=host, port=port)


if __name__ == "__main__":
    app()
