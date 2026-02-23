"""FastAPI application for the argus-ops web dashboard."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from argus_ops.reporters.json_reporter import diagnosis_to_dict, finding_to_dict
from argus_ops.web.watch_service import WatchService

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class SettingsUpdate(BaseModel):
    watch_interval: int | None = Field(default=None, ge=10, le=3600)
    reload_interval: int | None = Field(default=None, ge=5, le=3600)


def create_app(watch: WatchService, cfg: dict[str, Any]) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        watch: Running WatchService instance providing thread-safe cluster state.
        cfg: Full argus-ops config dict (used to inject serve settings into templates).

    Returns:
        Configured FastAPI application ready to be passed to uvicorn.run().
    """
    from argus_ops import __version__

    app = FastAPI(
        title="Argus-Ops Dashboard",
        description="AI-powered Kubernetes monitoring dashboard",
        version=__version__,
    )
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    serve_cfg = cfg.get("serve", {})

    # Mutable runtime settings stored on app.state so endpoints can read/write them
    app.state.reload_interval = serve_cfg.get("reload_interval", 30)

    # -------------------------------------------------------------------------
    # HTML dashboard page
    # -------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        """Render the single-page dashboard."""
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "reload_interval": request.app.state.reload_interval,
            "version": __version__,
        })

    # -------------------------------------------------------------------------
    # REST API
    # -------------------------------------------------------------------------

    @app.get("/api/status")
    async def api_status() -> dict[str, Any]:
        """Server health and last scan timestamp."""
        state = watch.get_state()
        return {
            "ok": True,
            "last_scan": state["last_scan"],
            "error": state["error"],
            "diagnose_status": state.get("diagnose_status", "idle"),
            "diagnose_error": state.get("diagnose_error"),
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/scan")
    async def api_scan() -> dict[str, Any]:
        """Return current findings list."""
        state = watch.get_state()
        findings = state["findings"]
        return {
            "findings": [finding_to_dict(f) for f in findings],
            "total": len(findings),
            "last_scan": state["last_scan"],
            "error": state["error"],
        }

    @app.get("/api/nodes")
    async def api_nodes() -> dict[str, Any]:
        """Return node health grid data."""
        state = watch.get_state()
        nodes = state["nodes"]
        ready_count = sum(
            1 for n in nodes
            if n.get("conditions", {}).get("Ready", {}).get("status") == "True"
        )
        return {
            "nodes": nodes,
            "total": len(nodes),
            "ready": ready_count,
            "last_scan": state["last_scan"],
        }

    @app.get("/api/diagnoses")
    async def api_diagnoses() -> dict[str, Any]:
        """Return AI diagnosis history from SQLite store (most recent first)."""
        incidents = await run_in_threadpool(watch.get_incidents)
        result = []
        for inc in incidents:
            entry: dict[str, Any] = {
                "incident_id": inc.incident_id,
                "status": inc.status,
                "max_severity": inc.max_severity.value,
                "created_at": inc.created_at.isoformat(),
                "finding_count": len(inc.findings),
                "diagnosis": diagnosis_to_dict(inc.diagnosis) if inc.diagnosis else None,
            }
            result.append(entry)
        return {"incidents": result, "total": len(result)}

    @app.get("/api/trend")
    async def api_trend() -> dict[str, Any]:
        """Return severity trend data points for the chart."""
        state = watch.get_state()
        return {"trend": state["trend"]}

    @app.post("/api/diagnose")
    async def api_diagnose() -> dict[str, Any]:
        """Run AI diagnosis on current findings on demand. Blocks until complete."""
        try:
            new_incidents = await run_in_threadpool(watch.diagnose_now)
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e

        result = []
        for inc in new_incidents:
            result.append({
                "incident_id": inc.incident_id,
                "status": inc.status,
                "max_severity": inc.max_severity.value,
                "created_at": inc.created_at.isoformat(),
                "finding_count": len(inc.findings),
                "diagnosis": diagnosis_to_dict(inc.diagnosis) if inc.diagnosis else None,
            })
        return {"ok": True, "incidents": result, "total": len(result)}

    @app.get("/api/settings")
    async def api_settings_get(request: Request) -> dict[str, Any]:
        """Return current runtime settings."""
        state = watch.get_state()
        return {
            "watch_interval": state["interval"],
            "reload_interval": request.app.state.reload_interval,
        }

    @app.post("/api/settings")
    async def api_settings_post(request: Request, body: SettingsUpdate) -> dict[str, Any]:
        """Update watch_interval and/or reload_interval at runtime."""
        if body.watch_interval is not None:
            try:
                watch.set_interval(body.watch_interval)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e)) from e
        if body.reload_interval is not None:
            request.app.state.reload_interval = body.reload_interval
        state = watch.get_state()
        return {
            "ok": True,
            "watch_interval": state["interval"],
            "reload_interval": request.app.state.reload_interval,
        }

    return app
