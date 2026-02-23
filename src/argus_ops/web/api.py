"""FastAPI application for the argus-ops web dashboard."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from argus_ops.reporters.json_reporter import diagnosis_to_dict, finding_to_dict
from argus_ops.web.watch_service import WatchService

_TEMPLATES_DIR = Path(__file__).parent / "templates"


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
    reload_interval = serve_cfg.get("reload_interval", 30)

    # -------------------------------------------------------------------------
    # HTML dashboard page
    # -------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        """Render the single-page dashboard."""
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "reload_interval": reload_interval,
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
        """Return AI diagnosis history (most recent first)."""
        state = watch.get_state()
        incidents = list(reversed(state["incidents"]))
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

    return app
