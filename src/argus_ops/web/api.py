"""FastAPI application for the Argus-Ops web dashboard."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from argus_ops.audit.logger import AuditLogger
from argus_ops.audit.models import AuditRecord, RiskLevel
from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role, Session
from argus_ops.automation import (
    AutomationService,
    classify_intent,
    prefers_direct_execution,
)
from argus_ops.models import ActionIntent
from argus_ops.reporters.json_reporter import diagnosis_to_dict, finding_to_dict
from argus_ops.web.watch_service import WatchService

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class LoginRequest(BaseModel):
    username: str
    password: str


class SettingsUpdate(BaseModel):
    watch_interval: int | None = Field(default=None, ge=10, le=3600)
    reload_interval: int | None = Field(default=None, ge=5, le=3600)


class AdminUserCreate(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer


class AdminUserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class AdminPasswordReset(BaseModel):
    password: str


class PlanRequest(BaseModel):
    goal: str
    mode: str = Field(default="auto")
    targets: list[str] = Field(default_factory=list)


class ApplyRequest(BaseModel):
    plan_id: str
    approve: bool = False
    direct: bool = False


def create_app(
    watch: WatchService,
    cfg: dict[str, Any],
    auth: Authenticator | None = None,
    audit_logger: AuditLogger | None = None,
    automation_service: AutomationService | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    from argus_ops import __version__

    auth_cfg = cfg.get("auth", {})
    audit_cfg = cfg.get("audit", {})
    auth = auth or Authenticator(
        data_dir=auth_cfg.get("data_dir"),
        session_ttl_hours=auth_cfg.get("session_ttl_hours", 24),
    )
    audit_logger = audit_logger or AuditLogger(audit_dir=audit_cfg.get("log_dir"))
    automation_service = automation_service or AutomationService(data_dir=auth_cfg.get("data_dir"))
    cookie_name = auth_cfg.get("cookie_name", "argus_ops_session")

    app = FastAPI(
        title="Argus-Ops Dashboard",
        description="AI-powered infrastructure discovery and operations dashboard",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    serve_cfg = cfg.get("serve", {})
    app.state.reload_interval = serve_cfg.get("reload_interval", 30)
    app.state.mcp_enabled = serve_cfg.get("mcp", False)
    app.state.cookie_name = cookie_name
    app.state.auth = auth
    app.state.audit_logger = audit_logger
    app.state.automation = automation_service

    def _get_session(request: Request) -> Session:
        session = getattr(request.state, "session", None)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        return session

    def _get_admin_session(session: Session = Depends(_get_session)) -> Session:
        if session.role != Role.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required",
            )
        return session

    @app.middleware("http")
    async def audit_middleware(request: Request, call_next):
        token = request.cookies.get(cookie_name, "")
        request.state.session = auth.session_from_token(token) if token else None
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id
        response = await call_next(request)
        session = getattr(request.state, "session", None)
        audit_logger.log(
            AuditRecord(
                actor=session.username if session else "anonymous",
                role=session.role.value if session else "",
                session_id=session.token[:12] if session else "",
                request_id=request_id,
                source="web",
                action=request.url.path,
                intent=(
                    ActionIntent.READ_ONLY
                    if request.method in _SAFE_METHODS
                    else ActionIntent.MUTATING
                ),
                http_method=request.method,
                path=request.url.path,
                target=request.url.path,
                resource=request.url.path,
                ip_address=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", ""),
                status_code=response.status_code,
                risk_level=(RiskLevel.low if request.method in _SAFE_METHODS else RiskLevel.medium),
                result={"status": "ok" if response.status_code < 400 else "error"},
            )
        )
        response.headers["X-Request-Id"] = request_id
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "server_time": datetime.now(timezone.utc).isoformat()}

    @app.get("/docs", include_in_schema=False)
    async def api_docs(session: Session = Depends(_get_admin_session)) -> HTMLResponse:
        return get_swagger_ui_html(openapi_url="/openapi.json", title="Argus-Ops API Docs")

    @app.get("/openapi.json", include_in_schema=False)
    async def api_openapi(session: Session = Depends(_get_admin_session)) -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        session = getattr(request.state, "session", None)
        template = "dashboard.html" if session else "login.html"
        return templates.TemplateResponse(
            template,
            {
                "request": request,
                "reload_interval": request.app.state.reload_interval,
                "version": __version__,
                "session": session,
            },
        )

    @app.post("/api/auth/login")
    async def api_auth_login(request: Request, body: LoginRequest) -> Response:
        session = auth.login(
            body.username,
            body.password,
            persist=False,
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
        )
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        response = JSONResponse(
            {
                "ok": True,
                "username": session.username,
                "role": session.role.value,
                "expires_at": session.expires_at.isoformat(),
            }
        )
        response.set_cookie(cookie_name, session.token, httponly=True, samesite="lax")
        return response

    @app.post("/api/auth/logout")
    async def api_auth_logout(request: Request) -> Response:
        session = getattr(request.state, "session", None)
        if session is not None:
            auth.log_event(
                "logout",
                session.username,
                ip_address=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", ""),
            )
        response = JSONResponse({"ok": True})
        response.delete_cookie(cookie_name)
        return response

    @app.get("/api/auth/me")
    async def api_auth_me(session: Session = Depends(_get_session)) -> dict[str, Any]:
        return {
            "username": session.username,
            "role": session.role.value,
            "expires_at": session.expires_at.isoformat(),
        }

    @app.get("/api/status")
    async def api_status(session: Session = Depends(_get_session)) -> dict[str, Any]:
        state = watch.get_state()
        return {
            "ok": True,
            "user": session.username,
            "role": session.role.value,
            "last_scan": state["last_scan"],
            "error": state["error"],
            "diagnose_status": state.get("diagnose_status", "idle"),
            "diagnose_error": state.get("diagnose_error"),
            "mcp_enabled": app.state.mcp_enabled,
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/scan")
    async def api_scan(session: Session = Depends(_get_session)) -> dict[str, Any]:
        state = watch.get_state()
        findings = state["findings"]
        return {
            "findings": [finding_to_dict(finding) for finding in findings],
            "total": len(findings),
            "last_scan": state["last_scan"],
            "error": state["error"],
            "user": session.username,
        }

    @app.get("/api/nodes")
    async def api_nodes(session: Session = Depends(_get_session)) -> dict[str, Any]:
        state = watch.get_state()
        nodes = state["nodes"]
        ready_count = sum(
            1
            for node in nodes
            if node.get("conditions", {}).get("Ready", {}).get("status") == "True"
        )
        return {
            "nodes": nodes,
            "total": len(nodes),
            "ready": ready_count,
            "last_scan": state["last_scan"],
            "user": session.username,
        }

    @app.get("/api/inventory")
    async def api_inventory(session: Session = Depends(_get_session)) -> dict[str, Any]:
        summary = watch.get_inventory_summary()
        return {
            "snapshot_count": summary.get("snapshot_count", 0),
            "latest_snapshot": summary.get("latest_snapshot"),
            "asset_count": len(summary.get("assets", [])),
            "relation_count": len(summary.get("relations", [])),
            "capabilities": summary.get("capabilities", []),
            "user": session.username,
        }

    @app.get("/api/assets")
    async def api_assets(session: Session = Depends(_get_session)) -> dict[str, Any]:
        summary = watch.get_inventory_summary()
        return {
            "assets": summary.get("assets", []),
            "total": len(summary.get("assets", [])),
            "user": session.username,
        }

    @app.get("/api/topology")
    async def api_topology(session: Session = Depends(_get_session)) -> dict[str, Any]:
        summary = watch.get_inventory_summary()
        return {
            "assets": summary.get("assets", []),
            "relations": summary.get("relations", []),
            "user": session.username,
        }

    @app.get("/api/plans")
    async def api_plans(session: Session = Depends(_get_session)) -> dict[str, Any]:
        plans = [plan.model_dump(mode="json") for plan in automation_service.store.list_recent()]
        return {"plans": plans, "total": len(plans), "user": session.username}

    @app.get("/api/executions")
    async def api_executions(session: Session = Depends(_get_session)) -> dict[str, Any]:
        records = [
            record.model_dump(mode="json")
            for record in automation_service.list_execution_history(limit=20)
        ]
        return {"executions": records, "total": len(records), "user": session.username}

    @app.get("/api/workflows")
    async def api_workflows(session: Session = Depends(_get_session)) -> dict[str, Any]:
        workflows = [
            workflow.model_dump(mode="json")
            for workflow in automation_service.list_workflows()
        ]
        return {"workflows": workflows, "total": len(workflows), "user": session.username}

    @app.get("/api/workflows/export/{plan_id}")
    async def api_workflow_export(
        plan_id: str,
        session: Session = Depends(_get_session),
    ) -> dict[str, Any]:
        try:
            export = automation_service.export_workflow(plan_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return {"workflow": export["content"], "path": export["path"], "user": session.username}

    @app.get("/api/plugins")
    async def api_plugins(session: Session = Depends(_get_session)) -> dict[str, Any]:
        plugins = automation_service.list_plugins()
        return {"plugins": plugins, "total": len(plugins), "user": session.username}

    @app.post("/api/plan")
    async def api_plan(
        body: PlanRequest,
        session: Session = Depends(_get_session),
    ) -> dict[str, Any]:
        intent = classify_intent(body.goal)
        if intent == ActionIntent.MUTATING and session.role != Role.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required for mutating plans",
            )
        if intent == ActionIntent.READ_ONLY:
            execution_mode = "read-only"
        elif body.mode == "direct" or (body.mode == "auto" and prefers_direct_execution(body.goal)):
            execution_mode = "direct"
        else:
            execution_mode = "gitops"
        state = watch.get_state()
        plan = automation_service.build_plan(
            body.goal,
            inventory_summary=watch.get_inventory_summary(),
            findings=state.get("findings", []),
            actor=session.username,
            execution_mode=execution_mode,
            target_assets=body.targets,
        )
        return {"ok": True, "plan": plan.model_dump(mode="json"), "user": session.username}

    @app.post("/api/apply")
    async def api_apply(
        body: ApplyRequest,
        session: Session = Depends(_get_admin_session),
    ) -> JSONResponse:
        try:
            result = automation_service.apply_plan(
                body.plan_id,
                actor=session.username,
                approve=body.approve,
                direct=body.direct,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        payload = {"ok": result.get("status") == "completed", **result, "user": session.username}
        status_code = (
            status.HTTP_200_OK
            if result.get("status") == "completed"
            else status.HTTP_409_CONFLICT
        )
        return JSONResponse(payload, status_code=status_code)

    @app.get("/api/diagnoses")
    async def api_diagnoses(session: Session = Depends(_get_session)) -> dict[str, Any]:
        incidents = await run_in_threadpool(watch.get_incidents)
        result = []
        for incident in incidents:
            result.append(
                {
                    "incident_id": incident.incident_id,
                    "status": incident.status,
                    "max_severity": incident.max_severity.value,
                    "created_at": incident.created_at.isoformat(),
                    "finding_count": len(incident.findings),
                    "diagnosis": (
                        diagnosis_to_dict(incident.diagnosis)
                        if incident.diagnosis
                        else None
                    ),
                }
            )
        return {"incidents": result, "total": len(result), "user": session.username}

    @app.get("/api/trend")
    async def api_trend(session: Session = Depends(_get_session)) -> dict[str, Any]:
        state = watch.get_state()
        return {"trend": state["trend"], "user": session.username}

    @app.get("/api/mcp/manifest")
    async def api_mcp_manifest(session: Session = Depends(_get_session)) -> dict[str, Any]:
        if not app.state.mcp_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="MCP manifest is disabled",
            )
        summary = watch.get_inventory_summary()
        return {
            "name": "argus-ops",
            "version": __version__,
            "capabilities": summary.get("capabilities", []),
            "tools": [
                {"name": "inventory", "endpoint": "/api/inventory", "role": "viewer"},
                {"name": "scan", "endpoint": "/api/scan", "role": "viewer"},
                {"name": "topology", "endpoint": "/api/topology", "role": "viewer"},
                {"name": "plans", "endpoint": "/api/plans", "role": "viewer"},
                {"name": "executions", "endpoint": "/api/executions", "role": "viewer"},
                {"name": "workflows", "endpoint": "/api/workflows", "role": "viewer"},
                {
                    "name": "workflow_export",
                    "endpoint": "/api/workflows/export/{plan_id}",
                    "role": "viewer",
                },
                {"name": "plugins", "endpoint": "/api/plugins", "role": "viewer"},
                {"name": "plan", "endpoint": "/api/plan", "role": "viewer_or_admin"},
                {"name": "apply", "endpoint": "/api/apply", "role": "admin"},
                {"name": "diagnose", "endpoint": "/api/diagnose", "role": "admin"},
                {"name": "admin_audit", "endpoint": "/api/admin/audit", "role": "admin"},
            ],
            "user": session.username,
        }

    @app.post("/api/diagnose")
    async def api_diagnose(session: Session = Depends(_get_admin_session)) -> dict[str, Any]:
        try:
            incidents = await run_in_threadpool(watch.diagnose_now)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return {
            "ok": True,
            "incidents": [
                {
                    "incident_id": incident.incident_id,
                    "status": incident.status,
                    "max_severity": incident.max_severity.value,
                    "created_at": incident.created_at.isoformat(),
                    "finding_count": len(incident.findings),
                    "diagnosis": (
                        diagnosis_to_dict(incident.diagnosis)
                        if incident.diagnosis
                        else None
                    ),
                }
                for incident in incidents
            ],
            "total": len(incidents),
            "user": session.username,
        }

    @app.get("/api/settings")
    async def api_settings_get(
        request: Request,
        session: Session = Depends(_get_session),
    ) -> dict[str, Any]:
        state = watch.get_state()
        return {
            "watch_interval": state["interval"],
            "reload_interval": request.app.state.reload_interval,
            "user": session.username,
        }

    @app.post("/api/settings")
    async def api_settings_post(
        request: Request,
        body: SettingsUpdate,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        if body.watch_interval is not None:
            try:
                watch.set_interval(body.watch_interval)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        if body.reload_interval is not None:
            request.app.state.reload_interval = body.reload_interval
        state = watch.get_state()
        return {
            "ok": True,
            "watch_interval": state["interval"],
            "reload_interval": request.app.state.reload_interval,
            "user": session.username,
        }

    @app.get("/api/admin/users")
    async def api_admin_users(session: Session = Depends(_get_admin_session)) -> dict[str, Any]:
        users = [
            {"username": user.username, "role": user.role.value, "is_active": user.is_active}
            for user in auth.user_store.list_users()
        ]
        return {"users": users, "total": len(users), "user": session.username}

    @app.post("/api/admin/users")
    async def api_admin_create_user(
        body: AdminUserCreate,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        try:
            user = auth.user_store.create_user(body.username, body.password, body.role)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "ok": True,
            "username": user.username,
            "role": user.role.value,
            "user": session.username,
        }

    @app.patch("/api/admin/users/{username}")
    async def api_admin_update_user(
        username: str,
        body: AdminUserUpdate,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        updated = False
        if body.role is not None:
            updated = auth.user_store.update_role(username, body.role) or updated
        if body.is_active is not None:
            updated = auth.user_store.set_active(username, body.is_active) or updated
        if not updated:
            raise HTTPException(status_code=404, detail=f"User '{username}' not found")
        return {"ok": True, "username": username, "user": session.username}

    @app.post("/api/admin/users/{username}/password")
    async def api_admin_reset_password(
        username: str,
        body: AdminPasswordReset,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        if not auth.user_store.change_password(username, body.password):
            raise HTTPException(status_code=404, detail=f"User '{username}' not found")
        return {"ok": True, "username": username, "user": session.username}

    @app.delete("/api/admin/users/{username}")
    async def api_admin_delete_user(
        username: str,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        if not auth.user_store.remove_user(username):
            raise HTTPException(status_code=404, detail=f"User '{username}' not found")
        return {"ok": True, "username": username, "user": session.username}

    @app.get("/api/admin/audit")
    async def api_admin_audit(
        actor: str | None = None,
        action: str | None = None,
        date_str: str | None = None,
        session: Session = Depends(_get_admin_session),
    ) -> dict[str, Any]:
        start_date = end_date = None
        if date_str:
            try:
                start_date = end_date = date.fromisoformat(date_str)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail="Invalid date format") from exc
        records = audit_logger.query(
            start_date=start_date,
            end_date=end_date,
            actor=actor,
            action=action,
            limit=500,
        )
        return {
            "records": [record.model_dump(mode="json") for record in records],
            "total": len(records),
            "user": session.username,
        }

    @app.get("/api/events")
    async def api_events(
        request: Request,
        session: Session = Depends(_get_session),
    ) -> StreamingResponse:
        async def event_generator():
            last_scan = None
            while True:
                if await request.is_disconnected():
                    break
                for event in watch.get_pending_events():
                    yield f"data: {json.dumps(event)}\n\n"
                state = watch.get_state()
                current_scan = state.get("last_scan")
                if current_scan != last_scan:
                    last_scan = current_scan
                    summary = state.get("inventory", {})
                    payload = {
                        "last_scan": current_scan,
                        "finding_count": len(state["findings"]),
                        "node_count": len(state["nodes"]),
                        "asset_count": len(summary.get("assets", [])),
                        "user": session.username,
                    }
                    yield (
                        "event: state\n"
                        f"data: {json.dumps(payload)}\n\n"
                    )
                await asyncio.sleep(1)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app





