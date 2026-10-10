"""A local web "command center" for the agent: start runs, watch them
live (tool calls, results, model messages) over a WebSocket, approve or
deny gated actions from the browser instead of a terminal prompt, and
browse reports/knowledge/staged learn drafts.

This grants no new capability over the CLI -- it's the same
SecurityAgent/LearningAgent/Guardrails underneath, with a browser
standing in for the terminal. Every safety property from the rest of
this repo holds exactly as before: scope.yaml authorization is still
required before a run starts, the approval gate still blocks (now via
a browser click instead of stdin `y/N`), and nothing here bypasses
`guardrails.py`.

Run with:
    pip install -r security_agent/ui_requirements.txt
    python -m security_agent.cli serve
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from .. import config as cfg
from ..cli import OWASP_CATEGORIES, SPECIALIZED_CATEGORIES, _build_owasp_objective, _build_specialized_objective
from ..config import load_config
from ..guardrails import Guardrails, Scope, ScopeViolation
from ..learning import LearningAgent
from ..loop import SecurityAgent
from ..memory import KnowledgeBase

logger = logging.getLogger("security_agent.ui")

STATIC_DIR = Path(__file__).resolve().parent / "static"


# ------------------------------------------------------------ connection manager


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, event: dict) -> None:
        async with self._lock:
            conns = list(self._connections)
        dead = []
        for ws in conns:
            try:
                await ws.send_json(event)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)


manager = ConnectionManager()
MAIN_LOOP: asyncio.AbstractEventLoop | None = None


def broadcast_sync(event: dict[str, Any]) -> None:
    """Called from a background thread (an agent run or a learn job) to
    push an event to every connected browser. Best-effort: a run must
    never fail or block because no browser happens to be connected, or
    because sending to one failed.
    """
    if MAIN_LOOP is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(event), MAIN_LOOP)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to broadcast event to UI clients (non-fatal).")


# ------------------------------------------------------------------- jobs


@dataclass
class Job:
    id: str
    kind: str  # "run" | "learn" | "consolidate"
    status: str = "running"  # "running" | "finished" | "error"
    summary: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


@dataclass
class PendingApproval:
    id: str
    job_id: str
    category: str
    description: str
    event: threading.Event = field(default_factory=threading.Event)
    decision: bool = False


PENDING_APPROVALS: dict[str, PendingApproval] = {}
PENDING_LOCK = threading.Lock()

APPROVAL_TIMEOUT_SECONDS = 1800  # auto-deny if nobody answers in 30 minutes


def make_ui_asker(job_id: str):
    """Returns an `asker` callable compatible with guardrails.ApprovalGate
    -- instead of blocking on stdin, it broadcasts a request to every
    connected browser and blocks the calling (background) thread until
    POST /api/approve/{request_id} resolves it, or it times out (auto-deny,
    never auto-approve).
    """

    def _asker(prompt: str) -> bool:
        category, _, description = prompt.partition(": ")
        req_id = str(uuid.uuid4())
        pending = PendingApproval(id=req_id, job_id=job_id, category=category, description=description)
        with PENDING_LOCK:
            PENDING_APPROVALS[req_id] = pending

        broadcast_sync(
            {
                "type": "approval_requested",
                "job_id": job_id,
                "request_id": req_id,
                "category": category,
                "description": description,
            }
        )

        answered = pending.event.wait(timeout=APPROVAL_TIMEOUT_SECONDS)
        with PENDING_LOCK:
            PENDING_APPROVALS.pop(req_id, None)

        decision = pending.decision if answered else False
        broadcast_sync(
            {
                "type": "approval_resolved",
                "job_id": job_id,
                "request_id": req_id,
                "approved": decision,
                "timed_out": not answered,
            }
        )
        return decision

    return _asker


def _run_agent_job(job_id: str, objective: str, non_interactive: bool) -> None:
    job = JOBS[job_id]
    try:
        config = load_config()
        config.require_human_approval_default = not non_interactive
        asker = None if non_interactive else make_ui_asker(job_id)
        guardrails = Guardrails(asker=asker, auto_deny_approvals=non_interactive)
        agent = SecurityAgent(
            config=config,
            guardrails=guardrails,
            on_event=lambda ev: broadcast_sync({**ev, "job_id": job_id}),
        )
        report = agent.run(objective)
        job.status, job.summary = "finished", ("\n".join(report.findings) or "(no findings)")
    except ScopeViolation as exc:
        job.status, job.summary = "error", f"REFUSING TO START: {exc}"
    except Exception as exc:  # noqa: BLE001
        logger.exception("Agent job failed")
        job.status, job.summary = "error", str(exc)
    broadcast_sync({"type": "job_finished", "job_id": job_id, "status": job.status, "summary": job.summary})


def _run_learn_job(job_id: str, source: str, source_type: str, label: str) -> None:
    job = JOBS[job_id]
    try:
        agent = LearningAgent(config=load_config())
        if source_type == "repo":
            report = agent.learn_from_repo(source)
        elif source_type == "document":
            report = agent.learn_from_document(source)
        elif source_type == "url":
            report = agent.learn_from_url(source)
        else:
            report = agent.learn_from_text(source, label=label)
        job.status = "error" if report.decision == "error" else "finished"
        job.summary = report.reasoning
        job.extra = {
            "decision": report.decision,
            "staged_tool_path": str(report.staged_tool_path) if report.staged_tool_path else None,
            "staged_playbook_path": str(report.staged_playbook_path) if report.staged_playbook_path else None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("Learn job failed")
        job.status, job.summary = "error", str(exc)
    broadcast_sync({"type": "job_finished", "job_id": job_id, "status": job.status, "summary": job.summary, "extra": job.extra})


def _run_consolidate_job(job_id: str) -> None:
    job = JOBS[job_id]
    try:
        agent = LearningAgent(config=load_config())
        report = agent.consolidate()
        job.status = "error" if report.decision == "error" else "finished"
        job.summary = report.reasoning
        job.extra = {"staged_playbook_path": str(report.staged_playbook_path) if report.staged_playbook_path else None}
    except Exception as exc:  # noqa: BLE001
        logger.exception("Consolidate job failed")
        job.status, job.summary = "error", str(exc)
    broadcast_sync({"type": "job_finished", "job_id": job_id, "status": job.status, "summary": job.summary, "extra": job.extra})


def _start_job(kind: str, target_fn, *args) -> Job:
    job_id = str(uuid.uuid4())
    job = Job(id=job_id, kind=kind)
    with JOBS_LOCK:
        JOBS[job_id] = job
    thread = threading.Thread(target=target_fn, args=(job_id, *args), daemon=True)
    thread.start()
    return job


# ------------------------------------------------------------------- app


@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    yield


app = FastAPI(title="the-hack-agent command center", lifespan=lifespan)


class RunRequest(BaseModel):
    mode: str = "run"  # "run" | "owasp-scan" | "specialized-scan"
    objective: str | None = None
    target: str | None = None
    category: str | None = None
    non_interactive: bool = False


class LearnRequest(BaseModel):
    source: str
    type: str = "repo"  # repo|document|url|text
    label: str = "pasted-text"


class ApproveRequest(BaseModel):
    approved: bool


@app.get("/", response_class=HTMLResponse)
async def index():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    html = html.replace("{{OWASP_CATEGORIES_JSON}}", json.dumps(OWASP_CATEGORIES))
    html = html.replace("{{SPECIALIZED_CATEGORIES_JSON}}", json.dumps(SPECIALIZED_CATEGORIES))
    return HTMLResponse(html)


@app.get("/api/scope")
async def get_scope():
    try:
        scope = Scope.load()
    except ScopeViolation as exc:
        return {"error": str(exc)}
    authorized_ok = True
    authorized_error = None
    try:
        scope.check_authorized()
    except ScopeViolation as exc:
        authorized_ok = False
        authorized_error = str(exc)
    return {
        "authorized": scope.authorized,
        "authorized_ok": authorized_ok,
        "authorized_error": authorized_error,
        "authorized_by": scope.authorized_by,
        "authorization_reference": scope.authorization_reference,
        "allowed_domains": scope.allowed_domains,
        "allowed_cidrs": scope.allowed_cidrs,
        "rules_of_engagement": scope.rules_of_engagement,
        "budgets": scope.budgets,
        "require_human_approval_for": scope.require_human_approval_for,
        "disclosure_recipients_configured": len(scope.allowed_disclosure_recipients),
    }


@app.get("/api/playbooks")
async def list_playbooks():
    kb = KnowledgeBase()
    out = []
    for f in sorted(kb.playbooks_dir.glob("*.md")):
        first_line = f.read_text(encoding="utf-8").splitlines()[0].lstrip("# ")
        out.append({"name": f.name, "title": first_line})
    return out


@app.get("/api/knowledge")
async def list_knowledge():
    kb = KnowledgeBase()
    out = []
    for f in sorted(kb.root.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        if f.name.lower() == "readme.md":
            continue
        out.append({"name": f.name, "mtime": f.stat().st_mtime})
    return out


@app.get("/api/staging")
async def list_staging():
    tools = sorted(p.name for p in cfg.TOOLS_STAGING_DIR.glob("*.draft")) if cfg.TOOLS_STAGING_DIR.exists() else []
    playbooks = (
        sorted(p.name for p in cfg.PLAYBOOKS_STAGING_DIR.glob("*.draft")) if cfg.PLAYBOOKS_STAGING_DIR.exists() else []
    )
    return {"tools": tools, "playbooks": playbooks}


def _safe_report_path(rel_path: str) -> Path:
    base = cfg.REPORTS_DIR.resolve()
    candidate = (base / rel_path).resolve()
    if base not in candidate.parents and candidate != base:
        raise HTTPException(status_code=400, detail="Invalid path.")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Not found.")
    return candidate


@app.get("/api/reports")
async def list_reports():
    out = []
    if cfg.REPORTS_DIR.exists():
        for f in sorted(cfg.REPORTS_DIR.rglob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
            out.append({"path": str(f.relative_to(cfg.REPORTS_DIR)), "mtime": f.stat().st_mtime})
    return out


@app.get("/api/reports/{rel_path:path}", response_class=PlainTextResponse)
async def get_report(rel_path: str):
    path = _safe_report_path(rel_path)
    return path.read_text(encoding="utf-8")


@app.post("/api/run")
async def start_run(req: RunRequest):
    try:
        if req.mode == "owasp-scan":
            objective = _build_owasp_objective(req.target or "", req.category)
        elif req.mode == "specialized-scan":
            objective = _build_specialized_objective(req.target or "", req.category or "")
        else:
            objective = req.objective or ""
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not objective.strip():
        raise HTTPException(status_code=400, detail="An objective (or target+category) is required.")

    job = _start_job("run", _run_agent_job, objective, req.non_interactive)
    return {"job_id": job.id}


@app.post("/api/learn")
async def start_learn(req: LearnRequest):
    job = _start_job("learn", _run_learn_job, req.source, req.type, req.label)
    return {"job_id": job.id}


@app.post("/api/consolidate")
async def start_consolidate():
    job = _start_job("consolidate", _run_consolidate_job)
    return {"job_id": job.id}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job.")
    return {"id": job.id, "kind": job.kind, "status": job.status, "summary": job.summary, "extra": job.extra}


@app.get("/api/approvals")
async def list_pending_approvals():
    with PENDING_LOCK:
        return [
            {"request_id": p.id, "job_id": p.job_id, "category": p.category, "description": p.description}
            for p in PENDING_APPROVALS.values()
        ]


@app.post("/api/approve/{request_id}")
async def approve(request_id: str, req: ApproveRequest):
    with PENDING_LOCK:
        pending = PENDING_APPROVALS.get(request_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Unknown or already-resolved approval request.")
    pending.decision = req.approved
    pending.event.set()
    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # clients don't send anything meaningful; just keep the socket open
    except WebSocketDisconnect:
        await manager.disconnect(ws)


def run_server(host: str = "127.0.0.1", port: int = 8420) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
