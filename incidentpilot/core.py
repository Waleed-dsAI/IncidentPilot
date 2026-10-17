"""IncidentPilot hackathon MVP: safe incident triage and approval-gated ticketing.

No model-based incident verdicts are invented: rules are labeled preliminary.
Actions never revoke sessions, rotate credentials, or alter security settings.
"""
import json
import asyncio
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.getenv("DB_PATH", str(ROOT / "incidentpilot.db"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
app = FastAPI(title="IncidentPilot", version="0.2.0")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, description TEXT NOT NULL,
          kind TEXT NOT NULL, source TEXT NOT NULL,
          priority TEXT NOT NULL, rationale TEXT NOT NULL,
          recommendation TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS containment (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL UNIQUE,
          repo TEXT NOT NULL, run_id INTEGER NOT NULL,
          run_url TEXT NOT NULL, workflow_name TEXT NOT NULL,
          observed_status TEXT NOT NULL, observed_conclusion TEXT,
          action_status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
          result_detail TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL, at TEXT NOT NULL,
          actor TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL
        );
        """)


init_db()


class NewIncident(BaseModel):
    title: str = Field(min_length=5, max_length=160)
    description: str = Field(min_length=12, max_length=4000)
    kind: str = Field(default="other", max_length=60)


class Review(BaseModel):
    decision: str
    note: str = Field(min_length=3, max_length=1200)
    reviewer: str = Field(default="IT Administrator", max_length=120)


def require_admin(token):
    if not ADMIN_TOKEN:
        raise HTTPException(503, "ADMIN_TOKEN is not configured")
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(401, "Invalid administrator token")


def triage(title: str, description: str, kind: str):
    text = f"{title} {description}".lower()
    kind = kind.lower().strip()
    if any(word in text for word in ["password entered", "entered my password", "credentials exposed", "secret scanning", "leaked token", "api key leaked", "token exposed"]):
        return "HIGH", "Possible credential exposure. Urgent human verification is required.", "Investigate affected accounts or keys; prepare containment plan for administrator approval."
    if kind == "phishing" or any(word in text for word in ["suspicious email", "phishing", "fake login"]):
        return "MEDIUM", "Potential phishing; no compromise is established from the report alone.", "Review message metadata and links safely; recommend reporting and human-approved follow-up."
    if kind in {"lost_device", "malware", "suspicious_login"}:
        return "MEDIUM", "Security impact depends on missing device or account evidence.", "Collect missing evidence and request administrator review."
    return "NEEDS_TRIAGE", "Insufficient verified evidence to determine impact.", "Ask for additional details and assign a reviewer."


def audit(con, incident_id, actor, event, details):
    con.execute("INSERT INTO audit (incident_id,at,actor,event,details) VALUES (?,?,?,?,?)",
                (incident_id, now(), actor, event, details))


def create_incident(title, description, kind, source):
    priority, rationale, recommendation = triage(title, description, kind)
    stamp = now()
    with db() as con:
        cur = con.execute("""INSERT INTO incidents
            (title,description,kind,source,priority,rationale,recommendation,status,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (title, description, kind, source, priority, rationale, recommendation, "PENDING_REVIEW", stamp, stamp))
        ident = cur.lastrowid
        audit(con, ident, source, "REPORTED", f"New {kind} report received")
        audit(con, ident, "triage engine", "TRIAGED", f"Preliminary priority: {priority}; {rationale}")
    return ident


@app.get("/")
def root():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/health")
def health():
    return {"ok": True, "service": "IncidentPilot", "time": now()}


@app.post("/api/incidents", status_code=201)
def submit(payload: NewIncident):
    ident = create_incident(payload.title, payload.description, payload.kind, "employee")
    return {"id": ident, "status": "PENDING_REVIEW"}


@app.post("/api/alerts", status_code=201)
async def ingest_alert(request: Request, x_webhook_token: str | None = Header(default=None)):
    if not WEBHOOK_TOKEN:
        raise HTTPException(503, "WEBHOOK_TOKEN is not configured")
    if not x_webhook_token or not secrets.compare_digest(x_webhook_token, WEBHOOK_TOKEN):
        raise HTTPException(401, "Invalid webhook token")
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Expected JSON")
    if not isinstance(data, dict):
        raise HTTPException(422, "Expected JSON object")
    title = str(data.get("title") or "External security alert")[:160]
    description = str(data.get("description") or json.dumps(data)[:3000])[:4000]
    kind = str(data.get("kind") or "other")[:60]
    if len(title) < 5 or len(description) < 12:
        raise HTTPException(422, "Alert must have meaningful title and description")
    ident = create_incident(title, description, kind, "authenticated webhook")
    return {"id": ident, "status": "PENDING_REVIEW"}


@app.get("/api/incidents")
def list_incidents(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 200").fetchall()]


@app.get("/api/incidents/{ident}/audit")
def audit_log(ident: int, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM audit WHERE incident_id=? ORDER BY id", (ident,)).fetchall()]


async def create_github_issue(incident):
    """Create an issue only in the explicitly configured authorized repository."""
    from . import github_app
    if github_app.connection():
        return 'NO_CONNECTOR', 'GitHub App is connected for Actions only; creating issues requires a separate Issues:write permission and is not enabled.'
    if not GITHUB_TOKEN or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", GITHUB_REPO):
        return "NO_CONNECTOR", "GitHub integration not configured; approval recorded, issue creation pending."
    body = (f"Incident #{incident['id']} — {incident['kind']}\n\n"
            f"**Description:** {incident['description']}\n\n"
            f"**Preliminary priority:** {incident['priority']}\n"
            f"**Human-approved follow-up:** {incident['recommendation']}\n\n"
            "This issue is a follow-up ticket, NOT evidence of containment.")
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/issues",
                headers={"Authorization": f"Bearer {GITHUB_TOKEN}",
                         "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28"},
                json={"title": f"[IncidentPilot #{incident['id']}] {incident['title']}", "body": body},
            )
        if resp.status_code == 201:
            return "DONE", str(resp.json().get("html_url", "Issue created"))
        return "FAILED", f"GitHub issue API returned HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        return "FAILED", f"GitHub request failed: {type(exc).__name__}"


@app.post("/api/incidents/{ident}/review")
async def review_incident(ident: int, payload: Review, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    if payload.decision not in {"approve", "reject", "investigate"}:
        raise HTTPException(422, "decision must be approve, reject, or investigate")
    with db() as con:
        row = con.execute("SELECT * FROM incidents WHERE id=?", (ident,)).fetchone()
        if not row:
            raise HTTPException(404, "Incident not found")
        if row["status"] != "PENDING_REVIEW":
            raise HTTPException(409, "Incident has already been reviewed")
        if con.execute("SELECT 1 FROM containment WHERE incident_id=?", (ident,)).fetchone():
            raise HTTPException(409, "GitHub containment requires exact-target review in the containment queue")
        new_status = {"approve": "APPROVED", "reject": "REJECTED", "investigate": "MORE_RESEARCH"}[payload.decision]
        con.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=? AND status='PENDING_REVIEW'", (new_status,now(),ident))
        audit(con, ident, payload.reviewer, f"REVIEW_{payload.decision.upper()}", payload.note)
        incident = dict(row)
    if payload.decision != "approve":
        return {"status": new_status, "execution": "NOT_RUN"}
    result, detail = await create_github_issue(incident)
    with db() as con:
        con.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?", ("TICKET_CREATED" if result == "DONE" else "APPROVED_PENDING_ACTION" if result == "NO_CONNECTOR" else "ACTION_FAILED",now(),ident))
        audit(con, ident, "action executor", f"GITHUB_TICKET_{result}", detail)
    return {"status": "TICKET_CREATED" if result == "DONE" else "APPROVED_PENDING_ACTION" if result == "NO_CONNECTOR" else "ACTION_FAILED", "execution": result, "details": detail}


