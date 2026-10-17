"""GitHub Actions containment endpoints from v2."""
import asyncio
import re
import httpx
from fastapi import HTTPException, Header
from pydantic import BaseModel, Field
from .core import app, require_admin, db, now, create_incident, audit, GITHUB_TOKEN, GITHUB_REPO
from . import github_app

# ---- GitHub Actions containment integration ---------------------------------
# Security boundaries: only one configured repository; only manually approved
# actions; no arbitrary GitHub API URL inputs; no token ever returned to users.

class RunInvestigation(BaseModel):
    run_id: int = Field(gt=0)

class ContainmentReview(BaseModel):
    decision: str
    note: str = Field(min_length=5, max_length=1200)
    confirm_repo: str
    confirm_run_id: int
    reviewer: str = Field(default="IT Administrator", max_length=120)


async def github_credentials(expected_repo=None):
    # User-managed GitHub App takes precedence. Never fall back to a developer
    # token once a GitHub App is connected, even if repository is not selected.
    if github_app.connection():
        return await github_app.credentials_for(expected_repo)
    # Legacy single-repo lab support; not a customer connection interface.
    if not GITHUB_TOKEN or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", GITHUB_REPO):
        raise HTTPException(503, "Connect GitHub under Settings → Integrations")
    if expected_repo is not None and expected_repo.lower() != GITHUB_REPO.lower():
        raise HTTPException(409, "Incident targets a different repository")
    return GITHUB_REPO, GITHUB_TOKEN


def github_headers(token=None):
    token = token or GITHUB_TOKEN
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


async def github_run(run_id: int, expected_repo=None):
    repo, token = await github_credentials(expected_repo)
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(url, headers=github_headers(token))
        if response.status_code != 200:
            raise HTTPException(502, f"GitHub could not retrieve run (HTTP {response.status_code})")
        data = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"GitHub connection failure: {type(exc).__name__}")
    # Require GitHub itself to confirm the run belongs to our allowlisted repo.
    if data.get("repository", {}).get("full_name", "").lower() != repo.lower():
        raise HTTPException(409, "Run does not belong to the configured repository")
    return {"run_id": data["id"], "name": data.get("name", "Unnamed workflow"),
            "status": data.get("status", "unknown"), "conclusion": data.get("conclusion"),
            "url": data.get("html_url", ""), "event": data.get("event", "unknown"),
            "branch": data.get("head_branch", "unknown"), "repo": repo}


@app.get("/api/github/runs")
async def list_github_runs(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    repo, token = await github_credentials()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"https://api.github.com/repos/{repo}/actions/runs",
                                 params={"per_page": 15}, headers=github_headers(token))
        if r.status_code != 200:
            raise HTTPException(502, f"GitHub run list HTTP {r.status_code}")
        return [{"id": x.get("id"), "name": x.get("name"), "status": x.get("status"),
                 "conclusion": x.get("conclusion"), "url": x.get("html_url")}
                for x in r.json().get("workflow_runs", [])]
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"GitHub connection failure: {type(exc).__name__}")


@app.post("/api/github/investigate", status_code=201)
async def investigate_run(payload: RunInvestigation, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    run = await github_run(payload.run_id)
    # We do not claim a run is malicious merely because it is active.
    description = (f"Run #{run['run_id']} ({run['name']}); event={run['event']}; "
                   f"branch={run['branch']}; observed status={run['status']}; "
                   f"conclusion={run['conclusion']}; source={run['url']}.")
    ident = create_incident(f"Review GitHub workflow run {run['run_id']}",
                            description, "github_workflow", "github admin investigation")
    with db() as con:
        con.execute("""INSERT INTO containment
            (incident_id,repo,run_id,run_url,workflow_name,observed_status,
             observed_conclusion,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (ident,run['repo'],run['run_id'],run['url'],run['name'],run['status'],
             run['conclusion'],now(),now()))
        con.execute("""UPDATE incidents SET priority=?,rationale=?,recommendation=? WHERE id=?""",
            ("NEEDS_TRIAGE", "Active workflows are not inherently malicious. Review event, code and context.",
             "If independently justified, administrator may approve cancelling this exact run.",ident))
        audit(con, ident, "GitHub API", "EVIDENCE_COLLECTED", description)
    return {"id": ident, "status": "PENDING_REVIEW", "github_evidence":run}


@app.get("/api/github/containments")
def containment_queue(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        return [dict(x) for x in con.execute("""SELECT c.*,i.title,i.priority,i.status AS incident_status
            FROM containment c JOIN incidents i ON i.id=c.incident_id ORDER BY c.id DESC LIMIT 100""")]


@app.post("/api/github/containments/{incident_id}/review")
async def approve_containment(incident_id: int, payload: ContainmentReview,
                              x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    if payload.decision not in {"approve", "reject"}:
        raise HTTPException(422, "decision must be approve or reject")
    with db() as con:
        data = con.execute("""SELECT c.*,i.status AS incident_status
            FROM containment c JOIN incidents i ON c.incident_id=i.id
            WHERE c.incident_id=?""", (incident_id,)).fetchone()
        if not data:
            raise HTTPException(404,"Containment request not found")
        data=dict(data)
        if data["incident_status"] != "PENDING_REVIEW":
            raise HTTPException(409,"Already reviewed; duplicate execution blocked")
        if payload.confirm_repo != data["repo"] or payload.confirm_run_id != data["run_id"]:
            raise HTTPException(409,"Exact repository/run confirmation does not match")
        new_status = "EXECUTING" if payload.decision == "approve" else "REJECTED"
        # Atomically claim execution; prevents two approvals from executing twice.
        cursor=con.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=? AND status='PENDING_REVIEW'",
                           (new_status,now(),incident_id))
        if cursor.rowcount != 1:
            raise HTTPException(409,"Already reviewed")
        con.execute("UPDATE containment SET action_status=?,updated_at=? WHERE incident_id=?",
                    (new_status,now(),incident_id))
        audit(con,incident_id,payload.reviewer,"CONTAINMENT_"+payload.decision.upper(),
              f"{payload.note} | exact target {data['repo']} run {data['run_id']}")
    if payload.decision == "reject":
        return {"status":"REJECTED", "execution":"NOT_RUN"}

    # Re-fetch evidence at action time, rather than trusting cached status.
    try:
        live=await github_run(data["run_id"], expected_repo=data["repo"])
        if live["status"] not in {"queued","in_progress","waiting","pending","requested"}:
            result="NOT_NEEDED"
            detail=f"Run no longer active: {live['status']} / {live['conclusion']}; no cancellation attempted"
        else:
            async with httpx.AsyncClient(timeout=15) as client:
                response=await client.post(
                    f"https://api.github.com/repos/{data['repo']}/actions/runs/{data['run_id']}/cancel",
                    headers=github_headers((await github_credentials(data["repo"]))[1]))
            if response.status_code == 202:
                # Cancellation is asynchronous; do not claim completion based on 202 alone.
                result="CANCELLATION_REQUESTED"
                detail="GitHub accepted cancellation request; verify final status shortly"
                for _ in range(3):
                    await asyncio.sleep(1.0)
                    latest=await github_run(data["run_id"])
                    if latest["status"] == "completed" and latest["conclusion"] == "cancelled":
                        result="VERIFIED_CANCELLED"
                        detail=f"GitHub reports completed / cancelled: {latest['url']}"
                        break
            else:
                result="FAILED"
                detail=f"GitHub cancellation returned HTTP {response.status_code}; no success claimed"
    except (HTTPException,httpx.HTTPError) as exc:
        result="FAILED"
        detail=f"Could not execute/verify cancellation: {str(exc)[:300]}"
    with db() as con:
        con.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?",(result,now(),incident_id))
        con.execute("UPDATE containment SET action_status=?,result_detail=?,updated_at=? WHERE incident_id=?",
                    (result,detail,now(),incident_id))
        audit(con,incident_id,"GitHub action executor",result,detail)
    return {"status":result,"execution":result,"details":detail,"run_url":data["run_url"]}


@app.post("/api/github/containments/{incident_id}/verify")
async def verify_containment(incident_id: int, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        row=con.execute("SELECT * FROM containment WHERE incident_id=?",(incident_id,)).fetchone()
        if not row:
            raise HTTPException(404,"Containment request not found")
        row=dict(row)
        if row["action_status"] not in {"CANCELLATION_REQUESTED","VERIFIED_CANCELLED"}:
            raise HTTPException(409,"Only requested cancellations can be verified")
    live=await github_run(row["run_id"], expected_repo=row["repo"])
    result="VERIFIED_CANCELLED" if live["status"]=="completed" and live["conclusion"]=="cancelled" else "CANCELLATION_REQUESTED"
    detail=f"GitHub current state: {live['status']} / {live['conclusion']}"
    with db() as con:
        con.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?",(result,now(),incident_id))
        con.execute("UPDATE containment SET action_status=?,result_detail=?,updated_at=? WHERE incident_id=?",(result,detail,now(),incident_id))
        audit(con,incident_id,"GitHub API","CONTAINMENT_VERIFIED" if result=="VERIFIED_CANCELLED" else "STATUS_CHECKED",detail)
    return {"status":result,"details":detail,"github_evidence":live}
