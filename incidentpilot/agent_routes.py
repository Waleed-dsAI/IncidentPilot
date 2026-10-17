"""Admin-only agent execution and evidence/report persistence."""
import json
from fastapi import APIRouter, Header, HTTPException
from .core import app, db, audit, now, require_admin
from .agents import run_team
from .llm import LLMUnavailable
from .mcp_protocol import MCPError

router=APIRouter(prefix='/api/agent',tags=['AI investigation'])

def ensure_table():
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS agent_reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          report TEXT,
          error TEXT,
          created_at TEXT NOT NULL
        )''')

ensure_table()

@router.post('/investigate/{incident_id}')
async def investigate(incident_id:int, x_admin_token:str|None=Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        row=con.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row:
            raise HTTPException(404,'Incident not found')
        incident=dict(row)
        target=con.execute('SELECT repo,run_id,run_url,workflow_name,observed_status FROM containment WHERE incident_id=?',
                           (incident_id,)).fetchone()
        if target:
            incident['github_target']=dict(target)
    try:
        report=await run_team(incident)
    except (LLMUnavailable,MCPError) as exc:
        with db() as con:
            con.execute('INSERT INTO agent_reports (incident_id,status,error,created_at) VALUES (?,?,?,?)',
                        (incident_id,'ERROR',str(exc)[:300],now()))
            audit(con,incident_id,'agent orchestrator','AGENT_FAILED',str(exc)[:300])
        raise HTTPException(503,str(exc)[:250])
    with db() as con:
        con.execute('INSERT INTO agent_reports (incident_id,status,report,created_at) VALUES (?,?,?,?)',
                    (incident_id,'COMPLETED',json.dumps(report),now()))
        audit(con,incident_id,'three-agent orchestrator','AGENT_RECOMMENDATION_SAVED',
              f"Risk: {report['analysis'].get('risk','UNKNOWN')}; no security action executed")
    return report

@router.get('/reports/{incident_id}')
def reports(incident_id:int,x_admin_token:str|None=Header(default=None)):
    require_admin(x_admin_token)
    with db() as con:
        result=con.execute('SELECT * FROM agent_reports WHERE incident_id=? ORDER BY id DESC LIMIT 20',(incident_id,)).fetchall()
    return [{**dict(r),'report':json.loads(r['report']) if r['report'] else None} for r in result]

app.include_router(router)
