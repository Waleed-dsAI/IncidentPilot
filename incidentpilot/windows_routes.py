"""Bounded Windows Defender signal ingest: explicitly submitted, never executes host commands."""
from fastapi import Header,HTTPException
from pydantic import BaseModel,Field
from .core import app,require_admin,create_incident,db,audit

class WindowsSignal(BaseModel):
    host_alias: str=Field(min_length=2,max_length=80)
    defender_enabled: bool | None=None
    realtime_enabled: bool | None=None
    detections: list[str]=Field(default_factory=list,max_length=10)
    status: str=Field(default='reported',max_length=40)

@app.post('/api/windows/signals',status_code=201)
def windows_signal(payload:WindowsSignal,x_admin_token:str|None=Header(default=None)):
    require_admin(x_admin_token)
    # Treat host-supplied claims as unverified telemetry, not proof of malware.
    desc=(f'Local collector host alias: {payload.host_alias}; Defender reported enabled: {payload.defender_enabled}; '
          f'realtime protection: {payload.realtime_enabled}; local detections (unverified): '
          +'; '.join(d[:180] for d in payload.detections))
    ident=create_incident('Windows security signals from '+payload.host_alias,desc,'malware','read-only Windows collector')
    with db() as conn:
        audit(conn,ident,'Windows collector','UNVERIFIED_TELEMETRY','No local containment was performed')
    return {'incident_id':ident,'security_action':'NONE','status':'PENDING_REVIEW'}
