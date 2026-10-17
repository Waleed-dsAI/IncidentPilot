"""Gmail demo connector: explicit opt-in, exact-message consent, auditable Trash action."""
import json
import secrets
import httpx
from fastapi import Header, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from .core import app, db, now, audit, create_incident, require_admin
from .gmail_service import auth_url, exchange, gmail_request, safe_message

class GmailCaseRequest(BaseModel):
    account_id: str = Field(max_length=320)
    message_id: str = Field(min_length=3,max_length=150,pattern=r'^[a-zA-Z0-9_-]+$')

class GmailDecision(BaseModel):
    decision: str
    confirm_message_id: str
    note: str = Field(min_length=8,max_length=1500)

@app.get('/api/gmail/connect')
def connect(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return {'url':auth_url()}

@app.get('/api/gmail/callback')
async def callback(code: str = '',state: str = '',error: str = ''):
    if error: raise HTTPException(400,'Google OAuth consent was declined')
    try:
        account=await exchange(code,state)
    except httpx.HTTPError as exc:
        raise HTTPException(502,'Google network error') from exc
    # Don't leak tokens or grant session permissions by clicking the callback.
    return HTMLResponse('<html><body><h2>Gmail connected</h2><p>Return to the IncidentPilot dashboard and refresh the account list.</p></body></html>')

@app.get('/api/gmail/accounts')
def accounts(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as conn:
        return [{'account_id':r['account_id'],'connected_at':r['connected_at']} for r in
                conn.execute('SELECT account_id,connected_at FROM gmail_accounts ORDER BY connected_at DESC')]

@app.get('/api/gmail/messages')
async def messages(account_id: str = Query(max_length=320), x_admin_token: str | None=Header(default=None)):
    require_admin(x_admin_token)
    data=await gmail_request(account_id,'GET','/messages',params={'maxResults':12,'labelIds':'INBOX'})
    out=[]
    for row in data.get('messages',[])[:12]:
        try:
            detail=await gmail_request(account_id,'GET','/messages/'+row['id'],params={'format':'metadata','metadataHeaders':['From','Subject']})
            out.append(safe_message(detail))
        except HTTPException:
            continue
    return out

@app.post('/api/gmail/cases',status_code=201)
async def create_case(payload:GmailCaseRequest, x_admin_token: str | None=Header(default=None)):
    require_admin(x_admin_token)
    detail=await gmail_request(payload.account_id,'GET','/messages/'+payload.message_id,
                               params={'format':'metadata','metadataHeaders':['From','Subject']})
    m=safe_message(detail)
    if m['message_id']!=payload.message_id:
        raise HTTPException(502,'Gmail returned the wrong message')
    if 'TRASH' in m['labels']:
        raise HTTPException(409,'Message is already in Trash')
    with db() as conn:
        exists=conn.execute('SELECT id FROM email_cases WHERE account_id=? AND message_id=?',
                        (payload.account_id,payload.message_id)).fetchone()
    if exists: raise HTTPException(409,'This message already has a case')
    ident=create_incident('Review suspicious email: '+m['subject'][:130],
        'Sender: '+m['sender']+'\nSubject: '+m['subject']+'\nSnippet (untrusted): '+m['snippet'],
        'phishing','connected Gmail')
    with db() as conn:
        conn.execute('''INSERT INTO email_cases
           (incident_id,account_id,message_id,thread_id,sender,subject,snippet,links_json,observed_labels,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
           (ident,payload.account_id,m['message_id'],m['thread_id'],m['sender'],m['subject'],
            m['snippet'],json.dumps(m['links']),json.dumps(m['labels']),now()))
        audit(conn,ident,'gmail connector','EVIDENCE_COLLECTED',
             'Read-only email metadata captured; not a verified phishing verdict')
    return {'incident_id':ident,'status':'PENDING_REVIEW','preview':m}

@app.get('/api/gmail/cases')
def cases(x_admin_token: str | None=Header(default=None)):
    require_admin(x_admin_token)
    with db() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM email_cases ORDER BY id DESC LIMIT 100')]

@app.post('/api/gmail/cases/{ident}/review')
async def review_case(ident:int,payload:GmailDecision,x_admin_token: str | None=Header(default=None)):
    require_admin(x_admin_token)
    if payload.decision not in ('approve','reject'):
        raise HTTPException(422,'decision must be approve or reject')
    if payload.decision=='approve':
        with db() as conn:
            analyzed=conn.execute('SELECT 1 FROM email_agent_reports WHERE incident_id=? LIMIT 1',(ident,)).fetchone()
        if not analyzed: raise HTTPException(409,'Run AI investigation and review the report before approving action')
    with db() as conn:
        row=conn.execute('SELECT * FROM email_cases WHERE incident_id=?',(ident,)).fetchone()
        if not row: raise HTTPException(404,'Email case not found')
        case=dict(row)
        if case['message_id'] != payload.confirm_message_id:
            raise HTTPException(409,'Exact Gmail message ID confirmation is required')
        new_status='EXECUTING' if payload.decision=='approve' else 'REJECTED'
        changed=conn.execute('''UPDATE email_cases SET action_status=?
              WHERE incident_id=? AND action_status='PENDING_REVIEW' ''',(new_status,ident))
        if changed.rowcount!=1: raise HTTPException(409,'Already decided or in progress')
        audit(conn,ident,'human administrator','GMAIL_'+payload.decision.upper(),
              'Exact message '+case['message_id']+'; rationale: '+payload.note)
    if payload.decision=='reject':
        with db() as conn:
            conn.execute('UPDATE incidents SET status=?,updated_at=? WHERE id=?',('REJECTED',now(),ident))
        return {'status':'REJECTED','execution':'NOT_RUN'}
    try:
        detail=await gmail_request(case['account_id'],'GET','/messages/'+case['message_id'],
                  params={'format':'metadata','metadataHeaders':['From','Subject']})
        current=safe_message(detail)
        if (current['message_id']!=case['message_id'] or current['sender']!=case['sender'] or
            current['subject']!=case['subject']):
            raise ValueError('Message identity or metadata changed after review')
        if 'TRASH' in current['labels']:
            raise ValueError('Already in Trash; not modified by IncidentPilot')
        await gmail_request(case['account_id'],'POST','/messages/'+case['message_id']+'/trash')
        verify=await gmail_request(case['account_id'],'GET','/messages/'+case['message_id'],
                                   params={'format':'minimal'})
        verified='TRASH' in verify.get('labelIds',[])
        status='VERIFIED_TRASHED' if verified else 'NEEDS_VERIFICATION'
        message='Message moved to Trash and independently verified' if verified else 'Trash call accepted; Gmail label not verified'
    except (HTTPException, httpx.HTTPError,ValueError) as exc:
        status='FAILED'
        message='Gmail operation failed or message changed. Inspect case and service logs.'
    with db() as conn:
        conn.execute('UPDATE email_cases SET action_status=?,action_detail=? WHERE incident_id=?',(status,message,ident))
        conn.execute('UPDATE incidents SET status=?,updated_at=? WHERE id=?',(status,now(),ident))
        audit(conn,ident,'gmail executor',status,message)
    return {'status':status,'detail':message}
