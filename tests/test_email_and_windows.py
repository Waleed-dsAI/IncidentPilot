import os
import json
from pathlib import Path
import pytest
import httpx
from cryptography.fernet import Fernet

# Standalone tests share main suite config via pytest session; env must be set before import.
os.environ.setdefault('ADMIN_TOKEN','test-admin-secret')
os.environ.setdefault('WEBHOOK_TOKEN','test-webhook-secret')
os.environ.setdefault('DB_PATH',str(Path(__file__).parent/'test-incidentpilot.db'))
os.environ['TOKEN_ENCRYPTION_KEY']=Fernet.generate_key().decode()
os.environ['GOOGLE_CLIENT_ID']='demo-client.apps.googleusercontent.com'
os.environ['GOOGLE_CLIENT_SECRET']='demo-secret'
os.environ['GOOGLE_REDIRECT_URI']='http://localhost:8000/api/gmail/callback'
from app import app
from incidentpilot import gmail_routes, gmail_service
from incidentpilot.email_agents import run_email_team
from incidentpilot.mcp_protocol import LocalMCPClient,MCPError
from incidentpilot.core import db

ADMIN={'x-admin-token':'test-admin-secret'}

@pytest.mark.asyncio
async def test_google_oauth_state_not_reusable(monkeypatch):
    start=gmail_service.auth_url()
    from urllib.parse import urlparse,parse_qs
    state=parse_qs(urlparse(start).query)['state'][0]
    assert parse_qs(urlparse(start).query)['scope']==[gmail_service.SCOPE]
    async def mock_exchange_payload(request):
        if request.url.path.endswith('/token'):
            return httpx.Response(200,json={'access_token':'access','refresh_token':'refresh','scope':gmail_service.SCOPE})
        return httpx.Response(200,json={'emailAddress':'tester@example.com'})
    transport=httpx.MockTransport(mock_exchange_payload)
    address=await gmail_service.exchange('dummy',state,transport=transport)
    assert address=='tester@example.com'
    with pytest.raises(Exception):
        await gmail_service.exchange('dummy',state,transport=transport)
    with db() as conn:
        rec=conn.execute('SELECT refresh_token FROM gmail_accounts WHERE account_id=?',(address,)).fetchone()
    assert rec and 'refresh' not in rec['refresh_token']

@pytest.mark.asyncio
async def test_gmail_action_requires_human_exact_target_and_only_one_execution(monkeypatch):
    actual={'trash':0}
    message={'id':'testmsgabc123','threadId':'threadabc','snippet':'Please login at https://example.invalid',
             'payload':{'headers':[{'name':'From','value':'IT Alerts <test@example.com>'},
                                  {'name':'Subject','value':'Suspicious login'}]},'labelIds':['INBOX']}
    async def fake_gmail(account,method,path,**kwargs):
        assert account=='tester@example.com'
        if method=='GET' and path.endswith('/messages/testmsgabc123'):
            if kwargs.get('params',{}).get('format')=='minimal':
                return {'id':'testmsgabc123','labelIds':['TRASH'] if actual['trash'] else ['INBOX']}
            return dict(message)
        if method=='POST' and path.endswith('/messages/testmsgabc123/trash'):
            actual['trash']+=1
            return {'id':'testmsgabc123','labelIds':['TRASH']}
        raise AssertionError(f'Unexpected Gmail request {method} {path}')
    monkeypatch.setattr(gmail_routes,'gmail_request',fake_gmail)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        assert (await client.post('/api/gmail/cases',json={'account_id':'tester@example.com','message_id':'testmsgabc123'})).status_code==401
        added=await client.post('/api/gmail/cases',json={'account_id':'tester@example.com','message_id':'testmsgabc123'},headers=ADMIN)
        assert added.status_code==201,added.text
        case_id=added.json()['incident_id']
        assert (await client.post('/api/gmail/cases',json={'account_id':'tester@example.com','message_id':'testmsgabc123'},headers=ADMIN)).status_code==409
        # Without a completed investigation, approval is blocked.
        premature=await client.post(f'/api/gmail/cases/{case_id}/review',headers=ADMIN,
                json={'decision':'approve','confirm_message_id':'testmsgabc123','note':'Before analysis'})
        assert premature.status_code==409
        with db() as conn:
            conn.execute('INSERT INTO email_agent_reports (incident_id,report_json,at) VALUES (?,?,?)',
                         (case_id, json.dumps({'model':'mocked test','human_review_required':True}), '2026-10-17T00:00:00Z'))
        bad=await client.post(f'/api/gmail/cases/{case_id}/review',headers=ADMIN,
               json={'decision':'approve','confirm_message_id':'differentmsg','note':'Confirmed simulated phishing'})
        assert bad.status_code==409 and actual['trash']==0
        ok=await client.post(f'/api/gmail/cases/{case_id}/review',headers=ADMIN,
                json={'decision':'approve','confirm_message_id':'testmsgabc123','note':'This is a dedicated test email'})
        assert ok.status_code==200 and ok.json()['status']=='VERIFIED_TRASHED' and actual['trash']==1
        repeat=await client.post(f'/api/gmail/cases/{case_id}/review',headers=ADMIN,
                json={'decision':'approve','confirm_message_id':'testmsgabc123','note':'Retry test email'})
        assert repeat.status_code==409 and actual['trash']==1
    return case_id

@pytest.mark.asyncio
async def test_mcp_scoping_prevents_other_email_tools():
    with db() as conn:
        case=conn.execute('SELECT incident_id FROM email_cases WHERE message_id=?',('testmsgabc123',)).fetchone()
    if not case: pytest.skip('Email case creation test must run first')
    async with LocalMCPClient(email_case_id=case['incident_id']) as mcp:
        names={t['name'] for t in await mcp.list_tools()}
        assert names=={'get_email_case'}
        rec=await mcp.call_tool('get_email_case',{})
        assert rec['message_id']=='testmsgabc123'
        with pytest.raises(MCPError):
            await mcp.call_tool('get_workflow_run',{'run_id':3})
        with pytest.raises(MCPError):
            await mcp.call_tool('get_email_case',{'message_id':'another'})

class EmailFakeLLM:
    def __init__(self):self.n=0
    async def complete(self,messages,tools=None):
        self.n+=1
        if self.n==1:return {'content':json.dumps({'indicators':['Urgency'],'counterindicators':[],'missing_evidence':['Headers'],'summary':'Uncertain'})}
        if self.n==2:return {'content':json.dumps({'risk':'UNKNOWN','rationale':'Insufficient evidence','uncertainties':['Limited preview']})}
        if self.n==3:return {'content':json.dumps({'recommended_action':'MORE_RESEARCH','reason':'Insufficient evidence','verification_steps':['Ask sender']})}
        raise AssertionError('Agent role count exceeded')

@pytest.mark.asyncio
async def test_three_email_agents_mcp_and_no_autonomous_action():
    with db() as conn:
        case=conn.execute('SELECT incident_id FROM email_cases WHERE message_id=?',('testmsgabc123',)).fetchone()
    if not case: pytest.skip('Email case creation test must run first')
    fake=EmailFakeLLM()
    report=await run_email_team(case['incident_id'],llm=fake)
    assert fake.n==3
    assert report['planner']['human_review_required'] is True
    assert report['execution']=='NONE_RECOMMENDATION_ONLY'
    assert report['mcp_tools_used']==['get_email_case']

@pytest.mark.asyncio
async def test_windows_collector_ingestion_is_read_only():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        payload={'host_alias':'testing-laptop','defender_enabled':True,'realtime_enabled':False,'detections':[]}
        assert (await client.post('/api/windows/signals',json=payload)).status_code==401
        r=await client.post('/api/windows/signals',json=payload,headers=ADMIN)
        assert r.status_code==201 and r.json()['security_action']=='NONE'
