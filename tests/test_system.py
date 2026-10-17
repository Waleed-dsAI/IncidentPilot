import importlib
import json
import os
import sys
from pathlib import Path
import pytest
import httpx

os.environ['ADMIN_TOKEN']='test-admin-secret'
os.environ['WEBHOOK_TOKEN']='test-webhook-secret'
os.environ.setdefault('DB_PATH',str(Path(__file__).parent/'test-incidentpilot.db'))
for module in list(sys.modules):
    if module=='app' or module.startswith('incidentpilot'):
        del sys.modules[module]
from app import app
from incidentpilot.mcp_protocol import LocalMCPClient, MCPError
from incidentpilot.agents import run_team
from incidentpilot.llm import LLMUnavailable, GroqLLM
from incidentpilot.mcp_server import fetch, TOOLS
from incidentpilot import github_routes

@pytest.mark.asyncio
async def test_mcp_handshake_and_read_only_tools():
    async with LocalMCPClient() as mcp:
        names={t['name'] for t in await mcp.list_tools()}
        assert names=={'get_workflow_run','get_workflow_jobs'}
        with pytest.raises(MCPError):
            await mcp.call_tool('cancel_run',{'run_id':1})

@pytest.mark.asyncio
async def test_mcp_missing_token_fails_closed():
    async with LocalMCPClient() as mcp:
        with pytest.raises(MCPError):
            await mcp.call_tool('get_workflow_run',{'run_id':123})

class FakeLLM:
    def __init__(self):
        self.index=0
    async def complete(self,messages,tools=None):
        self.index+=1
        if self.index==1:
            assert tools and tools[0]['name']=='get_workflow_run'
            return {'role':'assistant','content':None,'tool_calls':[{'id':'call_a','type':'function','function':{'name':'get_workflow_run','arguments':'{"run_id": 25}'}}]}
        if self.index==2:
            assert messages[-1]['role']=='tool'
            return {'role':'assistant','content':json.dumps({'facts':['Run could not be validated with current credentials'], 'gaps':['GitHub verification unavailable'],'summary':'Insufficient evidence'})}
        if self.index==3:
            return {'role':'assistant','content':json.dumps({'risk':'UNKNOWN','rationale':'No verified indication of compromise','uncertainties':['Missing logs']})}
        if self.index==4:
            return {'role':'assistant','content':json.dumps({'recommended_action':'Investigate and review before cancellation','justification':'Evidence missing','human_review_required':False,'verification_steps':['Check logs']})}
        raise AssertionError('Unexpected LLM call')

@pytest.mark.asyncio
async def test_three_agents_use_mcp_and_cannot_approve():
    report=await run_team({'title':'Possible suspicious run','github_target':{'run_id':25}},llm=FakeLLM())
    assert len(report['mcp_calls'])==1
    assert report['mcp_calls'][0]['tool']=='get_workflow_run'
    assert report['plan']['human_review_required'] is True
    assert report['status']=='RECOMMENDATION_ONLY_AWAITING_HUMAN'

@pytest.mark.asyncio
async def test_api_requires_admin_and_no_llm_means_failure_not_fake_success(monkeypatch):
    monkeypatch.delenv('GROQ_API_KEY',raising=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        res=await client.post('/api/incidents',json={'title':'Possible credential theft','description':'I entered my password on a suspicious page','kind':'phishing'})
        assert res.status_code==201
        ident=res.json()['id']
        assert (await client.post(f'/api/agent/investigate/{ident}')).status_code==401
        result=await client.post(f'/api/agent/investigate/{ident}',headers={'x-admin-token':'test-admin-secret'})
        assert result.status_code==503
        reports=await client.get(f'/api/agent/reports/{ident}',headers={'x-admin-token':'test-admin-secret'})
        assert reports.status_code==200
        assert reports.json()[0]['status']=='ERROR'
        assert (await client.get('/health')).status_code==200
        assert (await client.get('/')).status_code==200

@pytest.mark.asyncio
async def test_github_cancel_endpoint_rejects_wrong_confirmation():
    from incidentpilot.core import db,create_incident,now
    incident_id=create_incident('Inspect GitHub test workflow','Possible unexpected execution, needs administrator confirmation', 'github_workflow','test')
    with db() as con:
        con.execute('INSERT INTO containment (incident_id,repo,run_id,run_url,workflow_name,observed_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)',
                    (incident_id,'owner/repo',222,'https://github.com/owner/repo/actions/runs/222','lab','in_progress',now(),now()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        res=await client.post(f'/api/github/containments/{incident_id}/review',
           headers={'x-admin-token':'test-admin-secret'},json={'decision':'approve','note':'Approved for test only','confirm_repo':'owner/repo','confirm_run_id':999})
        assert res.status_code==409
        q=await client.get('/api/github/containments',headers={'x-admin-token':'test-admin-secret'})
        assert next(i for i in q.json() if i['incident_id']==incident_id)['action_status']=='PENDING_REVIEW'

@pytest.mark.asyncio
async def test_review_rejection_does_not_call_github():
    from incidentpilot.core import db,create_incident,now
    incident_id=create_incident('Inspect second GitHub run','Sample workflow run requiring human assessment','github_workflow','test')
    with db() as con:
        con.execute('INSERT INTO containment (incident_id,repo,run_id,run_url,workflow_name,observed_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)',
                    (incident_id,'owner/repo',333,'https://github.com/owner/repo/actions/runs/333','lab','in_progress',now(),now()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        res=await client.post(f'/api/github/containments/{incident_id}/review',
           headers={'x-admin-token':'test-admin-secret'},json={'decision':'reject','note':'Not sufficiently justified','confirm_repo':'owner/repo','confirm_run_id':333})
        assert res.status_code==200
        assert res.json()['execution']=='NOT_RUN'
        duplicate=await client.post(f'/api/github/containments/{incident_id}/review',
           headers={'x-admin-token':'test-admin-secret'},json={'decision':'approve','note':'Try again','confirm_repo':'owner/repo','confirm_run_id':333})
        assert duplicate.status_code==409
