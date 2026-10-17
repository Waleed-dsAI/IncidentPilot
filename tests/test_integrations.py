import hashlib
import os
os.environ.setdefault("ADMIN_TOKEN", "test-admin-secret")
import time
import httpx
import pytest
from incidentpilot import github_app
from incidentpilot.core import db
from app import app

@pytest.fixture(autouse=True)
def clean_install():
    with db() as con:
        con.execute('DELETE FROM github_install_states')
        con.execute('DELETE FROM github_app_connection')
    yield
    with db() as con:
        con.execute('DELETE FROM github_install_states')
        con.execute('DELETE FROM github_app_connection')

@pytest.mark.asyncio
async def test_install_state_replay_and_repo_allowlist(monkeypatch):
    with db() as con:
        con.execute('INSERT INTO github_install_states VALUES (?, ?)',
                    (hashlib.sha256(b'legitimate-state').hexdigest(), int(time.time())+600))
    async def fake_json(method,url,headers,**kwargs):
        if url.endswith('/app/installations/44'):
            return {'id':44,'suspended_at':None,'account':{'login':'test-org'},'permissions':{'actions':'write'}}
        if url.endswith('/installation/repositories'):
            return {'repositories':[{'full_name':'test-org/allowed'}]}
        if url.endswith('/app/installations/44/access_tokens'):
            return {'token':'test-short-lived'}
        raise AssertionError('Unexpected request '+url)
    monkeypatch.setattr(github_app,'github_json',fake_json)
    monkeypatch.setattr(github_app,'app_headers', lambda: {'Authorization':'Bearer dummy'})
    with pytest.raises(Exception):
        await github_app.complete_install(44,'attacker-state')
    assert github_app.connection() is None
    conn=await github_app.complete_install(44,'legitimate-state')
    assert conn['account']=='test-org'
    with pytest.raises(Exception):
        await github_app.complete_install(44,'legitimate-state')
    with pytest.raises(Exception):
        await github_app.select_repository('attacker/private')
    chosen=await github_app.select_repository('test-org/allowed')
    assert chosen=='test-org/allowed'
    assert github_app.connection()['selected_repo']==chosen
    assert (await github_app.credentials_for('test-org/allowed'))[0]==chosen
    with pytest.raises(Exception):
        await github_app.credentials_for('test-org/unapproved')
    github_app.disconnect()
    assert github_app.connection() is None

@pytest.mark.asyncio
async def test_connect_requires_admin_and_gmail_disconnect_requires_admin(monkeypatch):
    monkeypatch.setattr(github_app,'start_install', lambda: 'https://github.com/apps/test-app/installations/new?state=fake')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
        assert (await c.get('/api/integrations/github/connect')).status_code==401
        r=await c.get('/api/integrations/github/connect',headers={'X-Admin-Token':'test-admin-secret'})
        assert r.status_code==200 and 'github.com/apps/' in r.json()['url']
        assert (await c.get('/api/integrations/github/status')).status_code==401
        assert (await c.delete('/api/integrations/gmail/noone@example.org')).status_code==401

@pytest.mark.asyncio
async def test_invalid_callback_denied(monkeypatch):
    monkeypatch.setattr(github_app,'complete_install', lambda *args: (_ for _ in ()).throw(ValueError('No call expected')))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
        r=await c.get('/api/integrations/github/callback?installation_id=44&setup_action=delete')
        assert r.status_code==400
