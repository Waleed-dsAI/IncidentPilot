"""Single-admin integration settings. Not multi-tenant user authentication."""
from fastapi import Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from .core import app, db, require_admin
from . import github_app

class RepoSelection(BaseModel):
    repo: str = Field(min_length=3, max_length=220)

@app.get('/api/integrations/github/status')
def github_status(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    connection = github_app.connection()
    return {'connected': bool(connection), 'account': connection['account_login'] if connection else None,
            'selected_repo': connection['selected_repo'] if connection else None,
            'mode': 'GitHub App' if connection else 'not connected'}

@app.get('/api/integrations/github/connect')
def github_connect(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return {'url': github_app.start_install()}

@app.get('/api/integrations/github/callback', response_class=HTMLResponse)
async def github_callback(installation_id: int = 0, state: str = '', setup_action: str = ''):
    if setup_action not in ('install', 'update'):
        raise HTTPException(400, 'Unexpected GitHub installation action')
    result = await github_app.complete_install(installation_id, state)
    return HTMLResponse('<!doctype html><meta charset="utf-8"><h2>GitHub connected</h2>'
                        '<p>Return to IncidentPilot → Settings → Integrations and select an authorized repository.</p>'
                        '<p>No token was sent to your browser.</p>')

@app.get('/api/integrations/github/repositories')
async def github_repositories(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return {'repositories': await github_app.available_repositories()}

@app.post('/api/integrations/github/repository')
async def github_select(payload: RepoSelection, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return {'selected_repo': await github_app.select_repository(payload.repo)}

@app.delete('/api/integrations/github/disconnect')
def github_disconnect(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    github_app.disconnect()
    return {'connected': False, 'note': 'Local association deleted. Uninstall App in GitHub settings to revoke GitHub access.'}

@app.delete('/api/integrations/gmail/{account_id}')
def gmail_disconnect(account_id: str, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with db() as conn:
        result = conn.execute('DELETE FROM gmail_accounts WHERE account_id=?', (account_id,))
    if not result.rowcount:
        raise HTTPException(404, 'Gmail account not connected')
    return {'disconnected': account_id, 'note': 'Local OAuth credential deleted. Revoke access from Google Account security settings as well.'}
