"""Single-workspace GitHub App installation authorization for hackathon demo.

No PAT is requested from users. GitHub App private key and ID belong to the
operator, and installation tokens are minted server-side with short lifetimes.
This module intentionally handles only a single administrator workspace.
"""
import hashlib
import os
import re
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException

from .core import db, now

API = "https://api.github.com"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def init():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS github_install_states (
                state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS github_app_connection (
                singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                installation_id INTEGER NOT NULL,
                account_login TEXT NOT NULL,
                selected_repo TEXT,
                connected_at TEXT NOT NULL);
        """)

init()


def configured():
    app_id = os.getenv('GITHUB_APP_ID', '').strip()
    slug = os.getenv('GITHUB_APP_SLUG', '').strip()
    private_key = os.getenv('GITHUB_APP_PRIVATE_KEY', '').replace('\\n', '\n').strip()
    if not private_key and os.getenv('GITHUB_APP_PRIVATE_KEY_PATH'):
        from pathlib import Path
        try:
            private_key = Path(os.environ['GITHUB_APP_PRIVATE_KEY_PATH']).read_text(encoding='utf-8').strip()
        except OSError as exc:
            raise HTTPException(503, 'Could not load GitHub App private key file') from exc
    if not app_id.isdigit() or not re.fullmatch(r'[a-zA-Z0-9-]+', slug) or 'BEGIN' not in private_key:
        raise HTTPException(503, 'GitHub App not configured: set GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_PRIVATE_KEY')
    return app_id, slug, private_key


def app_headers():
    app_id, _, private_key = configured()
    timestamp = int(time.time())
    bearer = jwt.encode({'iat': timestamp - 60, 'exp': timestamp + 540, 'iss': app_id}, private_key, algorithm='RS256')
    return {'Authorization': f'Bearer {bearer}', 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'}


def start_install():
    _, slug, _ = configured()
    state = secrets.token_urlsafe(32)
    digest = hashlib.sha256(state.encode()).hexdigest()
    with db() as conn:
        conn.execute('DELETE FROM github_install_states WHERE expires_at<?', (int(time.time()),))
        conn.execute('INSERT INTO github_install_states(state_hash,expires_at) VALUES (?,?)',
                     (digest, int(time.time()) + 600))
    return f'https://github.com/apps/{slug}/installations/new?' + urlencode({'state': state})


async def github_json(method, url, headers, **kwargs):
    try:
        async with httpx.AsyncClient(timeout=18) as client:
            response = await client.request(method, url, headers=headers, **kwargs)
    except httpx.HTTPError as exc:
        raise HTTPException(502, 'GitHub connection failure') from exc
    if response.status_code not in (200, 201, 204):
        raise HTTPException(502, f'GitHub API returned HTTP {response.status_code}')
    return response.json() if response.content else {}


async def complete_install(installation_id: int, state: str):
    if installation_id <= 0 or not state or len(state) > 256:
        raise HTTPException(400, 'Missing installation ID or authorization state')
    digest = hashlib.sha256(state.encode()).hexdigest()
    with db() as conn:
        row = conn.execute('SELECT expires_at FROM github_install_states WHERE state_hash=?', (digest,)).fetchone()
        conn.execute('DELETE FROM github_install_states WHERE state_hash=?', (digest,))
    if not row or row['expires_at'] < int(time.time()):
        raise HTTPException(400, 'Invalid, expired or already used GitHub authorization state')
    info = await github_json('GET', f'{API}/app/installations/{installation_id}', app_headers())
    if info.get('id') != installation_id or info.get('suspended_at'):
        raise HTTPException(403, 'Installation invalid or suspended')
    perms = info.get('permissions', {})
    if perms.get('actions') != 'write':
        raise HTTPException(403, 'GitHub App installation needs Actions: read and write')
    account = info.get('account', {}).get('login', '')
    if not account:
        raise HTTPException(502, 'GitHub did not return installation account')
    with db() as conn:
        conn.execute('INSERT OR REPLACE INTO github_app_connection VALUES (1,?,?,NULL,?)',
                     (installation_id, account, now()))
    return {'installation_id': installation_id, 'account': account}


def connection():
    with db() as conn:
        row = conn.execute('SELECT * FROM github_app_connection WHERE singleton=1').fetchone()
    return dict(row) if row else None


async def installation_token(installation_id):
    data = await github_json('POST', f'{API}/app/installations/{installation_id}/access_tokens', app_headers())
    token = data.get('token')
    if not token:
        raise HTTPException(502, 'GitHub returned no installation token')
    return token


async def available_repositories():
    active = connection()
    if not active:
        raise HTTPException(409, 'Connect GitHub first')
    token = await installation_token(active['installation_id'])
    repos = []
    for page in range(1, 6):
        data = await github_json('GET', f'{API}/installation/repositories',
                                 {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'},
                                 params={'per_page': 100, 'page': page})
        batch = data.get('repositories', [])
        repos.extend([x['full_name'] for x in batch if NAME_RE.fullmatch(x.get('full_name', ''))])
        if len(batch) < 100:
            break
    return sorted(set(repos), key=str.lower)


async def select_repository(repo):
    if not NAME_RE.fullmatch(repo):
        raise HTTPException(422, 'Invalid GitHub repository name')
    permitted = await available_repositories()
    exact = next((r for r in permitted if r.lower() == repo.lower()), None)
    if not exact:
        raise HTTPException(403, 'Repository was not granted to IncidentPilot')
    with db() as conn:
        conn.execute('UPDATE github_app_connection SET selected_repo=? WHERE singleton=1', (exact,))
    return exact


async def credentials_for(repo=None):
    active = connection()
    if not active or not active['selected_repo']:
        raise HTTPException(503, 'Select an authorized GitHub repository under Settings')
    selected = active['selected_repo']
    if repo is not None and repo.lower() != selected.lower():
        raise HTTPException(409, 'Incident targets a repository that is no longer selected')
    token = await installation_token(active['installation_id'])
    return selected, token


def disconnect():
    # Clears our installation association. To fully revoke, uninstall the GitHub App on GitHub.
    with db() as conn:
        conn.execute('DELETE FROM github_app_connection WHERE singleton=1')
        conn.execute('DELETE FROM github_install_states')


def mcp_read_credentials():
    """Synchronous GitHub App installation token for isolated MCP stdio process."""
    active = connection()
    if not active:
        return None
    if not active['selected_repo']:
        raise ValueError('Choose a GitHub repository under Settings first')
    try:
        with httpx.Client(timeout=15) as client:
            response = client.post(f"{API}/app/installations/{active['installation_id']}/access_tokens", headers=app_headers())
        if response.status_code != 201 or not response.json().get('token'):
            raise ValueError('GitHub installation token unavailable')
        return active['selected_repo'], response.json()['token']
    except httpx.HTTPError as exc:
        raise ValueError('GitHub installation authentication unavailable') from exc
