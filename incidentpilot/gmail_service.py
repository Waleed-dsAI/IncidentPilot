"""Google OAuth / Gmail client. All account credentials are encrypted at rest.
Only OAuth-approved Gmail accounts; never asks for a user's password.
"""
import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode
import httpx
from cryptography.fernet import Fernet
from fastapi import HTTPException
from .core import db, now

GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token'
GMAIL_API = 'https://gmail.googleapis.com/gmail/v1/users/me'
SCOPE = 'https://www.googleapis.com/auth/gmail.modify'

def config():
    cid = os.getenv('GOOGLE_CLIENT_ID','')
    secret = os.getenv('GOOGLE_CLIENT_SECRET','')
    uri = os.getenv('GOOGLE_REDIRECT_URI','')
    if not all((cid,secret,uri,os.getenv('TOKEN_ENCRYPTION_KEY',''))):
        raise HTTPException(503,'Google OAuth client and TOKEN_ENCRYPTION_KEY must be configured')
    return cid,secret,uri

def cipher():
    try:
        return Fernet(os.environ['TOKEN_ENCRYPTION_KEY'].encode())
    except (KeyError,ValueError) as exc:
        raise HTTPException(503,'TOKEN_ENCRYPTION_KEY missing or invalid') from exc

def setup():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS gmail_oauth_states (
           state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS gmail_accounts (
           account_id TEXT PRIMARY KEY, refresh_token TEXT NOT NULL,
           connected_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS email_cases (
           id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL UNIQUE,
           account_id TEXT NOT NULL, message_id TEXT NOT NULL, thread_id TEXT NOT NULL,
           sender TEXT NOT NULL, subject TEXT NOT NULL, snippet TEXT NOT NULL,
           links_json TEXT NOT NULL, observed_labels TEXT NOT NULL,
           action_status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
           action_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS email_case_unique ON email_cases(account_id,message_id);
        ''')

setup()

def auth_url():
    import time
    cid, _, redirect = config()
    state = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute('DELETE FROM gmail_oauth_states WHERE expires_at < ?', (int(time.time()),))
        conn.execute('INSERT INTO gmail_oauth_states VALUES (?,?)',
                     (hashlib.sha256(state.encode()).hexdigest(),int(time.time())+600))
    params={'client_id':cid,'redirect_uri':redirect,'response_type':'code',
            'scope':SCOPE,'state':state,'access_type':'offline','prompt':'consent',
            'include_granted_scopes':'false'}
    return GOOGLE_AUTH+'?'+urlencode(params)

async def exchange(code,state,transport=None):
    import time
    if not code or not state or len(state)>256: raise HTTPException(400,'Missing OAuth code or state')
    digest=hashlib.sha256(state.encode()).hexdigest()
    with db() as conn:
        rec=conn.execute('SELECT expires_at FROM gmail_oauth_states WHERE state_hash=?',(digest,)).fetchone()
        conn.execute('DELETE FROM gmail_oauth_states WHERE state_hash=?',(digest,))
    if not rec or rec['expires_at']<int(time.time()):
        raise HTTPException(400,'Invalid or expired OAuth state')
    cid, secret, redirect=config()
    async with httpx.AsyncClient(timeout=15, transport=transport) as client:
        r=await client.post(GOOGLE_TOKEN,data={'code':code,'client_id':cid,'client_secret':secret,
                              'redirect_uri':redirect,'grant_type':'authorization_code'})
        if r.status_code!=200: raise HTTPException(502,'Google token exchange failed')
        payload=r.json()
        if SCOPE not in payload.get('scope','').split():
            raise HTTPException(403,'Required Gmail OAuth scope was not granted')
        access=payload.get('access_token')
        refresh=payload.get('refresh_token')
        if not access or not refresh: raise HTTPException(400,'Google did not provide refresh token. Reconnect with consent.')
        profile=await client.get(GMAIL_API+'/profile',headers={'Authorization':'Bearer '+access})
        if profile.status_code!=200: raise HTTPException(502,'Gmail profile lookup failed')
        address=profile.json()['emailAddress'].strip().lower()
    with db() as conn:
        conn.execute('INSERT OR REPLACE INTO gmail_accounts VALUES (?,?,?)',
              (address,cipher().encrypt(refresh.encode()).decode(),now()))
    return address

async def google_access_token(account_id,transport=None):
    cid,secret,_=config()
    with db() as conn:
        record=conn.execute('SELECT refresh_token FROM gmail_accounts WHERE account_id=?',(account_id,)).fetchone()
    if not record: raise HTTPException(404,'Connected Gmail account missing')
    refresh=cipher().decrypt(record['refresh_token'].encode()).decode()
    async with httpx.AsyncClient(timeout=15,transport=transport) as client:
        r=await client.post(GOOGLE_TOKEN,data={'client_id':cid,'client_secret':secret,
             'refresh_token':refresh,'grant_type':'refresh_token'})
    if r.status_code!=200: raise HTTPException(502,'Unable to refresh Google access token; reconnect Gmail')
    return r.json()['access_token']

async def gmail_request(account_id,method,path,transport=None,**kwargs):
    token=await google_access_token(account_id,transport=transport)
    async with httpx.AsyncClient(timeout=15,transport=transport) as client:
        r=await client.request(method,GMAIL_API+path,headers={'Authorization':'Bearer '+token},**kwargs)
    if r.status_code not in (200,201,202,204):
        raise HTTPException(502,f'Gmail API operation failed: HTTP {r.status_code}')
    return r.json() if r.content else {}

def safe_message(data):
    """Minimal email preview: do not download attachments or follow external links."""
    headers={item['name'].lower():item['value'] for item in data.get('payload',{}).get('headers',[])
             if item.get('name','').lower() in ('from','subject')}
    snippet=str(data.get('snippet',''))[:1000]
    import re
    # Only extract indicators from limited snippet; never fetch any URLs.
    links=list(dict.fromkeys(re.findall(r'https?://[^\s<>"\']+',snippet,flags=re.I)))[:10]
    return {'message_id':data['id'],'thread_id':data.get('threadId',''),
        'sender':headers.get('from','unknown')[:300],
        'subject':headers.get('subject','(no subject)')[:300],
        'snippet':snippet,'links':links,'labels':data.get('labelIds',[])}
