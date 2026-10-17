# IncidentPilot Security Guardian v4

**Human-governed AI security response prototype for Agentika 2.0.** Python 3.11+.

## What demonstrably works

- **Gmail phishing workflow:** the administrator connects a dedicated test Gmail account using Google OAuth; selects one email; a scoped, read-only MCP tool supplies the stored preview to three separate Groq LLM agent roles (investigator, skeptical analyst, response planner); administrator explicitly approves/rejects moving the exact selected message to Gmail **Trash**; backend re-reads metadata, invokes the real Gmail API, checks the label, and audits actual results. Moving to Trash is reversible; NOT permanent deletion or guaranteed phishing prevention.
- **GitHub workflow incident:** retains v3 three-agent investigation + MCP read tools + separately authorized GitHub Actions run cancellation. See `GITHUB_LAB.md`.
- **Windows signal intake:** optional `collector/windows_defender.py` reads limited Defender status on the user's Windows laptop and prints JSON. Administrator may choose to paste it into the dashboard. No background monitoring, ransomware detection, file quarantine, or process termination.
- **Shared queue and audit trail:** FastAPI and SQLite. Provisional incident triage rules remain labeled as preliminary.

**No AI or external API results were fabricated in testing.** Automated tests mock third-party services. Live Groq, OAuth and GitHub calls require your credentials and real-world end-to-end testing.

## Local start (PowerShell / Windows)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# use README config steps below, then:
uvicorn app:app --reload --port 8000
```

Open http://localhost:8000 . Copy `.env.example` as a reference; Uvicorn **does not automatically load `.env`**. Set each variable in PowerShell with `$env:VARIABLE="value"`, or use an approved secret manager. **Never push `.env` to GitHub**. `ADMIN_TOKEN` is entered in the administrator field of the dashboard; it is not an OAuth credential.

### Environment variables — where each one comes from

| Name | Get it from | Put it where |
| --- | --- | --- |
| `ADMIN_TOKEN` | Generate random secret locally with `python -c "import secrets;print(secrets.token_urlsafe(32))"` | PowerShell `$env:ADMIN_TOKEN="..."`; same value in Alternate Clouds Variables |
| `WEBHOOK_TOKEN` | Generate a **different** secret with same command | PowerShell / Alternate Clouds Variables |
| `TOKEN_ENCRYPTION_KEY` | `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"` | PowerShell / Alternate Clouds Variables. **Never rotate casually**: existing Gmail OAuth tokens become unreadable |
| `GOOGLE_CLIENT_ID` | Google Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client IDs → Web application | PowerShell / Alternate Clouds Variables |
| `GOOGLE_CLIENT_SECRET` | Same Google OAuth client | PowerShell / Alternate Clouds Variables; do not commit |
| `GOOGLE_REDIRECT_URI` | Choose the exact URL registered as Authorized Redirect URI for OAuth Web client | Local: `http://localhost:8000/api/gmail/callback`; deployed: `https://YOUR-APP.alternatefutures.ai/api/gmail/callback` |
| `GROQ_API_KEY` | https://console.groq.com/keys | PowerShell / Alternate Clouds Variables |
| `GROQ_MODEL` | A currently available Groq chat-completion model (supports structured JSON prompting); default `llama-3.3-70b-versatile` | PowerShell / Alternate Clouds Variables; verify account model availability |
| `GITHUB_TOKEN` | GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens; restrict to **one dedicated test repo**; Actions read/write | PowerShell / Alternate Clouds Variables |
| `GITHUB_REPO` | The dedicated repo you create, e.g. `YOUR_USERNAME/incidentpilot-security-lab` | PowerShell / Alternate Clouds Variables |
| `DB_PATH` | Your chosen SQLite file path | Local: `./incidentpilot.db`; deployed: **persistent mounted directory** path, if available |
| `PORT` | Alternate Clouds Service Source PORT setting | Must match the container listening port (`8000` by default) |

### Gmail OAuth, step by step

1. Use a **separate test Gmail account** with a harmless test message; never test on confidential mail.
2. Visit https://console.cloud.google.com/ and create/select a project. Enable **Gmail API** under APIs & Services → Library.
3. Under **Google Auth Platform** (or OAuth consent screen), configure app audience and consent fields. During **Testing**, add your Gmail test account under Test users, where available. The `gmail.modify` scope is restricted/sensitive; Google may require additional verification or access restrictions for public use. **Do not assume production OAuth access is granted.**
4. Under Credentials, create OAuth Client ID → **Web application**. Authorized redirect URI must match your actual `GOOGLE_REDIRECT_URI` exactly. Add local and hosted callback URLs as applicable.
5. Put the client ID and client secret in server-side environment variables. Set `TOKEN_ENCRYPTION_KEY`. Start the server and enter `ADMIN_TOKEN` into the dashboard.
6. Click **Connect Gmail**, consent to the restricted Gmail permission, then return to the dashboard, reenter `ADMIN_TOKEN` if needed, click **Refresh accounts**.
7. Click **Load last 12 inbox messages**, select one *harmless test email* → **Open investigation** → **Run 3 AI agents** → inspect evidence/risk → administrator adds a reason → **Approve move to Trash** (or Reject). Confirm in the test Gmail account. The action will refuse approval without a saved investigation report.
8. The data shown to the LLM includes the sender, subject, small snippet and extracted URL indicators from only the selected message. **Do not select private or sensitive messages**. No links are visited.

If the Google consent screen says `access blocked` or `unverified app`, first verify test-user status, OAuth audience, scope restrictions and the redirect URI. Restricted Gmail scopes may prevent public distribution without verification; the workaround is not to bypass Google's permission model.

### GitHub

See `GITHUB_LAB.md` for creation of a benign test workflow. Cancel only a run in a repo you control. Don't use production organization tokens.

### Windows

```powershell
python collector/windows_defender.py
```

This script does **not** upload anything. Copy its JSON output into **Windows Defender signals** on the IncidentPilot dashboard and submit with administrator permission. Only two Defender configuration booleans and an alias are reported; no files are scanned. The event is **unverified telemetry**, not a claim that ransomware was found.

## Multi-agent workflow and MCP

`incidentpilot/email_agents.py` implements **three actual model calls**, not three hard-coded strings: investigation → skeptical analysis → response planning. It obtains case evidence through `get_email_case` from a **case-scoped, read-only MCP stdio subprocess** (`mcp_server.py` and `mcp_protocol.py`). The local implementation covers a narrow MCP JSON-RPC tool subset, **not fastn** and not the official MCP SDK. The GitHub agent uses other read-only MCP tools. Neither model receives action-performing tools.

Actions are separate authenticated FastAPI endpoints. The Gmail executor checks administrator approval of the **exact message ID**, requires a saved AI report, re-reads source details, and verifies the Trash label after action. On API error it records FAILED and never claims success. Tests use mocks; verify it against Gmail live before pitching it as proven.

## Automated tests

```powershell
pip install pytest pytest-asyncio
python -m pytest -q tests
```

Tests include OAuth state replay, encrypted token storage, Gmail review guardrails, actual-action mocking, case-scoped MCP, LLM role separation, Windows ingest, and original GitHub / incident regressions. These do **not** test real OAuth credentials, live model availability, live GitHub cancellation, or live Alternate Clouds hosting.

## Alternate Clouds deployment — mandatory for Agentika

1. Push **code only** to GitHub (`.env`, database, credentials and local logs excluded). Use the included Dockerfile.
2. In https://clouds.alternatefutures.ai create a container/service from the repository; set service `PORT` to `8000` unless you change it in both places.
3. Enter secrets in **Variables** (never source code). Set a stable, secure `TOKEN_ENCRYPTION_KEY`.
4. Provide persistent storage for `DB_PATH` if supported. If not supported, SQLite data will not be guaranteed to survive redeployments; use hosted PostgreSQL before representing it as production-safe.
5. Update Google Cloud's authorized redirect URI to your **actual** deployed HTTPS URL and change `GOOGLE_REDIRECT_URI` in service environment accordingly.
6. **Rebuild**, wait for success, then **Deploy** (two separate operations). Verify `https://YOUR-APP/health`.
7. From the deployed UI, repeat the full Gmail test flow, the GitHub lab (if configured), then reboot/redeploy and check database persistence.
8. Record a 2–3 minute demo, capture deployment screenshot, publish your own original LinkedIn post (AI-written posts are forbidden by the handbook), and prepare the required submission PDF by event deadline.

## Safety limitations

- Prototype uses a shared administrator token, not organization login/RBAC. **Never expose this demo with a real personal inbox or long-term credentials to untrusted users**.
- Gmail OAuth refresh tokens are encrypted in SQLite with a Fernet key in the environment; deploy only over HTTPS, keep server access restricted, and secure backups.
- Gmail Trash is reversible; moving a message is **not** proof that phishing or account compromise was prevented.
- Local Windows telemetry is not continuous monitoring or ransomware prevention.
- `GROQ_API_KEY` is required for live AI. Without it, the email investigation returns an error rather than pretending a model ran.
- The project has **not** been deployed to Alternate Clouds and is **not** production certified.

## v5: Connections from the UI

See **[INTEGRATIONS_SETUP.md](INTEGRATIONS_SETUP.md)**. GitHub now supports a **Connect GitHub** → GitHub App installation → authorized repository selection flow from the Settings page. The app operator configures `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, and GitHub App private key server-side. The Gmail UI also includes disconnect controls. These are **single-admin hackathon features, not multi-user onboarding**.
