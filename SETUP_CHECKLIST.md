# IncidentPilot v4 — Do this in order

**A. Get the application to start**

1. Extract ZIP, open root directory in VS Code.
2. `py -m venv .venv`, activate, `pip install -r requirements.txt`.
3. Generate different `ADMIN_TOKEN` and `WEBHOOK_TOKEN` with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
4. Generate `TOKEN_ENCRYPTION_KEY` with `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`.
5. Set environment variables in PowerShell (`$env:NAME="actual-value"`) **in the same terminal** where you run `uvicorn app:app --reload --port 8000`.
6. Check `http://localhost:8000/health` and dashboard.

**B. Make three agents actually reason**

1. Visit https://console.groq.com/keys, create key, set `GROQ_API_KEY`.
2. Check that `GROQ_MODEL` is currently available; default is in `.env.example`.
3. To investigate an email, complete C and then run **Run 3 AI agents**. The model does **not** run at project startup.

**C. Give Gmail permission without giving us your password**

1. Google Cloud Console → new project → enable Gmail API.
2. Configure OAuth consent as Testing; add your **test Gmail** as allowed test user if External.
3. Credentials → OAuth Client ID → Web application → authorized redirect URI `http://localhost:8000/api/gmail/callback`.
4. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `TOKEN_ENCRYPTION_KEY`.
5. Dashboard → enter ADMIN_TOKEN → Connect Gmail. After consent, return, paste ADMIN_TOKEN again → Refresh accounts.
6. Select harmless email, investigate, review AI report, approve moving the **exact** message to Trash.

**D. Connect GitHub (optional second live action)**

1. Create private test repository `incidentpilot-security-lab` and add harmless lab workflow from `GITHUB_LAB.md`.
2. GitHub fine-grained PAT: only that repository, Actions read/write; set `GITHUB_TOKEN` and `GITHUB_REPO`.
3. Run test workflow; select run; investigate with AI, approve cancellation, check live result.

**E. Windows test signals (no privileged rights or changes)**

1. Run `python collector/windows_defender.py` on Windows.
2. Copy printed JSON into dashboard Windows signals form; click Submit.

**F. Deployment**

1. Push code only (no `.env`, no database) to GitHub.
2. Alternate Clouds → service (Dockerfile), port 8000, create Variables above, persistent DB volume if available.
3. Add your hosted HTTPS callback URL to Google OAuth Web client; update `GOOGLE_REDIRECT_URI` for cloud service.
4. Rebuild → Deploy → verify public `/health` and real action; capture proof for event submission.

**Remember:** Google OAuth restricted Gmail scopes may require an eligible testing configuration or additional verification. Do not share any of the secret values in chat or screenshots.
