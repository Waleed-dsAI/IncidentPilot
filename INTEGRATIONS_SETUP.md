# IncidentPilot v5 — Connect services from the dashboard

## What is new

**Settings → Connected services** lets the hackathon administrator connect a GitHub App, select an authorized repository, inspect connection status and disconnect it without supplying a PAT to the browser. Gmail already supports its own **Connect Gmail** OAuth button; the Settings panel now supports viewing and disconnecting Gmail accounts. The Windows collector remains read-only and manual.

This is a **single-administrator demonstration**, not secure multi-tenant signup. A shared `ADMIN_TOKEN` protects settings and approvals. Do not deploy this as a production multi-user security service.

## Operator-only setup — GitHub App

One developer configures the app once. Users then authorize access in GitHub's own UI.

1. At [GitHub Developer Settings → GitHub Apps](https://github.com/settings/apps), create a GitHub App.
2. Set the **Setup URL** to the precise HTTPS URL of your deployed service plus `/api/integrations/github/callback`. For local development, you can use a reachable HTTPS tunnel that forwards to port 8000; GitHub needs a URL it can redirect your browser to. Do not put an untrusted tunnel in front of production admin endpoints.
3. Under **Repository permissions**, give **Actions: Read and write**. Keep all other permissions minimal. For a personal installation, choose *Only on this account* if appropriate. The app does **not** need organization-wide installation.
4. Generate a GitHub App private key (.pem). Do not commit or upload the PEM. Note the **App ID** and the **app slug** in its public URL (`https://github.com/apps/<slug>`).
5. Configure the following **server-side** variables:

```text
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=your-app-slug
GITHUB_APP_PRIVATE_KEY_PATH=C:\\secure\\incidentpilot-app.private-key.pem
```

Alternatively, for Alternate Clouds set `GITHUB_APP_PRIVATE_KEY` to the complete PEM with newline characters encoded as `\n`, in the service's secret/variable settings. Do not put the private key in the UI. Leave `GITHUB_APP_PRIVATE_KEY_PATH` unset in that case.

6. Run the app. Enter the demo administrator token in the UI, open **Settings → Connected services**, click **Connect GitHub**, and approve installing the App **only on the designated test repository**.
7. GitHub redirects to your **Setup URL**; return to Settings, refresh connection, choose an authorized repository and click **Use selected repository**.
8. From now on, GitHub run listing, containment and read-only agent evidence tools use short-lived installation tokens for that selected repository. The older `GITHUB_TOKEN` and `GITHUB_REPO` env values remain an optional developer-only fallback when no App is connected. Remove those fallback values on any public deployment.

**Note:** The GitHub App needs Actions write permission to cancel a workflow; a separate `Issues: write` permission would be required to create GitHub issues. This version deliberately does not create issues using the GitHub App.

## Gmail (already supported in v4)

The operator sets `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and `TOKEN_ENCRYPTION_KEY` on the server (see the original setup checklist). Users click **Connect Gmail**, authorize the requested scope on Google's site, then can view and disconnect the account under Settings. Local disconnect deletes the stored refresh token. Separately revoke the app under Google Account → Security for complete revocation.

## Security boundaries and limitations

- The callback has an unpredictable, expiring, one-time state and checks the installation through GitHub's authenticated API.
- Repository selection only accepts repos returned by the current installation token. A changed selection will block cancellation of incidents associated with the previous repo.
- The dashboard must be hosted over HTTPS. Never send administrator tokens over plain HTTP on an external network.
- Current shared administrator tokens **do not implement individual user accounts, organizational tenancy, or per-user permission checks**. A production product requires a real identity/session system and strong server-side tenant isolation.
- Store the database on persistent storage or use managed Postgres before relying on connections surviving container redeployment.
- **Local disconnect does not uninstall the GitHub App.** Uninstall/revoke at GitHub settings to invalidate external authorization.
- These new authorization flows passed mocked tests. Live GitHub installation/OAuth must still be tested with a real GitHub App.
