# Real GitHub containment lab

1. Create a **new private test repository** named `incidentpilot-security-lab` in your GitHub account. Do not use a work or production repository.
2. Add `.github/workflows/harmless-lab.yml` from this project to that repository. Commit it on the default branch.
3. GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens: create a short-lived token restricted to **only this test repo** with **Actions: Read and write**. GitHub may require repository owner approval. Do not put the token in code, Git, chat, or screenshots.
4. Configure environment variables `GITHUB_TOKEN`, `GITHUB_REPO`, `ADMIN_TOKEN`, `WEBHOOK_TOKEN`. `GITHUB_REPO` must equal `owner/incidentpilot-security-lab`.
5. In the GitHub test repository, go to **Actions** > Harmless containment lab > **Run workflow**.
6. Open IncidentPilot, enter ADMIN_TOKEN, click **Load GitHub runs**, then **Investigate this run**. Inspect the GitHub run and approve its cancellation only if it is your harmless test.
7. The system requests cancellation and polls GitHub briefly. If the result says `CANCELLATION_REQUESTED`, click **Check GitHub status**. Only `VERIFIED_CANCELLED` establishes confirmed cancellation.
8. Open the incident audit log and capture proof for the demonstration.

## Important
- A GitHub Actions running job is not inherently malicious. This lab tests a *manual containment decision* on a test job, not malware detection.
- Canceling a run stops that run; it does not disable the workflow or revoke stolen secrets.
- This prototype uses a single administrator secret. It needs organization authentication, stronger authorization and a robust work queue before real-world use.
- SQLite inside a disposable cloud container may reset on redeploy; use persistent storage or a managed database if needed.
