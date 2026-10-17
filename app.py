"""Thin FastAPI entrypoint; route implementations live in incidentpilot modules."""
from incidentpilot.core import app
import incidentpilot.github_routes  # noqa: F401 — registers GitHub routes
import incidentpilot.agent_routes  # noqa: F401 — registers agent routes
import incidentpilot.gmail_routes  # noqa: F401 — Gmail connector routes
import incidentpilot.windows_routes  # noqa: F401 — opt-in Windows signal ingestion
import incidentpilot.email_agents  # noqa: F401 — email-specific multi-agent routes

import incidentpilot.integrations_routes  # noqa: F401 - settings and OAuth
