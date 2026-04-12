"""Global test fixtures — runs before any test module is imported."""

import os

# Override the App Insights connection string so tests never export
# telemetry to a real (or stale) endpoint.  Setting the env var to ""
# overrides whatever pydantic-settings reads from .env, because env
# vars take precedence over env_file values.
os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"] = ""
