"""PostureIQ — Distributed tracing with Azure Application Insights.

Integrates OpenTelemetry for distributed tracing. Every tool call and LLM call
becomes a trace span, enabling end-to-end visibility in App Insights.
"""

from __future__ import annotations

import functools
import time
from typing import Any, Callable, TypeVar

import structlog
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from src.agent.config import settings

logger = structlog.get_logger(__name__)

# Module-level tracer — initialized in setup_tracing()
_tracer: trace.Tracer | None = None

F = TypeVar("F", bound=Callable[..., Any])


def setup_tracing() -> None:
    """Initialize Azure Monitor OpenTelemetry tracing.

    Call once at application startup (in main.py).
    """
    global _tracer

    conn_string = settings.applicationinsights_connection_string

    if conn_string:
        try:
            from azure.monitor.opentelemetry import configure_azure_monitor

            configure_azure_monitor(
                connection_string=conn_string,
                enable_live_metrics=True,
            )
            logger.info("tracing.setup.complete", target="azure_app_insights")
        except ImportError:
            logger.warning("tracing.setup.skipped", reason="azure-monitor-opentelemetry not installed")
        except Exception as e:
            logger.warning("tracing.setup.failed", error=str(e))
    else:
        logger.info("tracing.setup.skipped", reason="no connection string configured")

    _tracer = trace.get_tracer("postureiq", "0.1.0")


def get_tracer() -> trace.Tracer:
    """Get the configured tracer, initializing if needed."""
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer("postureiq", "0.1.0")
    return _tracer


def trace_tool_call(tool_name: str) -> Callable[[F], F]:
    """Decorator that wraps a tool function in an OpenTelemetry span.

    Records: tool name, duration, status, and any errors.

    Usage:
        @trace_tool_call("query_secure_score")
        async def query_secure_score(...) -> dict:
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(
                name=f"tool.{tool_name}",
                attributes={
                    "postureiq.tool.name": tool_name,
                    "postureiq.tool.type": "assessment",
                },
            ) as span:
                start_time = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                    duration_ms = (time.monotonic() - start_time) * 1000

                    span.set_attribute("postureiq.tool.duration_ms", duration_ms)
                    span.set_attribute("postureiq.tool.status", "success")
                    span.set_status(StatusCode.OK)

                    logger.info(
                        f"tool.{tool_name}.traced",
                        duration_ms=round(duration_ms, 2),
                        status="success",
                    )

                    return result

                except Exception as e:
                    duration_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute("postureiq.tool.duration_ms", duration_ms)
                    span.set_attribute("postureiq.tool.status", "error")
                    span.set_attribute("postureiq.tool.error", str(e))
                    span.set_status(StatusCode.ERROR, str(e))
                    span.record_exception(e)

                    logger.error(
                        f"tool.{tool_name}.error",
                        duration_ms=round(duration_ms, 2),
                        error=str(e),
                    )
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator
