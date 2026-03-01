"""PostureIQ — Distributed tracing & custom metrics with Azure Application Insights.

Integrates OpenTelemetry for distributed tracing. Every tool call, LLM call,
and session becomes a trace span, enabling end-to-end visibility in App Insights.

GenAI semantic conventions (populates the App Insights "Agent (preview)" blade):
  - Agent Runs  → ``gen_ai.operation.name = "invoke_agent"``
  - Tool Calls  → ``gen_ai.operation.name = "execute_tool"``
  - Token Usage → auto-instrumented by ``opentelemetry-instrumentation-openai-v2``

Custom metrics emitted:
  - postureiq.secure_score.current          (gauge)
  - postureiq.assessment.duration_seconds   (histogram)
  - postureiq.remediation.steps_generated   (counter)
  - postureiq.content_safety.blocked_count  (counter)
"""

from __future__ import annotations

import contextlib
import functools
import time
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any, TypeVar

import structlog
from opentelemetry import metrics, trace
from opentelemetry.trace import SpanKind, StatusCode

from src.agent.config import settings
from src.middleware.pii_redaction import redact_dict

# ── GenAI semantic-convention attribute keys ──────────────
# These are the attribute names the App Insights "Agent (preview)" blade
# queries to populate Agent Runs, Tool Calls, and Token Consumption panels.
_GENAI_SYSTEM = "gen_ai.system"
_GENAI_OPERATION_NAME = "gen_ai.operation.name"
_GENAI_AGENT_NAME = "gen_ai.agent.name"
_GENAI_AGENT_DESCRIPTION = "gen_ai.agent.description"
_GENAI_TOOL_NAME = "gen_ai.tool.name"
_GENAI_TOOL_CALL_ID = "gen_ai.tool.call.id"
_GENAI_CONVERSATION_ID = "gen_ai.conversation.id"
_GENAI_REQUEST_MODEL = "gen_ai.request.model"

logger = structlog.get_logger(__name__)

# Module-level tracer & meter — initialized in setup_tracing()
_tracer: trace.Tracer | None = None
_meter: metrics.Meter | None = None

# ── Custom metrics (initialized in setup_tracing) ──────────
_secure_score_gauge: metrics.ObservableGauge | None = None
_assessment_duration_histogram: metrics.Histogram | None = None
_remediation_steps_counter: metrics.Counter | None = None
_content_safety_blocked_counter: metrics.Counter | None = None

# Internal store for the latest secure score value (for gauge callback)
_latest_secure_score: float = 0.0

F = TypeVar("F", bound=Callable[..., Any])


def _secure_score_callback(
    options: metrics.CallbackOptions,
) -> list[metrics.Observation]:
    """Observable gauge callback — returns the last-known secure score."""
    return [metrics.Observation(value=_latest_secure_score)]


def setup_tracing() -> None:
    """Initialize Azure Monitor OpenTelemetry tracing and custom metrics.

    Call once at application startup (in main.py).
    """
    global _tracer, _meter
    global _secure_score_gauge, _assessment_duration_histogram
    global _remediation_steps_counter, _content_safety_blocked_counter

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
            logger.warning(
                "tracing.setup.skipped",
                reason="azure-monitor-opentelemetry not installed",
            )
        except Exception as e:
            logger.warning("tracing.setup.failed", error=str(e))

        # ── GenAI auto-instrumentation ─────────────────────────────
        # Patches the openai SDK so every chat.completions.create() call
        # emits spans with gen_ai.* semantic-convention attributes.
        # This populates the App Insights "Agent (preview)" blade.
        try:
            from opentelemetry.instrumentation.openai_v2 import OpenAIInstrumentor

            OpenAIInstrumentor().instrument()
            logger.info("tracing.genai_instrumentor.complete", instrumentor="openai_v2")
        except ImportError:
            logger.debug(
                "tracing.genai_instrumentor.skipped",
                reason="opentelemetry-instrumentation-openai-v2 not installed",
            )
        except Exception as e:
            logger.warning("tracing.genai_instrumentor.failed", error=str(e))
    else:
        logger.info(
            "tracing.setup.skipped",
            reason="no connection string configured",
        )

    _tracer = trace.get_tracer("postureiq", "0.1.0")
    _meter = metrics.get_meter("postureiq", "0.1.0")

    # ── Custom metrics ────────────────────────────────────
    _secure_score_gauge = _meter.create_observable_gauge(
        name="postureiq.secure_score.current",
        description="Current tenant secure score",
        unit="points",
        callbacks=[_secure_score_callback],
    )

    _assessment_duration_histogram = _meter.create_histogram(
        name="postureiq.assessment.duration_seconds",
        description="Duration of security assessment operations",
        unit="s",
    )

    _remediation_steps_counter = _meter.create_counter(
        name="postureiq.remediation.steps_generated",
        description="Total remediation steps generated",
        unit="steps",
    )

    _content_safety_blocked_counter = _meter.create_counter(
        name="postureiq.content_safety.blocked_count",
        description="Total content blocked by Azure AI Content Safety",
        unit="blocks",
    )


def get_tracer() -> trace.Tracer:
    """Get the configured tracer, initializing if needed."""
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer("postureiq", "0.1.0")
    return _tracer


def get_meter() -> metrics.Meter:
    """Get the configured meter, initializing if needed."""
    global _meter
    if _meter is None:
        _meter = metrics.get_meter("postureiq", "0.1.0")
    return _meter


# ── Metric recording helpers ─────────────────────────────


def record_secure_score(score: float) -> None:
    """Update the observable gauge with the latest secure score."""
    global _latest_secure_score
    _latest_secure_score = score
    logger.info("metric.secure_score.updated", score=score)


def record_assessment_duration(duration_seconds: float, tool_name: str = "") -> None:
    """Record an assessment duration measurement."""
    if _assessment_duration_histogram is not None:
        _assessment_duration_histogram.record(
            duration_seconds,
            attributes={"postureiq.tool.name": tool_name},
        )


def record_remediation_steps(count: int) -> None:
    """Increment the remediation steps counter."""
    if _remediation_steps_counter is not None:
        _remediation_steps_counter.add(count)
    logger.info("metric.remediation_steps.recorded", count=count)


def record_content_safety_block(category: str = "unknown") -> None:
    """Increment the content safety blocked counter."""
    if _content_safety_blocked_counter is not None:
        _content_safety_blocked_counter.add(1, attributes={"postureiq.safety.category": category})
    logger.warning("metric.content_safety.blocked", category=category)


# ── Trace decorators ─────────────────────────────────────


def trace_tool_call(tool_name: str) -> Callable[[F], F]:
    """Decorator that wraps a tool function in an OpenTelemetry span.

    Records both PostureIQ-specific and GenAI semantic-convention attributes
    so the span appears in the App Insights "Agent (preview)" → Tool Calls panel.

    GenAI attributes emitted:
      - ``gen_ai.system``          = ``"openai"``
      - ``gen_ai.operation.name``  = ``"execute_tool"``
      - ``gen_ai.tool.name``       = *tool_name*
      - ``gen_ai.tool.call.id``    = unique UUID per invocation

    Usage::

        @trace_tool_call("query_secure_score")
        async def query_secure_score(...) -> dict:
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            tool_call_id = str(uuid.uuid4())
            with tracer.start_as_current_span(
                name=f"execute_tool {tool_name}",
                kind=SpanKind.INTERNAL,
                attributes={
                    # GenAI semantic conventions (Agent blade)
                    _GENAI_SYSTEM: "openai",
                    _GENAI_OPERATION_NAME: "execute_tool",
                    _GENAI_TOOL_NAME: tool_name,
                    _GENAI_TOOL_CALL_ID: tool_call_id,
                    # PostureIQ-specific (custom dashboards)
                    "postureiq.tool.name": tool_name,
                    "postureiq.tool.type": "assessment",
                },
            ) as span:
                start_time = time.monotonic()

                # Record redacted input parameters
                if kwargs:
                    redacted_params = redact_dict(dict(kwargs))
                    span.set_attribute(
                        "postureiq.tool.input_params",
                        str(redacted_params)[:500],
                    )

                try:
                    result = await func(*args, **kwargs)
                    duration_ms = (time.monotonic() - start_time) * 1000
                    duration_s = duration_ms / 1000

                    span.set_attribute("postureiq.tool.duration_ms", duration_ms)
                    span.set_attribute("postureiq.tool.status", "success")

                    # Record output summary
                    if isinstance(result, dict):
                        span.set_attribute(
                            "postureiq.tool.output_summary",
                            str(list(result.keys()))[:200],
                        )
                    elif isinstance(result, str):
                        span.set_attribute(
                            "postureiq.tool.output_summary",
                            f"string({len(result)} chars)",
                        )

                    span.set_status(StatusCode.OK)

                    # Record assessment duration metric
                    record_assessment_duration(duration_s, tool_name)

                    logger.info(
                        f"tool.{tool_name}.traced",
                        tool_name=tool_name,
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
                        tool_name=tool_name,
                        duration_ms=round(duration_ms, 2),
                        error=str(e),
                    )
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator


def trace_llm_call(
    model_name: str = "gpt-4o",
) -> Callable[[F], F]:
    """Decorator that wraps an LLM call in an OpenTelemetry span.

    Records: model name, token usage (prompt + completion), Content Safety
    filter result, duration, and any errors.

    Usage:
        @trace_llm_call("gpt-4o")
        async def call_llm(prompt: str) -> dict:
            ...
            return {"content": "...", "usage": {"prompt_tokens": 100, "completion_tokens": 50}}
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(
                name=f"llm.{model_name}",
                attributes={
                    "postureiq.llm.model": model_name,
                    "postureiq.llm.type": "chat_completion",
                },
            ) as span:
                start_time = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                    duration_ms = (time.monotonic() - start_time) * 1000

                    span.set_attribute("postureiq.llm.duration_ms", duration_ms)
                    span.set_attribute("postureiq.llm.status", "success")

                    # Extract token usage if available
                    if isinstance(result, dict):
                        usage = result.get("usage", {})
                        if usage:
                            prompt_tokens = usage.get("prompt_tokens", 0)
                            completion_tokens = usage.get("completion_tokens", 0)
                            total_tokens = usage.get(
                                "total_tokens",
                                prompt_tokens + completion_tokens,
                            )
                            span.set_attribute("postureiq.llm.prompt_tokens", prompt_tokens)
                            span.set_attribute(
                                "postureiq.llm.completion_tokens",
                                completion_tokens,
                            )
                            span.set_attribute("postureiq.llm.total_tokens", total_tokens)

                        # Record Content Safety filter result if present
                        safety_result = result.get("content_safety_result", "")
                        if safety_result:
                            span.set_attribute(
                                "postureiq.llm.content_safety_result",
                                str(safety_result),
                            )

                    span.set_status(StatusCode.OK)

                    logger.info(
                        "llm.call.traced",
                        model=model_name,
                        duration_ms=round(duration_ms, 2),
                        status="success",
                    )

                    return result

                except Exception as e:
                    duration_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute("postureiq.llm.duration_ms", duration_ms)
                    span.set_attribute("postureiq.llm.status", "error")
                    span.set_attribute("postureiq.llm.error", str(e))
                    span.set_status(StatusCode.ERROR, str(e))
                    span.record_exception(e)

                    logger.error(
                        "llm.call.error",
                        model=model_name,
                        duration_ms=round(duration_ms, 2),
                        error=str(e),
                    )
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator


def trace_session(session_id: str) -> Callable[[F], F]:
    """Decorator that wraps an entire agent session in a parent span.

    All tool and LLM spans within the session will be correlated under
    this parent trace, providing full end-to-end visibility.

    Usage:
        @trace_session("session-abc123")
        async def run_session() -> dict:
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(
                name="session",
                attributes={
                    "postureiq.session.id": session_id,
                    "postureiq.session.type": "assessment",
                },
            ) as span:
                start_time = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                    duration_ms = (time.monotonic() - start_time) * 1000

                    span.set_attribute("postureiq.session.duration_ms", duration_ms)
                    span.set_attribute("postureiq.session.status", "completed")
                    span.set_status(StatusCode.OK)

                    logger.info(
                        "session.completed",
                        session_id=session_id,
                        duration_ms=round(duration_ms, 2),
                    )
                    return result

                except Exception as e:
                    duration_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute("postureiq.session.duration_ms", duration_ms)
                    span.set_attribute("postureiq.session.status", "error")
                    span.set_status(StatusCode.ERROR, str(e))
                    span.record_exception(e)

                    logger.error(
                        "session.error",
                        session_id=session_id,
                        duration_ms=round(duration_ms, 2),
                        error=str(e),
                    )
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator


# ── GenAI Agent-invocation span ───────────────────────────


@contextlib.asynccontextmanager
async def trace_agent_invocation(
    session_id: str,
    *,
    agent_name: str = "PostureIQ",
    agent_description: str = "ME5 Security Posture Assessment Agent",
    model: str = "gpt-4o",
) -> AsyncIterator[trace.Span]:
    """Async context manager that creates an ``invoke_agent`` span.

    Wraps one user-turn through the agent so it appears in the
    App Insights **Agent (preview)** → *Agent Runs* panel.

    GenAI attributes emitted:
      - ``gen_ai.system``              = ``"openai"``
      - ``gen_ai.operation.name``      = ``"invoke_agent"``
      - ``gen_ai.agent.name``          = *agent_name*
      - ``gen_ai.agent.description``   = *agent_description*
      - ``gen_ai.conversation.id``     = *session_id*
      - ``gen_ai.request.model``       = *model*

    Usage::

        async with trace_agent_invocation(session_id="sess-1") as span:
            result = await run_tools(message)
            span.set_attribute("postureiq.tools_called", len(tools))
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(
        name=f"invoke_agent {agent_name}",
        kind=SpanKind.CLIENT,
        attributes={
            # GenAI semantic conventions (Agent blade → Agent Runs)
            _GENAI_SYSTEM: "openai",
            _GENAI_OPERATION_NAME: "invoke_agent",
            _GENAI_AGENT_NAME: agent_name,
            _GENAI_AGENT_DESCRIPTION: agent_description,
            _GENAI_CONVERSATION_ID: session_id,
            _GENAI_REQUEST_MODEL: model,
            # PostureIQ-specific
            "postureiq.session.id": session_id,
            "postureiq.session.type": "assessment",
        },
    ) as span:
        start_time = time.monotonic()
        try:
            yield span
            duration_ms = (time.monotonic() - start_time) * 1000
            span.set_attribute("postureiq.session.duration_ms", duration_ms)
            span.set_status(StatusCode.OK)
            logger.info(
                "agent.invocation.completed",
                session_id=session_id,
                duration_ms=round(duration_ms, 2),
            )
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            span.set_attribute("postureiq.session.duration_ms", duration_ms)
            span.set_status(StatusCode.ERROR, str(e))
            span.record_exception(e)
            logger.error(
                "agent.invocation.error",
                session_id=session_id,
                duration_ms=round(duration_ms, 2),
                error=str(e),
            )
            raise


@contextlib.contextmanager
def trace_genai_tool_call(tool_name: str):
    """Synchronous context manager for a lightweight ``execute_tool`` span.

    Use this when you call a tool *outside* the ``@trace_tool_call`` decorator
    path (e.g. in the chat HTTP handler's direct-mode dispatcher).
    """
    tracer = get_tracer()
    tool_call_id = str(uuid.uuid4())
    with tracer.start_as_current_span(
        name=f"execute_tool {tool_name}",
        kind=SpanKind.INTERNAL,
        attributes={
            _GENAI_SYSTEM: "openai",
            _GENAI_OPERATION_NAME: "execute_tool",
            _GENAI_TOOL_NAME: tool_name,
            _GENAI_TOOL_CALL_ID: tool_call_id,
            "postureiq.tool.name": tool_name,
        },
    ) as span:
        yield span
