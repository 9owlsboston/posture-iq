"""SecPostureIQ — Streaming chat endpoint (SSE) backed by Azure OpenAI.

Provides ``POST /chat/stream`` which sends Server-Sent Events as the LLM
processes the request:
  - ``tool_start``   — a tool is about to be invoked
  - ``tool_result``  — tool completed with result summary
  - ``token``        — a single content token from the LLM
  - ``done``         — final aggregated response with metadata
  - ``error``        — something went wrong

The existing SPA (``index.html``) consumes these events to display
real-time tool-call visualization and streamed responses while
preserving all existing UI features (auth, quick actions, consent).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from typing import Any, cast

import structlog
from openai import AsyncAzureOpenAI
from openai.types.chat import (
    ChatCompletionMessageParam,
    ChatCompletionToolParam,
)

from src.agent.config import settings
from src.agent.system_prompt import SYSTEM_PROMPT
from src.api.chat import _run_tool
from src.tools.definitions import TOOL_SCHEMAS

logger = structlog.get_logger(__name__)

_MAX_HISTORY_TURNS = 20


def _get_openai_client() -> AsyncAzureOpenAI:
    """Build the Azure OpenAI async client."""
    if settings.azure_openai_api_key:
        return AsyncAzureOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
            api_key=settings.azure_openai_api_key,
        )
    from azure.identity.aio import (  # noqa: PLC0415
        DefaultAzureCredential,
        get_bearer_token_provider,
    )

    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
    return AsyncAzureOpenAI(
        azure_endpoint=settings.azure_openai_endpoint,
        api_version=settings.azure_openai_api_version,
        azure_ad_token_provider=token_provider,
    )


# ── In-memory session store for LLM conversation history ──────────────────
_llm_sessions: dict[str, dict[str, Any]] = {}


def _sse_event(event: str, data: dict[str, Any]) -> str:
    """Format a Server-Sent Event line."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def stream_chat(
    message: str,
    session_id: str | None = None,
    graph_token: str = "",
) -> AsyncGenerator[str, None]:
    """Stream an LLM-powered chat response as SSE events.

    Yields SSE-formatted strings. The caller should wrap this in a
    ``StreamingResponse(media_type="text/event-stream")``.
    """
    sid = session_id or str(uuid.uuid4())

    # Initialise or retrieve session
    if sid not in _llm_sessions:
        _llm_sessions[sid] = {
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}],
            "results": {},
        }
    session = _llm_sessions[sid]
    messages: list[dict[str, Any]] = session["messages"]
    results: dict[str, Any] = session["results"]

    messages.append({"role": "user", "content": message})

    # Trim to fit token budget
    messages = _trim_messages(messages)

    tools_called: list[str] = []
    full_content = ""

    try:
        client = _get_openai_client()
    except Exception as e:
        logger.error("chat_stream.client_error", error=str(e))
        yield _sse_event("error", {"message": f"OpenAI client error: {e}"})
        return

    # Function-calling loop
    max_iterations = 10
    for _ in range(max_iterations):
        try:
            response = await client.chat.completions.create(
                model=settings.azure_openai_deployment,
                messages=cast(list[ChatCompletionMessageParam], messages),
                tools=cast(list[ChatCompletionToolParam], TOOL_SCHEMAS),
                stream=True,
            )
        except Exception as e:
            logger.error("chat_stream.openai_error", error=str(e))
            yield _sse_event("error", {"message": str(e)})
            return

        # Collect streamed response
        tool_calls_map: dict[int, dict[str, Any]] = {}
        content_parts: list[str] = []

        async for chunk in response:
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta is None:
                continue

            if delta.content:
                content_parts.append(delta.content)
                yield _sse_event("token", {"token": delta.content})

            if delta.tool_calls:
                for tc_chunk in delta.tool_calls:
                    idx = tc_chunk.index
                    if idx not in tool_calls_map:
                        tool_calls_map[idx] = {
                            "id": tc_chunk.id or "",
                            "name": (tc_chunk.function.name or "") if tc_chunk.function else "",
                            "arguments": "",
                        }
                    else:
                        if tc_chunk.id:
                            tool_calls_map[idx]["id"] = tc_chunk.id
                        if tc_chunk.function and tc_chunk.function.name:
                            tool_calls_map[idx]["name"] = tc_chunk.function.name
                    if tc_chunk.function and tc_chunk.function.arguments:
                        tool_calls_map[idx]["arguments"] += tc_chunk.function.arguments

        content = "".join(content_parts)

        if not tool_calls_map:
            # Final response — no more tool calls
            full_content = content
            messages.append({"role": "assistant", "content": content})
            break

        # Record tool-call assistant message
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["name"], "arguments": tc["arguments"]},
                    }
                    for tc in (tool_calls_map[i] for i in sorted(tool_calls_map))
                ],
            }
        )

        # Execute tool calls
        for tc_data in (tool_calls_map[i] for i in sorted(tool_calls_map)):
            tool_name = tc_data["name"]
            try:
                tool_args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
            except json.JSONDecodeError:
                tool_args = {}

            # Inject prior assessment context for remediation/scorecard tools
            if tool_name in ("generate_remediation_plan", "create_adoption_scorecard") and (
                "assessment_context" not in tool_args or not tool_args["assessment_context"]
            ):
                tool_args["assessment_context"] = json.dumps(results, default=str)

            yield _sse_event("tool_start", {"tool": tool_name})

            try:
                result = await _run_tool(tool_name, tool_args, graph_token)
                results[tool_name] = result
                tools_called.append(tool_name)
                yield _sse_event("tool_result", {"tool": tool_name, "success": True})
            except Exception as e:
                logger.error("chat_stream.tool_error", tool=tool_name, error=str(e))
                result = {"error": str(e)}
                yield _sse_event("tool_result", {"tool": tool_name, "success": False, "error": str(e)})

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc_data["id"],
                    "content": json.dumps(result, default=str),
                }
            )

    # Determine data source
    data_source = "mock"
    for r in results.values():
        if isinstance(r, dict) and r.get("data_source") not in ("mock", None):
            data_source = "live"
            break

    # Persist session
    session["messages"] = messages
    session["results"] = results

    yield _sse_event(
        "done",
        {
            "session_id": sid,
            "tools_called": tools_called,
            "data_source": data_source,
            "response": full_content,
        },
    )


def _trim_messages(messages: list[dict[str, Any]], max_turns: int = _MAX_HISTORY_TURNS) -> list[dict[str, Any]]:
    """Keep system prompt + last N user turns."""
    if len(messages) <= 1:
        return messages
    system = messages[0] if messages[0].get("role") == "system" else None
    rest = messages[1:] if system else messages
    user_indices = [i for i, m in enumerate(rest) if m.get("role") == "user"]
    if len(user_indices) <= max_turns:
        return messages
    cutoff_idx = user_indices[-max_turns]
    trimmed = rest[cutoff_idx:]
    return [system] + trimmed if system else trimmed
