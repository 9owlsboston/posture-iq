"""SecPostureIQ — Chainlit conversational chat UI backed by Azure OpenAI.

This module implements the LLM-based chat mode (``CHAT_MODE=llm``) using
Chainlit for the web interface and Azure OpenAI function calling for
intelligent tool selection.

Architecture:
    Browser → Chainlit UI (WebSocket) → @cl.on_message
        → Azure OpenAI (GPT-4o, function calling)
        → _run_tool() (existing tool functions)
        → Azure OpenAI (compose final response)
        → cl.Message.stream_token() → Browser

Run standalone:
    CHAT_MODE=llm chainlit run src/chainlit_app.py

Or mounted inside FastAPI (see src/api/app.py).
"""

from __future__ import annotations

import json
from typing import Any, cast

import chainlit as cl
import structlog
from openai import AsyncAzureOpenAI
from openai.types.chat import (
    ChatCompletionMessageParam,
    ChatCompletionMessageToolCall,
    ChatCompletionToolParam,
)
from openai.types.chat.chat_completion_message_tool_call import Function

from src.agent.config import settings
from src.agent.system_prompt import SYSTEM_PROMPT
from src.api.chat import _run_tool
from src.middleware.tracing import trace_agent_invocation
from src.tools.definitions import TOOL_SCHEMAS

logger = structlog.get_logger(__name__)

# ── Maximum conversation history turns to keep (to fit token budget) ──────
_MAX_HISTORY_TURNS = 20


def _get_openai_client() -> AsyncAzureOpenAI:
    """Build the Azure OpenAI async client using app settings."""
    if settings.azure_openai_api_key:
        return AsyncAzureOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
            api_key=settings.azure_openai_api_key,
        )
    # Use DefaultAzureCredential (Managed Identity)
    from azure.identity.aio import DefaultAzureCredential, get_bearer_token_provider  # noqa: PLC0415

    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
    return AsyncAzureOpenAI(
        azure_endpoint=settings.azure_openai_endpoint,
        api_version=settings.azure_openai_api_version,
        azure_ad_token_provider=token_provider,
    )


def _trim_messages(messages: list[dict[str, Any]], max_turns: int = _MAX_HISTORY_TURNS) -> list[dict[str, Any]]:
    """Trim conversation history to fit within the token budget.

    Keeps the system prompt (first message) and the most recent ``max_turns``
    user/assistant pairs.  Tool-call and tool-result messages that are part
    of a kept turn are also retained.
    """
    if len(messages) <= 1:
        return messages

    system = messages[0] if messages[0].get("role") == "system" else None
    rest = messages[1:] if system else messages

    # Count user messages to determine how many turns to keep
    user_indices = [i for i, m in enumerate(rest) if m.get("role") == "user"]

    if len(user_indices) <= max_turns:
        return messages

    # Keep messages from the (len - max_turns)th user message onwards
    cutoff_idx = user_indices[-max_turns]
    trimmed = rest[cutoff_idx:]

    if system:
        return [system] + trimmed
    return trimmed


async def _collect_stream(
    response: Any,
) -> tuple[list[ChatCompletionMessageToolCall], str]:
    """Collect a streaming OpenAI response into tool_calls and content.

    Returns:
        A tuple of (tool_calls_list, content_text).
    """
    tool_calls_map: dict[int, dict[str, Any]] = {}  # index → partial tool call
    content_parts: list[str] = []

    async for chunk in response:
        delta = chunk.choices[0].delta if chunk.choices else None
        if delta is None:
            continue

        # Accumulate content tokens
        if delta.content:
            content_parts.append(delta.content)

        # Accumulate tool call fragments
        if delta.tool_calls:
            for tc_chunk in delta.tool_calls:
                idx = tc_chunk.index
                if idx not in tool_calls_map:
                    tool_calls_map[idx] = {
                        "id": tc_chunk.id or "",
                        "type": "function",
                        "function": {
                            "name": tc_chunk.function.name or "" if tc_chunk.function else "",
                            "arguments": "",
                        },
                    }
                else:
                    if tc_chunk.id:
                        tool_calls_map[idx]["id"] = tc_chunk.id
                    if tc_chunk.function and tc_chunk.function.name:
                        tool_calls_map[idx]["function"]["name"] = tc_chunk.function.name

                if tc_chunk.function and tc_chunk.function.arguments:
                    tool_calls_map[idx]["function"]["arguments"] += tc_chunk.function.arguments

    # Convert accumulated map to ChatCompletionMessageToolCall objects
    tool_calls: list[ChatCompletionMessageToolCall] = []
    for _idx in sorted(tool_calls_map):
        tc_data = tool_calls_map[_idx]
        tool_calls.append(
            ChatCompletionMessageToolCall(
                id=tc_data["id"],
                type="function",
                function=Function(
                    name=tc_data["function"]["name"],
                    arguments=tc_data["function"]["arguments"],
                ),
            )
        )

    return tool_calls, "".join(content_parts)


# ── Chainlit Event Handlers ──────────────────────────────────────────────


@cl.on_chat_start
async def on_start() -> None:
    """Initialize a new chat session with the system prompt."""
    cl.user_session.set(
        "messages",
        [{"role": "system", "content": SYSTEM_PROMPT}],
    )
    cl.user_session.set("results", {})

    await cl.Message(
        content=(
            "🛡️ **SecPostureIQ** ready. Ask me about your tenant's ME5 security posture.\n\n"
            'Try: *"Assess this tenant\'s ME5 security posture"* for a full assessment.'
        ),
    ).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    """Handle an incoming user message with Azure OpenAI function calling."""
    messages: list[dict[str, Any]] = cl.user_session.get("messages")
    results: dict[str, Any] = cl.user_session.get("results")
    graph_token: str = cl.user_session.get("graph_token") or ""

    messages.append({"role": "user", "content": message.content})

    # Trim history to stay within token budget
    messages = _trim_messages(messages)

    # Check for Azure OpenAI availability
    if not settings.azure_openai_endpoint:
        await _fallback_keyword_mode(message, messages, results, graph_token)
        return

    try:
        client = _get_openai_client()
    except Exception as e:
        logger.error("chainlit.openai_client.error", error=str(e))
        await _fallback_keyword_mode(message, messages, results, graph_token)
        return

    tools_called: list[str] = []

    async with trace_agent_invocation(session_id="chainlit", model=settings.resolved_default_model) as agent_span:
        # Function-calling loop — iterate until LLM produces a final response
        max_iterations = 10  # safety limit
        for _ in range(max_iterations):
            try:
                response = await client.chat.completions.create(
                    model=settings.resolved_default_model,
                    messages=cast(list[ChatCompletionMessageParam], messages),
                    tools=cast(list[ChatCompletionToolParam], TOOL_SCHEMAS),
                    stream=True,
                )
            except Exception as e:
                logger.error("chainlit.openai.error", error=str(e))
                # Fallback to keyword mode on LLM failure
                await _fallback_keyword_mode(message, messages, results, graph_token)
                return

            tool_calls, content = await _collect_stream(response)

            if not tool_calls:
                # Final response — send to user
                final_msg = cl.Message(content=content or "I couldn't generate a response. Please try again.")
                await final_msg.send()
                messages.append({"role": "assistant", "content": content})
                break

            # Record the assistant message with tool_calls
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                }
            )

            # Execute each tool call with cl.Step visualization
            for tc in tool_calls:
                tool_name = tc.function.name
                try:
                    tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    tool_args = {}

                # For remediation/scorecard tools, inject prior results as context
                if tool_name in ("generate_remediation_plan", "create_adoption_scorecard") and (
                    "assessment_context" not in tool_args or not tool_args["assessment_context"]
                ):
                    tool_args["assessment_context"] = json.dumps(results, default=str)

                async with cl.Step(name=tool_name, type="tool") as step:
                    step.input = json.dumps(tool_args, indent=2, default=str)
                    try:
                        result = await _run_tool(tool_name, tool_args, graph_token)
                        results[tool_name] = result
                        tools_called.append(tool_name)
                        step.output = json.dumps(result, indent=2, default=str)
                    except Exception as e:
                        logger.error("chainlit.tool.error", tool=tool_name, error=str(e))
                        result = {"error": str(e)}
                        step.output = f"Error: {e}"
                        step.is_error = True

                # Append tool result to messages
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, default=str),
                    }
                )

        agent_span.set_attribute("secpostureiq.tools_called", len(tools_called))

    # Persist updated state
    cl.user_session.set("messages", messages)
    cl.user_session.set("results", results)


async def _fallback_keyword_mode(
    message: cl.Message,
    messages: list[dict[str, Any]],
    results: dict[str, Any],
    graph_token: str,
) -> None:
    """Fall back to keyword-based intent classification when LLM is unavailable."""
    from src.api.chat import ChatRequest, handle_chat  # noqa: PLC0415

    banner = "⚠️ *LLM unavailable — using keyword matching.*\n\n"

    request = ChatRequest(message=message.content)
    response = await handle_chat(request, graph_token=graph_token)

    reply = cl.Message(content=banner + response.response)
    await reply.send()

    messages.append({"role": "assistant", "content": response.response})
    cl.user_session.set("messages", messages)
