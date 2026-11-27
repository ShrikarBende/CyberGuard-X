"""OpenAI-compatible tool-calling client and deterministic test double."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import random
import time
import httpx
from app.core.config import settings


@dataclass
class ToolCall:
    name: str
    arguments: dict | str
    call_id: str = ""


@dataclass
class AssistantTurn:
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    # Preserve provider-specific fields (for example GPT-OSS reasoning metadata)
    # so the next tool round can send back the assistant message unchanged.
    provider_message: dict = field(default_factory=dict)


class AgentLLM:
    def __init__(self, api_url=None, api_key=None, model=None, mode=None, client_factory=httpx.Client):
        self.api_url = api_url if api_url is not None else settings.AGENT_LLM_API_URL
        self.api_key = api_key if api_key is not None else settings.AGENT_LLM_API_KEY
        self.model = model or settings.AGENT_LLM_MODEL
        self.mode = mode or settings.AGENT_TOOL_MODE
        self.client_factory = client_factory
        self._native_unsupported = False

    def chat(self, messages: list[dict], tools: list[dict], timeout=None) -> AssistantTurn:
        if not self.api_url:
            raise RuntimeError("Agent LLM is not configured")
        timeout = 45.0 if timeout is None else max(0.001, float(timeout))
        mode = self.mode
        if mode == "native" and not self._native_unsupported:
            try:
                return self._request(messages, tools, native=True, timeout=timeout)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 400:
                    raise
                self._native_unsupported = True
                mode = "json"
        return self._request(messages, tools, native=False, timeout=timeout)

    @staticmethod
    def _retry_after(response):
        value = response.headers.get("Retry-After") if response is not None else None
        if not value:
            return None
        try:
            return min(20.0, max(0.0, float(value)))
        except (TypeError, ValueError):
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                return min(20.0, max(0.0, (when - datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                return None

    @staticmethod
    def _json_messages(messages):
        converted = []
        for message in messages:
            role = message.get("role")
            if role == "assistant" and message.get("tool_calls"):
                for call in message["tool_calls"]:
                    function = call.get("function") or {}
                    try:
                        args = json.loads(function.get("arguments", "{}"))
                    except (TypeError, json.JSONDecodeError):
                        args = {}
                    converted.append({"role": "assistant", "content": json.dumps({
                        "tool": function.get("name", ""), "args": args}, ensure_ascii=False)})
            elif role == "tool":
                content = str(message.get("content", ""))
                if "<untrusted_tool_result>" not in content:
                    content = content.replace("</untrusted_tool_result>", "&lt;/untrusted_tool_result&gt;")
                    content = f"<untrusted_tool_result>{content}</untrusted_tool_result>"
                converted.append({"role": "user", "content": content})
            else:
                converted.append({key: message[key] for key in ("role", "content") if key in message})
        return converted

    def _request(self, messages, tools, native, timeout=45.0):
        body = {"model": self.model, "messages": messages, "temperature": 0,
                "max_tokens": settings.AGENT_MAX_OUTPUT_TOKENS}
        if native:
            if tools:
                body.update({"tools": tools, "tool_choice": "auto"})
        else:
            tool_definitions = [{"name": item["function"]["name"],
                "description": item["function"].get("description", ""),
                "parameters": item["function"].get("parameters", {})} for item in tools]
            body["messages"] = [*self._json_messages(messages), {"role": "system", "content":
                "If a tool is needed, respond with exactly {\"tool\": name, \"args\": object}. "
                "Otherwise respond with exactly {\"final\": report_object}. Tool definitions and argument schemas: "
                + json.dumps(tool_definitions, ensure_ascii=False)}]
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        started = time.monotonic()
        last_error = None
        for attempt in range(3):
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise httpx.TimeoutException("Agent LLM retry budget exhausted")
            try:
                with self.client_factory(timeout=min(45.0, remaining)) as client:
                    response = client.post(self.api_url, headers=headers, json=body)
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt < 2:
                        delay = self._retry_after(response)
                        if delay is None:
                            delay = 0.5 * (2 ** attempt) * random.uniform(0.8, 1.2)
                        remaining = timeout - (time.monotonic() - started)
                        if delay >= remaining:
                            raise httpx.TimeoutException("Agent LLM retry budget exhausted")
                        time.sleep(min(20.0, delay))
                        continue
                response.raise_for_status()
                payload = response.json()
                message = payload["choices"][0]["message"]
                usage = payload.get("usage") or {}
                if native:
                    calls = []
                    for raw in message.get("tool_calls") or []:
                        function = raw.get("function") or {}
                        try:
                            args = json.loads(function.get("arguments", "{}"))
                            if not isinstance(args, dict):
                                raise ValueError("tool arguments must be an object")
                        except (json.JSONDecodeError, TypeError, ValueError):
                            args = {"__malformed_json": str(function.get("arguments", ""))[:2000]}
                        calls.append(ToolCall(str(function.get("name", "")), args, str(raw.get("id", ""))))
                    return AssistantTurn(message.get("content"), calls, usage, dict(message))
                content = message.get("content") or ""
                try:
                    command = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    return AssistantTurn(str(content), [], usage)
                if isinstance(command, dict) and isinstance(command.get("tool"), str):
                    args = command.get("args", {})
                    return AssistantTurn(None, [ToolCall(command["tool"], args if isinstance(args, dict) else {})], usage)
                if isinstance(command, dict) and isinstance(command.get("final"), dict):
                    return AssistantTurn(json.dumps(command["final"], ensure_ascii=False), [], usage)
                return AssistantTurn(str(content), [], usage)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt < 2:
                    delay = 0.5 * (2 ** attempt) * random.uniform(0.8, 1.2)
                    remaining = timeout - (time.monotonic() - started)
                    if delay >= remaining:
                        raise httpx.TimeoutException("Agent LLM retry budget exhausted") from exc
                    time.sleep(delay)
                    continue
                raise
        if last_error:
            raise last_error
        raise RuntimeError("Agent LLM request failed")


class FakeLLM:
    """A no-network scripted LLM used by offline tests and evaluation."""
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def chat(self, messages, tools, timeout=None):
        self.calls.append({"messages": messages, "tools": tools, "timeout": timeout})
        if not self.script:
            raise RuntimeError("FakeLLM script exhausted")
        turn = self.script.pop(0)
        if isinstance(turn, Exception):
            raise turn
        if isinstance(turn, AssistantTurn):
            return turn
        if isinstance(turn, dict):
            return AssistantTurn(**turn)
        return AssistantTurn(content=str(turn))
