"""OpenAI-compatible tool-calling client and deterministic test double."""
from dataclasses import dataclass, field
import json
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

    def chat(self, messages: list[dict], tools: list[dict]) -> AssistantTurn:
        if not self.api_url or not self.api_key:
            raise RuntimeError("Agent LLM is not configured")
        mode = self.mode
        if mode == "native":
            try:
                return self._request(messages, tools, native=True)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 400:
                    raise
                mode = "json"
        return self._request(messages, tools, native=False)

    def _request(self, messages, tools, native):
        body = {"model": self.model, "messages": messages, "temperature": 0}
        if native:
            body.update({"tools": tools, "tool_choice": "auto"})
        else:
            tool_names = [item["function"]["name"] for item in tools]
            body["messages"] = [*messages, {"role": "system", "content":
                "If a tool is needed, respond with exactly {\"tool\": name, \"args\": object}. "
                "Otherwise respond with exactly {\"final\": report_object}. Available tools: "
                + json.dumps(tool_names)}]
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_error = None
        for attempt in range(2):
            try:
                with self.client_factory(timeout=45.0) as client:
                    response = client.post(self.api_url, headers=headers, json=body)
                if response.status_code in {429, 500, 502, 503, 504} and attempt == 0:
                    time.sleep(0.15)
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
                if attempt == 0:
                    time.sleep(0.15)
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

    def chat(self, messages, tools):
        self.calls.append({"messages": messages, "tools": tools})
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
