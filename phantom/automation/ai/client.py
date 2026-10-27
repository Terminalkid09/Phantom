"""client.py — model transports for the per-phase AI layer.

One protocol, three implementations:

* :class:`LocalClient` — a llama.cpp server (OpenAI-compatible) on the
  operator's box. Nothing leaves the machine.
* :class:`CloudClient` — any OpenAI-compatible endpoint. The credential is
  read from the environment variable whose NAME is configured; no literal
  token is stored here and none is ever logged.
* :class:`MockClient` — deterministic double for tests (no sockets).

Every transport returns ``(text, model_id)``. No transport executes
anything: the only side effect is one HTTP request.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Dict, List, Optional, Protocol, Sequence, Tuple, Union

Message = Dict[str, str]


class AIError(RuntimeError):
    """A typed AI transport/config failure (never carries a credential)."""


class AIClient(Protocol):
    """The one surface the router depends on."""

    model_id: str

    def chat(self, messages: Sequence[Message], *,
             schema_key: str = "",
             timeout: Optional[float] = None) -> Tuple[str, str]:
        ...


def _endpoint(base_url: str) -> str:
    """`/v1/chat/completions`, tolerating a base that already ends in /v1."""
    base = str(base_url or "").rstrip("/")
    if not base:
        raise AIError("ai endpoint is not configured")
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def _post_chat(base_url: str, api_key: str, model: str, messages,
               timeout: float) -> str:
    """One OpenAI-compatible POST, stdlib only."""
    import urllib.error
    import urllib.request

    payload = json.dumps({
        "model": model or "default",
        "messages": [{"role": m.get("role", "user"),
                      "content": m.get("content", "")} for m in messages],
        "temperature": 0.2,
        "max_tokens": 800,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(_endpoint(base_url), data=payload,
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        # the body may echo the prompt: the status is enough for the caller
        raise AIError(f"http {exc.code} from model endpoint") from None
    except urllib.error.URLError as exc:
        raise AIError(f"model endpoint unreachable: {exc.reason}") from None
    except (TimeoutError, OSError) as exc:
        raise AIError(f"model endpoint failed: {exc}") from None
    try:
        return str(body["choices"][0]["message"]["content"] or "")
    except (KeyError, IndexError, TypeError):
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, dict) and isinstance(result.get("response"), str):
            return result["response"]
        raise AIError("model endpoint returned no message content") from None


class LocalClient:
    """llama.cpp server transport (no data leaves the machine)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080",
                 model: str = "", timeout: float = 60.0) -> None:
        self.base_url = base_url
        self.model = model
        self.model_id = model or "local"
        self.timeout = timeout

    def chat(self, messages, *, schema_key="", timeout=None) -> Tuple[str, str]:
        text = _post_chat(self.base_url, "", self.model,
                          messages, timeout or self.timeout)
        return text, self.model_id


class CloudClient:
    """OpenAI-compatible endpoint authenticated by an env-var NAME."""

    def __init__(self, base_url: str = "", api_key_env: str = "",
                 model: str = "", timeout: float = 60.0) -> None:
        self.base_url = base_url
        self.api_key_env = api_key_env
        self.model = model
        self.model_id = model or "cloud"
        self.timeout = timeout

    def chat(self, messages, *, schema_key="", timeout=None) -> Tuple[str, str]:
        if not self.api_key_env:
            raise AIError("ai.cloud.api_key_env is not configured")
        key = os.getenv(self.api_key_env)
        if not key:
            # the NAME is safe to report; the value never exists here
            raise AIError(f"cloud credential not configured: {self.api_key_env}")
        text = _post_chat(self.base_url, key, self.model,
                          messages, timeout or self.timeout)
        return text, self.model_id


Scripted = Union[str, Dict[str, str], Callable[[Sequence[Message], str], str]]


class MockClient:
    """Deterministic test double.

    ``scripted`` may be a string (returned for every call), a dict keyed by
    schema name plus ``"default"``, or a callable ``(messages, schema) ->
    text`` (raise from it to exercise the error path). ``calls`` records the
    exact messages the router built, which is what the redaction tests
    inspect.
    """

    def __init__(self, scripted: Scripted = "", model_id: str = "mock") -> None:
        self.scripted = scripted
        self.model_id = model_id
        self.calls: List[List[Message]] = []

    def chat(self, messages, *, schema_key="", timeout=None) -> Tuple[str, str]:
        self.calls.append([dict(m) for m in messages])
        if callable(self.scripted):
            return str(self.scripted(messages, schema_key)), self.model_id
        if isinstance(self.scripted, dict):
            text = (self.scripted.get(schema_key)
                    or self.scripted.get("default") or "")
            return str(text), self.model_id
        return str(self.scripted or ""), self.model_id
