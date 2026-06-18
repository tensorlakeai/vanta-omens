from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class VantaSettings:
    vanta_base_url: str
    vanta_client_id: str
    vanta_client_secret: str
    vanta_scope: str
    vanta_page_size: int
    vanta_asset_fetch_concurrency: int
    repository_urls: dict[str, str]

    @classmethod
    def from_env(cls) -> "VantaSettings":
        return cls(
            vanta_base_url=os.getenv("VANTA_BASE_URL", "https://api.vanta.com").strip().rstrip("/"),
            vanta_client_id=_required_env("VANTA_CLIENT_ID"),
            vanta_client_secret=_required_env("VANTA_CLIENT_SECRET"),
            vanta_scope=os.getenv("VANTA_SCOPE", "vanta-api.all:read").strip(),
            vanta_page_size=int(os.getenv("VANTA_PAGE_SIZE", "100")),
            vanta_asset_fetch_concurrency=int(os.getenv("VANTA_ASSET_FETCH_CONCURRENCY", "10")),
            repository_urls=_json_map(os.getenv("REPOSITORY_URLS_JSON", "{}")),
        )


@dataclass(frozen=True)
class AgentSettings:
    code_agent_model: str
    code_agent_command: str
    dry_run: bool

    @classmethod
    def from_env(cls) -> "AgentSettings":
        return cls(
            code_agent_model=os.getenv("CODE_AGENT_MODEL", "gpt-4.1-mini"),
            code_agent_command=os.getenv(
                "CODE_AGENT_COMMAND",
                "codex exec --model {model} --sandbox workspace-write - < {prompt_file}",
            ),
            dry_run=os.getenv("DRY_RUN", "false").lower() in {"1", "true", "yes"},
        )


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    value = value.strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _json_map(raw: str) -> dict[str, str]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("REPOSITORY_URLS_JSON must be a JSON object")
    return {str(key): str(value) for key, value in data.items()}
