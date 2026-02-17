from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import yaml


DEFAULT_POLICY = {
    "fail_on": {
        "critical": 1,
        "high": 9999,
        "medium": 9999,
        "low": 9999,
    },
    "exclude_paths": [
        ".git/**",
        "node_modules/**",
        ".venv/**",
        "venv/**",
        "__pycache__/**",
    ],
}


@dataclass
class PolicyConfig:
    fail_on: dict[str, int]
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class AiSettings:
    mode: str  # auto|on|off
    enabled: bool
    base_url: str | None
    api_key: str | None
    model: str | None
    timeout_seconds: int
    max_findings: int


def load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE pairs from a .env file without overriding existing env."""
    if not path.exists() or not path.is_file():
        return

    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_policy(path: str | None) -> PolicyConfig:
    if not path:
        return PolicyConfig(
            fail_on=DEFAULT_POLICY["fail_on"].copy(),
            exclude_paths=list(DEFAULT_POLICY["exclude_paths"]),
        )

    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    data = yaml.safe_load(policy_path.read_text()) or {}
    fail_on = DEFAULT_POLICY["fail_on"].copy()
    fail_on.update((data.get("fail_on") or {}))

    exclude_paths = list(DEFAULT_POLICY["exclude_paths"])
    user_excludes = data.get("exclude_paths") or []
    if isinstance(user_excludes, list):
        exclude_paths.extend([str(x) for x in user_excludes])

    return PolicyConfig(fail_on=fail_on, exclude_paths=exclude_paths)


def load_ai_settings(ai_mode_override: str = "auto") -> AiSettings:
    env_mode = (os.getenv("GUARDRAIL_AI_MODE", "auto") or "auto").strip().lower()
    mode = (ai_mode_override or "auto").strip().lower()
    if mode == "auto":
        mode = env_mode

    if mode not in {"auto", "on", "off"}:
        mode = "auto"

    enabled = mode != "off"

    return AiSettings(
        mode=mode,
        enabled=enabled,
        base_url=os.getenv("OPENAI_BASE_URL"),
        api_key=os.getenv("OPENAI_API_KEY"),
        model=os.getenv("OPENAI_MODEL"),
        timeout_seconds=int(os.getenv("GUARDRAIL_AI_TIMEOUT_SECONDS", "25") or "25"),
        max_findings=int(os.getenv("GUARDRAIL_AI_MAX_FINDINGS", "40") or "40"),
    )
