from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import yaml


DEFAULT_POLICY = {
    "fail_on": {
        "critical": 1,
        "high": 9999,
        "medium": 9999,
        "low": 9999,
    }
}


@dataclass
class PolicyConfig:
    fail_on: dict[str, int]



def load_policy(path: str | None) -> PolicyConfig:
    if not path:
        return PolicyConfig(fail_on=DEFAULT_POLICY["fail_on"].copy())

    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    data = yaml.safe_load(policy_path.read_text()) or {}
    fail_on = DEFAULT_POLICY["fail_on"].copy()
    fail_on.update((data.get("fail_on") or {}))
    return PolicyConfig(fail_on=fail_on)
