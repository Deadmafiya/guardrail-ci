from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import requests

from guardrail_ci.config import AiSettings
from guardrail_ci.models import Finding, sort_findings

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _chat_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if not text:
        return {}

    # Allow fenced JSON blocks
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)

    try:
        return json.loads(text)
    except Exception:
        # fallback: greedy object extraction
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return {}
        try:
            return json.loads(m.group(0))
        except Exception:
            return {}


def _context_window(path: Path, line: int | None, window: int = 2) -> str:
    if line is None or not path.exists() or not path.is_file():
        return ""
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return ""
    start = max(0, line - 1 - window)
    end = min(len(lines), line + window)
    snippet = []
    for idx in range(start, end):
        snippet.append(f"{idx + 1}: {lines[idx][:220]}")
    return "\n".join(snippet)


def _build_payload(root: Path, findings: list[Finding], max_findings: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for finding in findings[:max_findings]:
        fpath = root / finding.file
        out.append(
            {
                "id": finding.id,
                "file": finding.file,
                "line": finding.line,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "message": finding.message,
                "remediation": finding.remediation,
                "evidence": finding.evidence,
                "context": _context_window(fpath, finding.line),
            }
        )
    return out


def _build_messages(repo_path: Path, payload: list[dict[str, Any]]) -> list[dict[str, str]]:
    system = (
        "You are a senior application security triage assistant. "
        "Given findings from a repository scan, reassess severity and suggest concise remediation. "
        "Only return strict JSON with key 'decisions'."
    )
    user = {
        "repo": str(repo_path),
        "rules": {
            "allowed_severity": ["critical", "high", "medium", "low", "info"],
            "output_shape": {
                "decisions": [
                    {
                        "id": "string",
                        "file": "string",
                        "line": "number|null",
                        "severity": "critical|high|medium|low|info",
                        "rationale": "short string",
                        "remediation": "short string"
                    }
                ]
            }
        },
        "findings": payload,
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user)},
    ]


def _normalize_sev(value: str | None) -> str | None:
    if not value:
        return None
    sev = value.strip().lower()
    if sev in ALLOWED_SEVERITIES:
        return sev
    return None


def apply_ai_triage(root: Path, findings: list[Finding], settings: AiSettings) -> tuple[list[Finding], dict[str, Any]]:
    """Apply optional LLM triage to findings, returning updated findings + metadata."""
    if not settings.enabled:
        return findings, {"status": "disabled", "mode": settings.mode}

    if not findings:
        return findings, {"status": "skipped", "mode": settings.mode, "reason": "no_findings"}

    if not settings.base_url or not settings.api_key or not settings.model:
        return findings, {
            "status": "fallback",
            "mode": settings.mode,
            "reason": "missing_openai_config",
        }

    payload = _build_payload(root, findings, settings.max_findings)
    req_body = {
        "model": settings.model,
        "messages": _build_messages(root, payload),
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    try:
        resp = requests.post(
            _chat_url(settings.base_url),
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
            },
            json=req_body,
            timeout=settings.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()

        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = _extract_json(content)
        decisions = parsed.get("decisions") if isinstance(parsed, dict) else None
        if not isinstance(decisions, list):
            return findings, {
                "status": "fallback",
                "mode": settings.mode,
                "reason": "invalid_ai_response_shape",
            }

        indexed = {(f.id, f.file, f.line): f for f in findings}
        updated: dict[tuple[str, str, int | None], Finding] = {}
        applied = 0

        for item in decisions:
            if not isinstance(item, dict):
                continue
            key = (item.get("id"), item.get("file"), item.get("line"))
            if key not in indexed:
                continue

            base = indexed[key]
            sev = _normalize_sev(str(item.get("severity", ""))) or base.severity
            rationale = str(item.get("rationale") or "").strip()
            remediation = str(item.get("remediation") or "").strip() or base.remediation
            msg = base.message
            if rationale:
                msg = f"{base.message} AI triage: {rationale}"

            updated[key] = Finding(
                id=base.id,
                title=base.title,
                category=base.category,
                severity=sev,
                file=base.file,
                line=base.line,
                message=msg,
                remediation=remediation,
                evidence=base.evidence,
            )
            applied += 1

        merged: list[Finding] = []
        for finding in findings:
            merged.append(updated.get((finding.id, finding.file, finding.line), finding))

        return sort_findings(merged), {
            "status": "ok",
            "mode": settings.mode,
            "model": settings.model,
            "decisions_applied": applied,
            "requested_findings": len(payload),
        }

    except Exception as e:
        return findings, {
            "status": "fallback",
            "mode": settings.mode,
            "reason": "ai_request_failed",
            "error": str(e)[:220],
        }
