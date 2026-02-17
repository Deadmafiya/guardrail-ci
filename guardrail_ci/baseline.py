from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
import hashlib
import re

import yaml

from guardrail_ci.models import Finding


@dataclass(frozen=True)
class SuppressionEntry:
    id: str
    reason: str
    expires_at: date
    file: str | None = None
    line: int | None = None
    fingerprint: str | None = None
    created_by: str | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class Baseline:
    version: int
    suppressions: list[SuppressionEntry]


def normalize_evidence(evidence: str) -> str:
    return re.sub(r"\s+", " ", evidence.strip().lower())


def finding_fingerprint(finding: Finding) -> str:
    raw = "|".join(
        [
            finding.id,
            finding.file,
            str(finding.line or 0),
            normalize_evidence(finding.evidence),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_date(value: str) -> date:
    try:
        return datetime.fromisoformat(value).date()
    except ValueError as exc:
        raise ValueError(f"Invalid expires_at date '{value}' (expected YYYY-MM-DD)") from exc


def load_baseline(path: Path) -> Baseline:
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    data = yaml.safe_load(path.read_text()) or {}
    version = int(data.get("version", 1))
    raw_suppressions = data.get("suppressions") or []
    if not isinstance(raw_suppressions, list):
        raise ValueError("Baseline 'suppressions' must be a list")

    suppressions: list[SuppressionEntry] = []
    for idx, raw in enumerate(raw_suppressions, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Suppression #{idx} must be an object")

        sid = raw.get("id")
        reason = raw.get("reason")
        expires_raw = raw.get("expires_at")
        file = raw.get("file")
        line = raw.get("line")
        fingerprint = raw.get("fingerprint")

        if not sid or not isinstance(sid, str):
            raise ValueError(f"Suppression #{idx} missing required string field: id")
        if not reason or not isinstance(reason, str):
            raise ValueError(f"Suppression #{idx} missing required string field: reason")
        if not expires_raw or not isinstance(expires_raw, str):
            raise ValueError(f"Suppression #{idx} missing required string field: expires_at")
        if not fingerprint and not file:
            raise ValueError(
                f"Suppression #{idx} must include fingerprint or file for matching"
            )

        parsed_line: int | None = None
        if line is not None:
            try:
                parsed_line = int(line)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Suppression #{idx} has invalid line: {line}") from exc

        suppressions.append(
            SuppressionEntry(
                id=sid,
                reason=reason,
                expires_at=_parse_date(expires_raw),
                file=str(file) if file is not None else None,
                line=parsed_line,
                fingerprint=str(fingerprint) if fingerprint is not None else None,
                created_by=str(raw.get("created_by")) if raw.get("created_by") is not None else None,
                created_at=str(raw.get("created_at")) if raw.get("created_at") is not None else None,
            )
        )

    return Baseline(version=version, suppressions=suppressions)


def match_suppression(
    finding: Finding,
    suppressions: list[SuppressionEntry],
) -> SuppressionEntry | None:
    fp = finding.fingerprint or finding_fingerprint(finding)

    for s in suppressions:
        if s.fingerprint and s.fingerprint == fp:
            return s

    for s in suppressions:
        if s.id != finding.id:
            continue
        if s.file and s.file != finding.file:
            continue
        if s.line is not None and (finding.line or 0) != s.line:
            continue
        return s

    return None


def apply_baseline(
    findings: list[Finding],
    baseline: Baseline | None,
    today: date | None = None,
) -> tuple[list[Finding], int, int]:
    if baseline is None:
        return findings, 0, 0

    now = today or date.today()
    suppressed_total = 0
    expired_total = 0

    updated: list[Finding] = []
    for finding in findings:
        fp = finding.fingerprint or finding_fingerprint(finding)
        match = match_suppression(finding, baseline.suppressions)

        if not match:
            updated.append(
                finding.with_updates(
                    fingerprint=fp,
                    suppressed=False,
                    suppression_status="none",
                )
            )
            continue

        is_expired = match.expires_at < now
        if is_expired:
            expired_total += 1
            updated.append(
                finding.with_updates(
                    fingerprint=fp,
                    suppressed=False,
                    suppression_reason=match.reason,
                    suppression_expires_at=match.expires_at.isoformat(),
                    suppression_status="expired",
                )
            )
        else:
            suppressed_total += 1
            updated.append(
                finding.with_updates(
                    fingerprint=fp,
                    suppressed=True,
                    suppression_reason=match.reason,
                    suppression_expires_at=match.expires_at.isoformat(),
                    suppression_status="active",
                )
            )

    return updated, suppressed_total, expired_total


def generate_baseline(findings: list[Finding]) -> dict[str, Any]:
    today = date.today().isoformat()
    entries = []
    for f in findings:
        entries.append(
            {
                "id": f.id,
                "file": f.file,
                "line": f.line,
                "fingerprint": f.fingerprint or finding_fingerprint(f),
                "reason": "TODO: explain temporary suppression",
                "expires_at": "2099-12-31",
                "created_by": "@owner",
                "created_at": today,
            }
        )

    return {"version": 1, "suppressions": entries}


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = generate_baseline(findings)
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
