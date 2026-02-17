# guardrail-ci

Secure-by-Design CI guardrail for modern repositories. `guardrail-ci` scans code/IaC/dependency posture, applies policy gates, supports baseline suppressions with expiry, and can optionally use an **OpenAI-compatible model** to improve triage.

## What it does (v0.3)
- CLI scanner (`guardrail-ci scan`)
- Detector categories:
  - ✅ Secrets
  - ✅ IaC misconfiguration checks
  - ✅ Dependency posture checks (lockfile hygiene)
- ✅ Baseline suppression lifecycle (reason + expiry)
- ✅ PR-focused diff scanning (`--diff-base`)
- ✅ Reports: JSON + Markdown + SARIF
- ✅ GitHub Security upload-ready workflow
- Optional AI triage (OpenAI-compatible endpoint)

## Installation
```bash
cd career-project/guardrail-ci
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Quickstart
```bash
guardrail-ci scan --path . --policy examples/guardrail.yml
```

Generate SARIF too:
```bash
guardrail-ci scan \
  --path . \
  --policy examples/guardrail.yml \
  --json-out guardrail-report.json \
  --md-out guardrail-report.md \
  --sarif-out guardrail-report.sarif
```

## Baseline suppressions (expiry + reason)
Create baseline from current findings:
```bash
guardrail-ci scan --path . --write-baseline
```

Use baseline in normal scans:
```bash
guardrail-ci scan --path . --baseline .guardrail-baseline.yml
```

Strict expiry mode (fail when expired suppressions exist):
```bash
guardrail-ci scan --path . --baseline .guardrail-baseline.yml --baseline-strict-expiry
```

Example baseline format:
```yaml
version: 1
suppressions:
  - id: GR-SEC-003
    file: src/config.py
    line: 42
    fingerprint: 7b2a8f0d...
    reason: Legacy token pending migration
    expires_at: "2026-04-01"
    created_by: "@deadmafia"
    created_at: "2026-02-17"
```

## PR changed-files mode
Limit scanning to files changed from a base ref:
```bash
guardrail-ci scan --path . --policy examples/guardrail.yml --diff-base origin/main
```

Notes:
- Content detectors (secrets/IaC) are diff-scoped.
- Dependency posture checks remain repo-level by design.
- Ensure CI fetches enough git history (`fetch-depth: 0`).

## GitHub Security (SARIF upload)
Workflow example in `.github/workflows/guardrail-demo.yml` includes:
- `permissions.security-events: write`
- SARIF generation
- `github/codeql-action/upload-sarif@v3`

Minimal upload snippet:
```yaml
permissions:
  contents: read
  security-events: write

- name: Run guardrail scan
  run: guardrail-ci scan --path . --policy examples/guardrail.yml --sarif-out guardrail-report.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardrail-report.sarif
```

## Exit codes
- `0` = policy passed
- `1` = policy failed
- `2` = invalid input/config/git-diff error

## Run tests
```bash
pytest -q
```
