# guardrail-ci

Secure-by-Design CI guardrail for modern repositories. `guardrail-ci` scans code/IaC/dependency posture, applies policy gates, and can optionally use an **OpenAI-compatible model** to improve severity triage.

## What it does
- CLI scanner (`guardrail-ci scan`)
- Detector categories:
  - ✅ Secrets (implemented)
  - ✅ IaC misconfiguration checks (implemented)
  - ✅ Dependency posture checks (lockfile hygiene)
- Optional AI triage (OpenAI-compatible endpoint)
- Policy gating (CI-friendly exit codes)
- Reports: JSON + Markdown + SARIF
- GitHub Actions integration example

## Requirements
- Python 3.10+
- pip

Optional for AI mode:
- OpenAI-compatible API endpoint + key + model

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

## AI mode (OpenAI-compatible)
1. Copy env template:
```bash
cp .env.example .env
```
2. Fill:
- `OPENAI_BASE_URL`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`

3. Run with AI mode:
```bash
guardrail-ci scan --path . --policy examples/guardrail.yml --ai-mode auto
```

Modes:
- `auto` (default): use AI if configured, otherwise fallback to rules
- `on`: try AI; fallback still preserved for reliability
- `off`: rules-only mode

## Exit codes
- `0` = policy passed
- `1` = policy failed
- `2` = invalid input/path

## Example policy config
See `examples/guardrail.yml`:
```yaml
fail_on:
  critical: 1
  high: 2
  medium: 5
  low: 9999
exclude_paths:
  - tests/fixtures/**
```

## Implemented checks (v0.2)

### Secrets
- `GR-SEC-001`: AWS Access Key pattern (`AKIA...`)
- `GR-SEC-002`: Private key block
- `GR-SEC-003`: Generic hardcoded token/api-key assignment

### IaC
- `GR-IAC-001`: Terraform admin ports exposed to `0.0.0.0/0`
- `GR-IAC-002`: `privileged: true` in YAML manifests

### Dependency posture
- `GR-DEP-001`: JavaScript manifest without lockfile
- `GR-DEP-002`: Python manifest without lockfile

## GitHub Actions usage
Workflow example: `.github/workflows/guardrail-demo.yml`

Minimal snippet:
```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'
- run: pip install .
- run: guardrail-ci scan --path . --policy examples/guardrail.yml --sarif-out guardrail-report.sarif
```

## Run tests
```bash
pytest -q
```

## Notes / limitations
- This is a fast heuristic guardrail, not a full SAST platform.
- AI triage is advisory/re-ranking logic; core deterministic checks remain the base.
- Dependency scanning is posture-focused in v0.2 (full CVE DB integration next).
