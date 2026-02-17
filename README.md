# guardrail-ci

Secure-by-Design CI guardrail for modern repositories. `guardrail-ci` scans code/IaC/dependency posture, generates reports, and enforces policy gates with CI-friendly exit codes.

## MVP scope
- CLI scanner (`guardrail-ci scan`)
- Detector categories:
  - ✅ **Secrets** (implemented)
  - ✅ **IaC** (implemented basic Terraform/K8s patterns)
  - ⚠️ **Dependency** posture checks (implemented baseline lockfile hygiene; advisory DB integration is a placeholder)
- Policy gating (non-zero exit on failure)
- Reports: **JSON + Markdown**
- GitHub Actions integration example
- Tests for core detector + policy logic

## Install
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

Outputs by default:
- `guardrail-report.json`
- `guardrail-report.md`

Exit codes:
- `0` = policy passed
- `1` = policy failed
- `2` = invalid input/path

## CLI options
```bash
guardrail-ci scan \
  --path . \
  --policy examples/guardrail.yml \
  --json-out guardrail-report.json \
  --md-out guardrail-report.md
```

## Example policy config
See `examples/guardrail.yml`:
```yaml
fail_on:
  critical: 1
  high: 2
  medium: 5
  low: 9999
```

## Implemented checks (MVP)

### Secrets (real implemented check set)
- `GR-SEC-001`: AWS Access Key pattern (`AKIA...`)
- `GR-SEC-002`: Private key block in source
- `GR-SEC-003`: Generic hardcoded token/api-key assignment pattern

### IaC
- `GR-IAC-001`: Terraform ingress exposing admin ports to `0.0.0.0/0`
- `GR-IAC-002`: `privileged: true` in YAML manifests

### Dependency posture (baseline)
- `GR-DEP-001`: JavaScript manifest present without lockfile
- `GR-DEP-002`: Python manifest present without lockfile

## GitHub Action integration
Example workflow is in `.github/workflows/guardrail-demo.yml`.

Minimal usage snippet:
```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'
- run: pip install .
- run: guardrail-ci scan --path . --policy examples/guardrail.yml
```

## Run tests
```bash
pytest
```

## Notes / limitations
- This is a fast, heuristic MVP and **not** a full SAST platform.
- Dependency checks are posture-oriented in v0.1.0; CVE/advisory enrichment planned next.
- No suppression/baselining yet.

## Roadmap (next)
1. SARIF output for GitHub code scanning annotations
2. Advisory DB integration for dependency vulnerabilities
3. Baseline suppression file (`.guardrail-baseline.json`)
4. Rule mapping to NIST SSDF and Secure-by-Design controls
