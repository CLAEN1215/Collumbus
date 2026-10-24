# Collumbus

A beginner-friendly, **read-only** AWS cloud configuration auditor written in Python.

> **Status: active development (Phase 6 of 7).** Core audit foundation, demo scanner,
> security rules, JSON/CSV reporting, 5-page Streamlit web dashboard, read-only AWS
> boto3 collector, static type safety (mypy), Bandit security scanning, and pip-audit CVE verification are complete. Not production-ready.

## Scope and limits

Collumbus is a **configuration auditor**. It is not a penetration-testing tool, antivirus,
or a complete cloud security platform. It does not detect every vulnerability, guarantee
security, or prove regulatory compliance. It reports only what its implemented rules and
the available evidence support. It never changes cloud resources.

## Implemented vs planned

| Feature | State |
|---|---|
| Validated Finding and Scan models, stable finding IDs | Implemented |
| `config/rules.yaml` validation | Implemented |
| Secret redaction in evidence and logs | Implemented |
| CLI: `validate-config`, `sample-finding` | Implemented |
| Demo scanner + checks S3-001, S3-002, IAM-001, CT-001 | Implemented |
| JSON / CSV reports & CSV injection defense | Implemented |
| Streamlit dashboard (5 pages) and scan history | Implemented |
| Read-only AWS scanning via boto3 | Implemented |
| Code hardening: PEP 561 typing, Mypy, Bandit, pip-audit | Implemented |

## Quick start (Windows PowerShell)

```powershell
cd C:\Projects\collumbus
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# If activation is blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements-dev.txt
pip install -e . --no-deps

# Validate configuration
python -m collumbus validate-config

# Run demo scan (no AWS account needed)
python -m collumbus demo-scan

# Launch web dashboard
python -m collumbus dashboard

# Run full test suite & security checks
python -m pytest
ruff check .
mypy src tests
bandit -r src
pip-audit
```
