# CLAUDE.md: Collumbus working agreement

Collumbus is a beginner-friendly, **read-only** AWS cloud configuration auditor (Python).
It is a learning and portfolio project for Lance (first-year BSIT, Network and Security).
It is a configuration auditor, not a pen-testing tool, antivirus, or compliance proof.

## Environment
- Windows. Give the user **PowerShell** commands, not bash.
- Python 3.14 in `.venv` (supports >=3.12). Activate: `.\.venv\Scripts\Activate.ps1`
  (if blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`).
- Never install packages globally. Package source lives in `src/collumbus/`.
- Test: `python -m pytest`  |  Lint: `ruff check .`  |  Format: `ruff format .`

## Non-negotiable principles
1. Working MVP before advanced features.
2. Simulated (demo) data first; no AWS account or cost needed to learn.
3. Demo and real AWS data share the same rule engine.
4. Use established SDKs (boto3); do not invent cloud integrations.
5. Readable, maintainable Python over clever code.
6. Never hardcode or store credentials, keys, or tokens.
7. Never create, modify, disable, or delete any cloud resource. No auto-remediation.
   Show human-readable fix instructions only.
8. API errors, missing permissions, throttling, and unknown states are never passes.
   They are Error/Unknown with incomplete coverage noted.
9. Never fabricate results, present simulated results as real, or merge demo and AWS
   findings without labeling the source.
10. Never claim a feature works or tests pass without running it and seeing real output.
11. Features too advanced for the current phase are documented and deferred.

## Working rules
1. Inspect before changing. State the next step before doing it.
2. Write tests alongside code; run them; fix failures before declaring a phase done.
3. Do not silently remove working functionality or rewrite working parts for style.
4. Never ask for AWS secret keys in chat. Use the standard credential chain/profiles.
5. Never perform paid, destructive, or modifying cloud operations.
6. Keep code simple enough for a beginner to understand. Keep docs in sync with code.
7. Local files and safe local commands are fine. Explain and get approval before
   installing dependencies or anything with external side effects.
8. Major architectural problem: explain it and propose the smallest reasonable fix.
9. Small Git commits at the end of each phase (never commit secrets); report the message.
10. Explain terms on first use; update `docs/LEARNING_GUIDE.md` every phase.

## Phase-gate workflow
Work one phase at a time. At the end of each phase: run tests, show real output, give a
learning summary, then **stop and wait for approval** before the next phase.

| Phase | Scope | Status |
|---|---|---|
| 0 | Inspect and plan | Done |
| 1 | Foundation: structure, models, config, logging, CLI, tests | Done |
| 2 | Demo collector, rule interface, scanner, 4 checks, fixtures | Next |
| 3 | JSON + CSV reporting | |
| 4 | Streamlit dashboard (5 pages) | |
| 5 | AWS read-only boto3 collector (label "live-unverified" if not live-tested) | |
| 6 | Hardening: stubs, Ruff, Bandit, pip-audit, docs | |
| 7 | Portfolio prep | |

## Design notes
- `finding_id` = first 16 hex chars of SHA-256 over JSON `[rule_id, account, region, resource_id]`.
- Severity is configured per rule in `config/rules.yaml`, separate from pass/fail logic.
- `Finding.evidence` is redacted automatically on validation; logs are redacted by a filter.
- A `Scan` cannot be `is_complete=True` if it has coverage gaps or Error findings,
  and cannot mix sources or accounts.
