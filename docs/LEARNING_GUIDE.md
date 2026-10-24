# Collumbus Learning Guide

A running record of what each phase taught. Read it before starting the next phase.

## Glossary

- **AWS**: Amazon Web Services, a cloud provider that rents computing and storage.
- **S3**: Simple Storage Service, AWS's file ("object") storage. Files live in *buckets*.
- **IAM**: Identity and Access Management, which controls who can do what in AWS.
- **CloudTrail**: AWS's audit log of API calls ("who did what, when").
- **Configuration auditor**: a tool that reads settings and compares them to rules. It does
  not attack anything or change anything.
- **Finding**: one rule's verdict (Pass, Fail, Error, Not Applicable) about one resource.
- **Virtual environment (venv)**: a private folder of Python packages for one project,
  so projects don't interfere with each other or with system Python.

## Phase 1: Foundation

### What we built
The "skeleton" every later phase relies on: validated data models, a validated config
file, secret redaction, logging, a CLI, and 59 tests.

### Key files
| File | Purpose |
|---|---|
| `src/collumbus/models/finding.py` | `Finding` model plus Severity, Status, Source enums |
| `src/collumbus/models/scan.py` | `Scan` model with `Coverage` (what was and wasn't inspected) |
| `src/collumbus/config.py` | Loads `config/rules.yaml` safely and validates it |
| `src/collumbus/security/redaction.py` | Removes secrets from text and data |
| `src/collumbus/logging_setup.py` | Logging with a redaction filter |
| `src/collumbus/cli.py` | Command-line entry point |

### Concepts

**Validation at the boundary.** Pydantic checks data the moment it enters the program.
A finding with severity `"Super Bad"` or a 4-digit account ID is rejected immediately with a
message saying which field is wrong. Bad data never reaches a report.

**Stable finding IDs.** The ID is a SHA-256 hash of rule + account + region + resource.
The same issue gets the same ID in every scan, which is how a later scan can tell whether
an issue is still present. The model recomputes the ID and rejects a finding whose stored
ID doesn't match, which catches edited or corrupted history files.

**"Couldn't check" is not "fine."** `Status.ERROR` is separate from `PASS`. A `Scan` with
coverage gaps or Error findings cannot be marked complete. The model refuses it.

**Defense in depth for secrets.** Collumbus never asks for credentials. As a second layer,
evidence and log messages are redacted anyway, in case an error message ever contains a key.

**`yaml.safe_load`.** The plain YAML loader can build arbitrary Python objects, which can
run code. `safe_load` only builds dicts, lists, strings, and numbers. A test proves that
a malicious `!!python/object/apply:os.system` tag is refused.

**Immutability.** Findings are `frozen`, so code can't quietly change a verdict after it
was validated.

### Before Phase 2, make sure you understand
1. Why `Error` must never be counted as `Pass`.
2. Why `finding_id` must not include the scan ID or timestamp.
3. Why Pydantic rejects unknown fields (`extra="forbid"`) instead of ignoring them.
