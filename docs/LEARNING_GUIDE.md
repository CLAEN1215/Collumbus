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

## Phase 2: Demo Collector, Rules, and Scanner

### What we built
The audit engine: a normalized resource model, a simulated demo data collector, four core
security rules, a scanner that coordinates evaluation, and full CLI support with `demo-scan`.

### Key files
| File | Purpose |
|---|---|
| `src/collumbus/collectors/base.py` | `Resource`, `CollectionResult`, `FetchError`, and `Collector` base class |
| `src/collumbus/collectors/demo.py` | `DemoCollector` reads simulated cloud config from JSON |
| `data/demo/resources.json` | Fictional AWS resources covering pass, fail, and error scenarios |
| `src/collumbus/rules/base.py` | Shared `Rule` interface and `RuleResult` verdict model |
| `src/collumbus/rules/s3_public_access.py` | S3-001: verifies all 4 S3 Block Public Access settings |
| `src/collumbus/rules/s3_encryption.py` | S3-002: verifies S3 default encryption algorithm against policy |
| `src/collumbus/rules/iam_wildcard.py` | IAM-001: flags broad wildcard permissions in IAM policies |
| `src/collumbus/rules/cloudtrail_logging.py` | CT-001: verifies active trails and per-region logging coverage |
| `src/collumbus/engine/severity.py` | Maps rule verdict + YAML config to finding severity |
| `src/collumbus/engine/scanner.py` | Runs rules against resources; converts gaps/errors into findings |

### Concepts

**Normalized representation.** Both demo files and real AWS APIs will feed the same data
structures (`Resource` and `CollectionResult`). The rules have no idea whether data came
from a JSON file or live boto3 calls, ensuring consistent evaluation.

**Missing configuration vs fetch error.** If a bucket has no encryption configured, AWS returns
an error (`ServerSideEncryptionConfigurationNotFoundError`), which is a known state (`None`)
and results in `FAIL`. But if an API call fails due to `AccessDenied` or `Throttling`, that is a
`FetchError` and results in `ERROR`. A security auditor must never confuse "not configured" with
"could not inspect".

**Separation of verdict from severity.** Rules evaluate resource state and return a `Status`
(Pass, Fail, Error, Not Applicable). They do not decide business impact. The engine assigns
severity using `config/rules.yaml`. If an organization considers unencrypted buckets Low severity
instead of High, they adjust the config file without touching rule code.

**Crash isolation.** A security auditor running across hundreds of resources must be resilient.
If a buggy rule raises an unhandled exception or receives malformed data, `scanner.py` logs the
error locally and produces an `ERROR` finding, allowing all other rules to finish inspecting the
target.

**Coverage gaps as first-class findings (SYS-001).** If an entire API call was denied
(e.g., `iam:ListUserPolicies`), the scanner records a `CoverageGap` and synthesizes a `SYS-001`
finding. This ensures uninspected areas appear prominently in summaries and reports.

### Before Phase 3, make sure you understand
1. How `Resource.attributes` differs from `Resource.fetch_errors`.
2. Why a rule returns `RuleResult` rather than directly creating a `Finding`.
3. How `scanner.py` guarantees an incomplete scan when coverage gaps or rule errors occur.

