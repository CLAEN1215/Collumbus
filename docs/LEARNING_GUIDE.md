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

## Phase 3: JSON and CSV Reporting

### What we built
Comprehensive reporting capabilities: full scan persistence and loss-less deserialization
via JSON, spreadsheet-ready CSV export with CSV injection defense, and CLI commands for
generating reports during scans or exporting existing scan files.

### Key files
| File | Purpose |
|---|---|
| `src/collumbus/reporting/json_report.py` | `export_json`, `write_json_report`, and `read_json_report` |
| `src/collumbus/reporting/csv_report.py` | `export_csv`, `write_csv_report`, and `sanitize_csv_cell` |
| `src/collumbus/reporting/__init__.py` | Package interface exposing all reporting utilities |
| `src/collumbus/cli.py` | CLI flags `--json`, `--csv`, `--failures-only`, and `export-csv` command |

### Concepts

**Loss-less round-tripping with Pydantic.** A `Scan` contains complex nested structures
including datetime objects, enums, coverage gaps, and finding lists. By using Pydantic's
`model_dump_json()` and `model_validate_json()`, scan reports can be saved to disk and
reloaded without loss of fidelity. This enables storing audit history and loading historical
scans in the dashboard (Phase 4).

**Spreadsheet security (CSV Formula Injection).** When spreadsheet software (such as Microsoft
Excel or LibreOffice Calc) opens a CSV file, cells beginning with `=`, `+`, `-`, `@`, `\t`, or
`\r` are interpreted as formulas rather than plain text. In malicious or unvetted environments,
a cloud resource ID or tag (e.g. `=cmd|'/C calc'!A0`) could execute arbitrary system commands
on an auditor's machine. Collumbus neutralizes this risk by prefixing formula trigger characters
with a single quote (`'`), instructing spreadsheet software to treat the content as literal text.

**Triage-first sorting.** In audits covering hundreds of resources, burying critical failures
under hundreds of passes creates operational fatigue. The CSV report sorts findings by
priority: High and Critical Failures first, followed by Errors, then Passes, and finally
Not Applicable. Within each status tier, findings are ordered by rule and resource ID.

**Full audit trail vs actionable worklist.** Compliance auditors require proof of every check
performed, including passes. Operations engineers, on the other hand, only need the items that
require fixing. Collumbus supports both: full exports by default, and a `--failures-only` flag
to produce focused remediation worklists.

### Before Phase 4, make sure you understand
1. Why CSV formula injection is a risk when exporting user-controllable cloud data to spreadsheets.
2. How `Scan.model_validate_json()` validates reloaded JSON reports against the exact same schema.
3. How sorting by status and severity aids rapid incident response.

## Phase 4: Streamlit Dashboard and Scan History

### What we built
An interactive 5-page Streamlit web dashboard and historical scan tracking system:

### Key files
| File | Purpose |
|---|---|
| `src/collumbus/history.py` | Scan persistence, correlation (`first_detected` age), and audit diffing |
| `src/collumbus/dashboard/app.py` | Main Streamlit entry point with sidebar status and page navigation |
| `src/collumbus/dashboard/state.py` | Session state management and scan execution integration |
| `src/collumbus/dashboard/views/overview.py` | Page 1: Executive posture metrics, completion banner, and charts |
| `src/collumbus/dashboard/views/findings.py` | Page 2: Filterable findings explorer, risk/fix details, evidence, exports |
| `src/collumbus/dashboard/views/coverage.py` | Page 3: Coverage gaps explorer and minimal IAM policy generator |
| `src/collumbus/dashboard/views/history.py` | Page 4: Scan timeline, baseline comparison diff, and on-demand runner |
| `src/collumbus/dashboard/views/rules.py` | Page 5: Rules catalog, security rationale, and config inspector |
| `src/collumbus/cli.py` | Added `dashboard` command to launch the web interface |

### Concepts

**Tracking issue lifecycles across scans.** In Phase 1 we established that `finding_id` is a stable
SHA-256 hash of `[rule_id, account_id, region, resource_id]`. In Phase 4, `src/collumbus/history.py`
uses this identity to correlate findings across multiple audits. If an unencrypted bucket was
first detected three months ago, `correlate_scan_with_history()` preserves the original
`first_detected` timestamp, showing the true age of unaddressed debt.

**Audit diffing (New, Resolved, Recurring).** `compare_scans()` compares a baseline scan with
a newer scan. Findings present in the baseline but absent in the current scan are marked **Resolved**
(fixed), findings appearing for the first time are marked **New** (regressions or new deployments),
and findings persisting in both are marked **Recurring**.

**Automated remediation policy generation.** When coverage gaps occur (e.g. `AccessDenied` for
`iam:ListUserPolicies` or `s3:GetBucketPublicAccessBlock`), the Coverage page synthesizes a
minimal read-only IAM policy document that an administrator can directly apply to grant the
auditor complete visibility.

**Multi-perspective interface.** Executive leadership needs high-level posture metrics (completion
status, overall failure rates, severity breakdown), compliance auditors need comprehensive inventories
and proof of coverage, while engineers need immediate step-by-step remediation commands and evidence.
The 5-page layout serves all three stakeholders in one application.

### Before Phase 5, make sure you understand
1. How stable finding IDs enable tracking the age and resolution of security findings across time.
2. How the dashboard surfaces coverage gaps as security concerns rather than passing grades.
3. Why the audit tool generates minimal read-only IAM policies rather than modifying cloud state.

## Phase 5: Read-Only AWS Boto3 Collector

### What we built
Live cloud configuration collection using the official AWS SDK (`boto3`):

### Key files
| File | Purpose |
|---|---|
| `src/collumbus/collectors/aws.py` | `AwsCollector` performs read-only inspection for S3, IAM, and CloudTrail |
| `src/collumbus/collectors/__init__.py` | Exported `AwsCollector` and `AwsCredentialsError` |
| `src/collumbus/cli.py` | Added `aws-scan` command with region, profile, and export options |
| `tests/test_aws_collector.py` | Unit tests for AWS authentication, parsing, and error simulation |

### Concepts

**The standard AWS credential chain.** Rather than asking users for API secrets or storing
tokens in configuration files, Collumbus delegates authentication to `boto3.Session`. The SDK
automatically resolves credentials in order: environment variables (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`), credentials file (`~/.aws/credentials`), config profiles
(`~/.aws/config`), and container/instance IAM roles. If credentials are missing, it provides
actionable setup instructions (`aws configure`).

**Zero-modification (read-only) guarantee.** The auditor only calls read-only APIs:
`sts:GetCallerIdentity`, `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`,
`s3:GetEncryptionConfiguration`, `iam:ListPolicies`, `iam:GetPolicyVersion`,
`cloudtrail:DescribeTrails`, and `cloudtrail:GetTrailStatus`. It never creates, updates, or
deletes any cloud resource.

**Known state vs API failure in boto3.** In AWS APIs, certain "errors" represent known states
rather than failures:
* `NoSuchPublicAccessBlockConfiguration` means Block Public Access is simply turned off. Collumbus
  records `public_access_block: None`, which the rule properly evaluates as `FAIL`.
* `ServerSideEncryptionConfigurationNotFoundError` means default encryption is not set. Collumbus
  records `encryption_rules: None`, which evaluates as `FAIL`.
* In contrast, `AccessDenied` or `Throttling` means the state could not be determined. Collumbus
  records a `FetchError`, which produces an `ERROR` finding and notes an incomplete scan.

**Shared evaluation pipeline.** Because `AwsCollector` and `DemoCollector` both emit standardized
`Resource` objects inside a `CollectionResult`, the four security rules, the severity engine,
the reporting modules, and the Streamlit dashboard all run against real AWS data with zero
modifications.

### Before Phase 6, make sure you understand
1. How `boto3.Session` resolves credentials through the standard credential chain.
2. The difference between a resource missing a configuration (`None`) vs an API call failing (`FetchError`).
3. Why `AwsCollector` and `DemoCollector` produce identical `CollectionResult` schemas.

## Phase 6: Code Hardening, Static Typing, and Security Assurance

### What we built
Comprehensive code hardening and security verification using industry-standard static analysis tools:

### Key tools and configurations
| Tool | Configuration | Purpose |
|---|---|---|
| `mypy` | `pyproject.toml` (`[tool.mypy]`), `plugins = ["pydantic.mypy"]` | Static type checking and verification across all source files and tests |
| `py.typed` | `src/collumbus/py.typed` | PEP 561 marker indicating package provides inline type annotations |
| `bandit` | `bandit -r src` | AST-based Python security vulnerability analyzer (detects CWE-78, CWE-259, etc.) |
| `pip-audit` | `pip-audit` | Audits virtual environment and dependency tree against known CVEs via PyPA advisory DB |
| `ruff` | `pyproject.toml` (`[tool.ruff.lint]`) | Fast linting and style enforcement (E, W, F, I, B, UP, S rules) |

### Concepts

**Type Safety and PEP 561 (`py.typed`).** Python is dynamically typed at runtime, but type checkers
like Mypy use static type annotations to catch type mismatches, missing attributes, and `None`-dereference
bugs before code ever runs in production. PEP 561 defines `py.typed` as the standard marker file that tells
tools a library ships with valid type hints.

**Pydantic Type Integration (`pydantic.mypy`).** Pydantic models perform runtime parsing and validation.
However, because Pydantic dynamically generates constructors and field validators, vanilla Mypy needs the
`pydantic.mypy` plugin to recognize generated method signatures, default factory fields, and model copy behaviors.

**AST-Based Security Analysis (Bandit).** Bandit parses Python source code into an Abstract Syntax Tree (AST)
and looks for common security pitfalls:
* Insecure use of `subprocess` without shell escaping (`B404`, `B603`).
* Hardcoded secrets and password-like strings (`B105`).
* Weak cryptographic hashing algorithms (`B303` - MD5/SHA1 used in security contexts).
When a flagged line is intentionally safe (e.g., status string `"Pass"` vs a password, or a controlled
dashboard child process), explicit `# nosec` annotations document the evaluated risk.

**Dependency Vulnerability Auditing (pip-audit).** Vulnerabilities in open-source dependencies (supply
chain attacks) represent a major attack vector in modern software. `pip-audit` checks installed packages
against the Python Packaging Advisory Database (OSV/PyPI advisory feed) to verify no dependencies contain
known Common Vulnerabilities and Exposures (CVEs).

### Before Phase 7, make sure you understand
1. How `py.typed` allows other projects and type checkers to inspect Collumbus's types.
2. The difference between linting (Ruff), static typing (Mypy), and AST security scanning (Bandit).
3. Why dependency scanning (`pip-audit`) is essential in modern DevSecOps pipelines.

## Phase 7: Portfolio Preparation & Security Engineering Communication

### What we built
Comprehensive portfolio presentation, architecture diagrams, interview talking points, and an end-to-end demonstration guide.

### Key assets
| Asset | Location | Purpose |
|---|---|---|
| Portfolio & Interview Guide | `docs/PORTFOLIO_GUIDE.md` | Complete guide for job interviews, architecture talking points, and live demo script |
| System Architecture Diagram | `README.md` & `docs/PORTFOLIO_GUIDE.md` | Mermaid diagram documenting dataflow from collectors to findings and reports |
| Project Showcase README | `README.md` | Comprehensive documentation, security guarantees, CLI reference, and DevSecOps verification |

### Concepts

**Communicating security trade-offs.** As a cybersecurity student, building software is only half
the battle; the other half is communicating *why* you made specific architectural choices. For example:
* *Why no auto-remediation?* Because security tools must not induce service outages (availability impact).
* *Why fail-closed on API errors?* Because treating missing information as a pass creates a false sense of security.
* *Why sanitize CSV exports?* Because formula injection (CWE-1236) turns security reports into attack payloads against the security analysts reading them.

**Decoupled collector architecture.** By standardizing on `CollectionResult` and `Resource` models,
the scanner engine has zero knowledge of whether data came from a simulated JSON fixture or live AWS
Boto3 API calls. This separation of concerns allows complete offline testing and rule development
without cloud costs, credentials, or network access.

**DevSecOps quality gates.** A security project should follow the highest standards of software
engineering. Incorporating static typing (`mypy`), AST security scanning (`bandit`), dependency audits
(`pip-audit`), automated linting (`ruff`), and regression testing (`pytest`) demonstrates an understanding
of defensive software engineering and the Secure Software Development Lifecycle (SSDLC).






