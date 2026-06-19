# cfn-drift-extended

Detect **additive drift** and **orphaned resources** in CloudFormation-managed AWS accounts that native drift detection misses.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-242%20passing-brightgreen.svg)](#-development)
[![PyPI](https://img.shields.io/badge/PyPI-v1.1.0-blue.svg)](https://pypi.org/project/cfn-drift-extended/)

## 🔍 The Problem

CloudFormation drift detection only catches modifications or deletions to resources it manages. It completely misses **additive changes** — for example, a manually attached IAM policy on a CDK-managed role, an extra security group ingress rule, or an unauthorized SNS subscription. This tool fills that gap.

**Real-world example:** A reconciliation job failed in QA but worked in Dev. Root cause: someone had manually attached a broader IAM policy to the orchestrator role in Dev. CloudFormation showed "IN_SYNC" because the manual addition wasn't a modification — it was an extra policy CFN didn't know about.

## 🎯 Supported Services

### Additive drift detection (`audit`)

| Service | Drift Detected | Severity |
|---------|---------------|----------|
| **IAM Roles** | Extra inline policies, extra managed policies, modified policy documents | HIGH |
| **Security Groups** | Extra ingress rules (attack surface), extra egress rules (exfiltration) | HIGH / MEDIUM |
| **SNS Topics** | Extra policy statements, extra subscriptions | HIGH / MEDIUM |
| **SQS Queues** | Extra resource policy statements | HIGH |
| **EventBridge** | Extra rules on CFN-managed event buses | MEDIUM |
| **Lambda** | Extra environment variables, extra layers, extra resource policies | MEDIUM |
| **S3** | Extra bucket policy statements, extra lifecycle rules, extra CORS rules | MEDIUM |
| **DynamoDB** | Extra GSIs, extra scaling targets, extra scaling policies | MEDIUM |

### Orphan detection (`orphans`)

| Service | What It Detects | Severity |
|---------|----------------|----------|
| **IAM Roles** | Roles not managed by any active CFN stack | HIGH |
| **Security Groups** | SGs not managed by any active CFN stack | MEDIUM |
| **Lambda Functions** | Functions not managed by any active CFN stack | MEDIUM |
| **SQS Queues** | Queues not managed by any active CFN stack | MEDIUM |
| **SNS Topics** | Topics not managed by any active CFN stack | MEDIUM |

## 📦 Installation

```bash
pip install cfn-drift-extended
```

**Requirements:** Python 3.11+

## 🚀 Quick Start

```bash
# Audit all stacks starting with "my-app"
cfn-drift-extended audit --stack-prefix my-app --region us-east-1

# Audit specific stacks by name
cfn-drift-extended audit --stack-name my-stack-prod --region us-east-1

# Filter by tags
cfn-drift-extended audit --stack-prefix my-app --tag Environment=Production --region us-east-1

# Write JSON report for CI/CD
cfn-drift-extended audit --stack-prefix my-app --output-json report.json

# Don't fail on drift (just report)
cfn-drift-extended audit --stack-prefix my-app --no-fail-on-drift

# Verbose mode for debugging
cfn-drift-extended audit --stack-prefix my-app -v

# Control concurrency (default: 10 parallel workers)
cfn-drift-extended audit --stack-prefix my-app --max-workers 5

# Audit only specific services
cfn-drift-extended audit --stack-prefix my-app --services iam,sg

# Audit only SNS/SQS and EventBridge
cfn-drift-extended audit --stack-prefix my-app --services sns,sqs,eventbridge
```

## 🔎 Orphan Detection (v1.1)

Detect resources that exist in your AWS account but aren't managed by any CloudFormation stack — leaked resources from deleted stacks, console-created resources never brought under IaC, or resources created during incidents and forgotten.

```bash
# Detect orphaned resources across all services
cfn-drift-extended orphans --region us-east-1

# Scope to stacks with a specific prefix
cfn-drift-extended orphans --stack-prefix my-app --region us-east-1

# Cap deleted-stack scan for large accounts (default: 200)
cfn-drift-extended orphans --stack-prefix my-app --max-deleted-stacks 500

# Separate CFN API concurrency to avoid throttling (default: 5)
cfn-drift-extended orphans --stack-prefix my-app --max-cfn-workers 3

# Scan only specific services
cfn-drift-extended orphans --services iam,sg,lambda --region us-east-1

# JSON output for CI/CD
cfn-drift-extended orphans --stack-prefix my-app --output-json orphans.json
```

### Orphan provenance classification

Each orphan is classified by origin:

| Provenance | Meaning | Severity |
|------------|---------|----------|
| `cfn_orphan_deleted_stack` | Created by CFN, stack since deleted (DeletionPolicy: Retain) | HIGH |
| `unknown` | CloudFormation has no record — could be non-IaC or scan was capped | MEDIUM |

### Scale optimization (v1.1)

For accounts with thousands of deleted stacks, the `--max-deleted-stacks` flag (default: 200) caps the deleted-stack provenance scan. This prevents API throttling while still resolving provenance for the most recently deleted stacks. Unresolved orphans are classified as `unknown` rather than silently misclassified.

The `--max-cfn-workers` flag (default: 5) controls separate concurrency for CloudFormation API calls, independent from the detector thread pool (`--max-workers`).

## 🔒 Required IAM Permissions (Least Privilege)

This tool uses **read-only** AWS API calls exclusively. No write operations are performed.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CfnDriftExtendedReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudformation:ListStacks",
        "cloudformation:GetTemplate",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResource",
        "cloudformation:ListStackResources",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "sqs:GetQueueAttributes",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptionsByTopic",
        "events:DescribeEventBus",
        "events:ListRules",
        "events:ListTargetsByRule",
        "sts:GetCallerIdentity",
        "tag:GetResources",
        "iam:ListRoles",
        "lambda:ListFunctions",
        "lambda:GetPolicy",
        "ec2:DescribeVpcs",
        "sqs:ListQueues",
        "sns:ListTopics"
      ],
      "Resource": "*"
    }
  ]
}
```

For tighter scoping, restrict `Resource` to specific stack ARNs, role ARNs, security group IDs, queue ARNs, topic ARNs, and event bus ARNs.

## ⚙️ Exit Codes

| Code | Command | Meaning |
|------|---------|---------|
| 0 | `audit` | No drift detected (or `--no-fail-on-drift` used) |
| 1 | `audit` | Additive drift detected |
| 0 | `orphans` | No orphans found |
| 1 | `orphans` | Orphaned resources detected |
| 2 | Both | Error (permission denied, invalid input, unexpected failure) |

## 🚀 Example Output

```
════════════════════════════════════════════════════════════════
  cfn-drift-extended — Additive Drift Report
════════════════════════════════════════════════════════════════
  Stacks scanned:    2
  Resources scanned: 5
  Resources drifted: 1

⚠ Found 1 drift finding(s) across 1 resource(s):

  [HIGH] tax-reconciliation-tool-orchestrator (tax-reconciliation-tool-dev)
         Managed policy 'arn:aws:iam::123456789012:policy/ManualBroadAccess'
         is attached to role but is not declared in the CloudFormation template
         + arn:aws:iam::123456789012:policy/ManualBroadAccess
```

## ⚙️ JSON Report Format

```json
{
  "tool_version": "0.1.0",
  "account_id": "123456789012",
  "region": "us-east-1",
  "timestamp": "2026-05-19T14:30:00+00:00",
  "stacks_scanned": 3,
  "resources_scanned": 12,
  "resources_with_drift": 2,
  "findings": [
    {
      "resource_type": "AWS::IAM::Role",
      "resource_id": "my-role",
      "stack_name": "my-stack",
      "drift_type": "managed_policy_attached",
      "severity": "high",
      "description": "Managed policy 'arn:...' is attached but not in template",
      "expected": ["arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole"],
      "actual": ["arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole", "arn:aws:iam::aws:policy/AdministratorAccess"],
      "extra": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ],
  "errors": []
}
```

## GitHub Action Usage

```yaml
# Additive drift detection
- uses: mopyle4/cfn-drift-extended@v1.1
  with:
    command: "audit"
    stack-prefix: "my-app"
    region: "us-east-1"
    services: "iam,sg,sns,sqs,eventbridge"
    fail-on-drift: "true"
    output-json: "drift-report.json"

# Orphan detection
- uses: mopyle4/cfn-drift-extended@v1.1
  with:
    command: "orphans"
    stack-prefix: "my-app"
    region: "us-east-1"
    max-deleted-stacks: "200"
    output-json: "orphan-report.json"
```

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  CLI (Click)│────▶│   Auditor    │────▶│  Reporters  │
└─────────────┘     └──────┬───────┘     └─────────────┘
       │                   │
       │          ┌────────┼────────┐
       │          ▼        ▼        ▼
       │   ┌──────────┐ ┌──────────┐ ┌───────────┐
       │   │Collectors│ │Collectors│ │Comparators│
       │   │(expected)│ │ (actual) │ │  (diff)   │
       │   └──────────┘ └──────────┘ └───────────┘
       │
       ▼
┌─────────────────┐     ┌──────────────────┐
│ Orphan Auditor  │────▶│ Provenance       │
│ (parallel detect│     │ Resolver         │
│  per service)   │     │ (tag + CFN API)  │
└────────┬────────┘     └──────────────────┘
         │
         ▼
┌─────────────────┐
│ Managed Index   │ ← Active + deleted stacks (capped)
│ (cfn_managed)   │
└─────────────────┘
```

- **Collectors** gather state (expected from CFN templates, actual from AWS APIs)
- **Comparators** diff expected vs actual using set operations (O(n))
- **Reporters** format results for different output targets (console, JSON, GitHub Checks)
- **Auditor** orchestrates the pipeline with parallel execution

## ⚡ Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Least Privilege** | Read-only API calls only; no write operations |
| **SOLID** | Single responsibility per module; dependency injection via constructor |
| **Immutable Models** | Frozen Pydantic models and frozen dataclasses prevent mutation |
| **Graceful Degradation** | Individual resource failures don't crash the audit |
| **Performance** | Parallel auditing via ThreadPoolExecutor; set operations for O(n) comparison |
| **Adaptive Retry** | Exponential backoff with jitter (boto3 adaptive mode, 5 max attempts) |
| **CI/CD Ready** | Exit codes, JSON output, and `--fail-on-drift` flag |

## ⚡ Performance Characteristics

- **Time complexity:** O(S × R) where S = stacks scanned, R = resources per stack
- **Comparison:** O(n) set-based diff operations per resource
- **Concurrency:** Configurable thread pool (default 10 workers) for parallel resource auditing
- **Memory:** Frozen dataclasses with `__slots__` for minimal memory footprint
- **Network:** Adaptive retry with exponential backoff prevents throttling

## 🛠️ Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Exit code 2 with "Permission denied" | Missing IAM permissions | Add the required permissions from the policy above |
| No stacks found | Prefix doesn't match or stacks are in non-terminal state | Check stack names with `aws cloudformation list-stacks` |
| Slow execution | Many roles across many stacks | Increase `--max-workers` or narrow `--stack-prefix` |
| False positives on CDK stacks | CDK generates `AWS::IAM::Policy` resources separately | Already handled — external policies are associated with their target roles |
| Orphan provenance all "unknown" | `--max-deleted-stacks` too low for your account | Increase `--max-deleted-stacks` (default 200) |
| CFN API throttling during orphans | Too many concurrent CFN calls | Decrease `--max-cfn-workers` (default 5) |
| Many orphans from service-linked roles | AWS-managed roles show as orphans | Already filtered — service-linked and AWS-reserved roles are excluded |

## 🧪 Development

```bash
# Clone and install in dev mode
git clone https://github.com/mopyle4/cfn-drift-extended.git
cd cfn-drift-extended
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (242 tests)
pytest --cov=cfn_drift_extended --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
