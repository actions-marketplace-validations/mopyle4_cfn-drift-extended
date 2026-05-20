# Design: New Service Collectors for cfn-drift-extended

## Overview

Extend cfn-drift-extended to detect additive drift on Security Groups, SNS/SQS, and EventBridge resources. Each follows the same collector/comparator pattern established by the IAM implementation.

## Assignment

| Service | Owner | Status |
|---|---|---|
| Lambda (env vars, layers, resource policies) | Farzad | Not started |
| S3 (bucket policies, lifecycle rules, CORS) | Farzad | Not started |
| DynamoDB (GSIs, auto-scaling policies) | Farzad | Not started |
| Security Groups (ingress/egress rules) | Morris | Not started |
| SNS/SQS (resource policies, subscriptions) | Morris | Not started |
| EventBridge (rules on CFN-managed event buses) | Morris | Not started |

---

## Architecture Pattern (follow exactly)

Each new service requires:

1. **Collector** (`src/cfn_drift_extended/collectors/<service>_collector.py`)
   - Frozen dataclass for actual state (immutable, slots)
   - Class with `__init__(region, session)` accepting optional boto3 session
   - Method(s) to fetch actual state from AWS API
   - Pagination on all list operations
   - Adaptive retry config (`Config(retries={"max_attempts": 5, "mode": "adaptive"})`)
   - Read-only API calls only (least privilege)
   - Returns `None` on access errors (graceful degradation)

2. **CfnCollector extension** — Add method to `cfn_collector.py` (or create service-specific extractor)
   - Extract expected state from CloudFormation template `Resources` section
   - Handle intrinsic function resolution where needed
   - Return frozen dataclass matching the collector's actual state structure

3. **Comparator** (`src/cfn_drift_extended/comparators/<service>_comparator.py`)
   - `compare(expected, actual) -> ResourceAudit`
   - Use set operations for O(n) comparison
   - Return `DriftFinding` objects with appropriate `DriftType` and `Severity`

4. **Models** — Add new `DriftType` enum values to `models.py`

5. **Tests** — Unit tests with moto mocks covering:
   - Happy path (no drift)
   - Additive drift detected
   - Resource not found (graceful degradation)
   - Permission denied (graceful degradation)
   - Edge cases (empty rules, multiple findings)

---

## Service 1: Security Groups

### Actual State Collector

```python
@dataclass(frozen=True, slots=True)
class ActualSecurityGroupState:
    group_id: str
    group_name: str
    ingress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)
    egress_rules: tuple[SecurityGroupRule, ...] = field(default_factory=tuple)

@dataclass(frozen=True, slots=True)
class SecurityGroupRule:
    ip_protocol: str
    from_port: int | None
    to_port: int | None
    cidr_ipv4: str | None = None
    cidr_ipv6: str | None = None
    source_security_group_id: str | None = None
    prefix_list_id: str | None = None
    description: str | None = None
```

### AWS API Calls (read-only)

- `ec2:DescribeSecurityGroups` — get rules for a specific group
- `ec2:DescribeSecurityGroupRules` — get individual rules (newer API, more detail)

### Expected State (from CFN template)

Extract from `AWS::EC2::SecurityGroup` resource:
- `SecurityGroupIngress` property → expected ingress rules
- `SecurityGroupEgress` property → expected egress rules

Also check for standalone `AWS::EC2::SecurityGroupIngress` and `AWS::EC2::SecurityGroupEgress` resources that reference the group.

### DriftType Values

- `SECURITY_GROUP_INGRESS_ADDED` — ingress rule exists but not in template
- `SECURITY_GROUP_EGRESS_ADDED` — egress rule exists but not in template

### Severity

- Ingress rules added: **HIGH** (opens attack surface)
- Egress rules added: **MEDIUM** (data exfiltration risk but less immediate)

### Comparison Logic

```
extra_ingress = actual_ingress_rules - expected_ingress_rules
extra_egress = actual_egress_rules - expected_egress_rules
```

Rules are compared by: (ip_protocol, from_port, to_port, cidr/source_sg/prefix_list). Description is NOT compared (cosmetic).

### Required IAM Permissions

```json
{
  "Action": ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"],
  "Resource": "*"
}
```

---

## Service 2: SNS/SQS Resource Policies & Subscriptions

### Actual State Collector

```python
@dataclass(frozen=True, slots=True)
class ActualSqsQueueState:
    queue_url: str
    queue_arn: str
    policy: dict | None = None  # Resource policy JSON
    redrive_policy: dict | None = None

@dataclass(frozen=True, slots=True)
class ActualSnsTopicState:
    topic_arn: str
    policy: dict | None = None  # Resource policy JSON
    subscriptions: tuple[SnsSubscription, ...] = field(default_factory=tuple)

@dataclass(frozen=True, slots=True)
class SnsSubscription:
    protocol: str
    endpoint: str
    subscription_arn: str
```

### AWS API Calls (read-only)

- `sqs:GetQueueAttributes` (AttributeNames: ["Policy", "RedrivePolicy"])
- `sns:GetTopicAttributes` (get topic policy)
- `sns:ListSubscriptionsByTopic` (get subscriptions)

### Expected State (from CFN template)

- `AWS::SQS::Queue` → extract `RedrivePolicy` from Properties
- `AWS::SQS::QueuePolicy` → extract `PolicyDocument` and target queues
- `AWS::SNS::Topic` → no inline policy (policies are separate resources)
- `AWS::SNS::TopicPolicy` → extract `PolicyDocument` and target topics
- `AWS::SNS::Subscription` → extract protocol + endpoint

### DriftType Values

- `SQS_POLICY_STATEMENT_ADDED` — extra statement in queue resource policy
- `SNS_POLICY_STATEMENT_ADDED` — extra statement in topic resource policy
- `SNS_SUBSCRIPTION_ADDED` — subscription exists but not in template

### Severity

- Policy statement added: **HIGH** (grants access to the queue/topic)
- Subscription added: **MEDIUM** (data flows to unintended destination)

### Required IAM Permissions

```json
{
  "Action": [
    "sqs:GetQueueAttributes",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic"
  ],
  "Resource": "*"
}
```

---

## Service 3: EventBridge Rules

### Actual State Collector

```python
@dataclass(frozen=True, slots=True)
class ActualEventBusState:
    event_bus_name: str
    event_bus_arn: str
    rules: tuple[EventBridgeRule, ...] = field(default_factory=tuple)

@dataclass(frozen=True, slots=True)
class EventBridgeRule:
    name: str
    state: str  # ENABLED | DISABLED
    event_pattern: dict | None = None
    schedule_expression: str | None = None
    targets: tuple[str, ...] = field(default_factory=tuple)  # target ARNs
```

### AWS API Calls (read-only)

- `events:ListRules` (EventBusName filter) — paginated
- `events:ListTargetsByRule` — get targets for each rule

### Expected State (from CFN template)

- `AWS::Events::Rule` → extract `EventBusName`, `EventPattern`, `ScheduleExpression`, `Targets`
- Match rules by name (physical resource ID from CFN)

### DriftType Values

- `EVENTBRIDGE_RULE_ADDED` — rule exists on bus but not in any CFN template

### Severity

- Rule added: **MEDIUM** (routes events to unintended targets, potential data flow issue)

### Comparison Logic

```
actual_rule_names = {rule.name for rule in actual_rules}
expected_rule_names = {rule.name for rule in expected_rules}
extra_rules = actual_rule_names - expected_rule_names
```

### Required IAM Permissions

```json
{
  "Action": ["events:ListRules", "events:ListTargetsByRule"],
  "Resource": "*"
}
```

---

## Model Updates Required

Add to `DriftType` enum in `models.py`:

```python
class DriftType(StrEnum):
    # Existing
    INLINE_POLICY_ADDED = "inline_policy_added"
    MANAGED_POLICY_ATTACHED = "managed_policy_attached"
    INLINE_POLICY_MODIFIED = "inline_policy_modified"
    # New: Security Groups
    SECURITY_GROUP_INGRESS_ADDED = "security_group_ingress_added"
    SECURITY_GROUP_EGRESS_ADDED = "security_group_egress_added"
    # New: SNS/SQS
    SQS_POLICY_STATEMENT_ADDED = "sqs_policy_statement_added"
    SNS_POLICY_STATEMENT_ADDED = "sns_policy_statement_added"
    SNS_SUBSCRIPTION_ADDED = "sns_subscription_added"
    # New: EventBridge
    EVENTBRIDGE_RULE_ADDED = "eventbridge_rule_added"
```

---

## Auditor Integration

Update `auditor.py` to:
1. Accept a `services` parameter (default: all) to control which services are scanned
2. For each stack, extract expected state for all enabled services
3. For each resource, collect actual state and run the appropriate comparator
4. Aggregate findings into the existing `AuditReport` model

---

## Test Strategy

Each service gets:
- `test_<service>_collector.py` — moto-mocked AWS API tests
- `test_<service>_comparator.py` — unit tests with fixture data (no AWS calls)

Test cases per service:
1. No drift (expected == actual) → `in_sync=True`
2. Single additive finding → correct DriftType and Severity
3. Multiple findings → all reported
4. Resource not found → graceful `None` return
5. Permission denied → graceful `None` return with error log
6. Empty rules/policies → no false positives
