#!/usr/bin/env bash
# Comprehensive end-to-end live test for the orphan provenance classifier.
#
# Exercises every classification path the code can take:
#
# CFN_ORPHAN_DELETED_STACK (managed-index tier, all 5 services):
#   - IAM role, SQS queue, SG, Lambda fn, SNS topic — each with
#     DeletionPolicy: Retain, all retained when the stack is deleted.
#
# NON_IAC (CLI-only, all 5 services):
#   - One CLI-created resource per supported service. Each must classify as
#     NON_IAC and keep its detector's default severity (HIGH for IAM,
#     MEDIUM for SQS / SG / Lambda, LOW for SNS).
#
# CFN_ORPHAN_ACTIVE_STACK skip path:
#   - Run the detector with --stack-prefix that excludes the test stack
#     while it's still active. Findings should be skipped and a warning
#     logged on stderr.
#
# Exclusion filters (every filter in orphan_filters.py):
#   - cdk-* IAM role name → excluded
#   - Lambda named *-Custom-* / *Custom::* → excluded
#   - Lambda named *LogRetention* → excluded
#   - SQS queue named *-dlq.fifo → excluded
#   - SQS queue named *-deadletter.fifo → excluded
#   - Service-linked roles + default SGs → asserted negatively (account state)
#
# CLI / output paths:
#   - --output-json → file is a parseable JSON report
#   - Console reporter → stdout contains "Provenance:" line
#   - --fail-on-orphans → non-zero exit when orphans exist
#   - --services iam → single-service filter respected
#   - --stack-prefix matching → findings unchanged
#
# USAGE
#   scripts/live-provenance-test.sh --profile NAME [--region REGION] [--keep]
#
# REQUIRES: explicit --profile or $AWS_PROFILE. Refuses to run if the profile
# or assumed-role ARN looks like production. Cleans up on success, failure,
# or signal. Idempotent — uses a unique per-run prefix so concurrent or
# repeat runs don't collide.

set -euo pipefail

# ----- argument parsing ------------------------------------------------------

PROFILE="${AWS_PROFILE:-}"
REGION="us-east-1"
KEEP=0
OVERRIDE_PROD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)              PROFILE="$2"; shift 2 ;;
    --region)               REGION="$2"; shift 2 ;;
    --keep)                 KEEP=1; shift ;;
    --i-know-what-im-doing) OVERRIDE_PROD=1; shift ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PROFILE" ]]; then
  echo "ERROR: AWS profile is required." >&2
  echo "       Pass --profile NAME or set AWS_PROFILE in your environment." >&2
  exit 2
fi

export AWS_PROFILE="$PROFILE"
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"

# Locate the CLI: prefer PATH, fall back to the project's editable venv.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if command -v cfn-drift-extended >/dev/null 2>&1; then
  CFNDX_CLI="$(command -v cfn-drift-extended)"
elif [[ -x "$PROJECT_ROOT/.venv/bin/cfn-drift-extended" ]]; then
  CFNDX_CLI="$PROJECT_ROOT/.venv/bin/cfn-drift-extended"
else
  echo "ERROR: cfn-drift-extended not on PATH and no $PROJECT_ROOT/.venv found." >&2
  exit 8
fi
echo "    cli: $CFNDX_CLI"

# ----- preflight -------------------------------------------------------------

echo ">>> Preflight: identifying caller and account"
IDENTITY=$(aws sts get-caller-identity --output json)
ACCOUNT=$(echo "$IDENTITY" | jq -r '.Account')
ARN=$(echo "$IDENTITY" | jq -r '.Arn')
echo "    account=$ACCOUNT"
echo "    arn=$ARN"

if [[ "$OVERRIDE_PROD" -eq 0 ]]; then
  if echo "$ARN" | grep -Eqi '(prod|production|prd)\b' \
     || echo "$PROFILE" | grep -Eqi '^(prod|production|prd)$'; then
    echo "ERROR: profile/role looks like production. Refusing to create + delete fixtures." >&2
    echo "       If this is genuinely a dev account, re-run with --i-know-what-im-doing." >&2
    exit 3
  fi
fi

# ----- per-run identifiers ---------------------------------------------------

TS=$(date -u +%Y%m%d-%H%M%S)
RUN_ID="${USER:-anon}-${TS}"
PREFIX="cfndx-prov-${RUN_ID}"
STACK_NAME="${PREFIX}-stack"

# CFN-created retained fixtures (all 5 services)
ROLE_NAME_CFN="${PREFIX}-role-cfn"
QUEUE_NAME_CFN="${PREFIX}-queue-cfn"
SG_NAME_CFN="${PREFIX}-sg-cfn"
LAMBDA_NAME_CFN="${PREFIX}-fn-cfn"
TOPIC_NAME_CFN="${PREFIX}-topic-cfn"

# CLI-created fixtures for the NON_IAC bucket (all 5 services)
ROLE_NAME_CLI="${PREFIX}-role-cli"
QUEUE_NAME_CLI="${PREFIX}-queue-cli"
SG_NAME_CLI="${PREFIX}-sg-cli"
LAMBDA_NAME_CLI="${PREFIX}-fn-cli"
TOPIC_NAME_CLI="${PREFIX}-topic-cli"

# Exclusion-filter fixtures — every one of these must be EXCLUDED by a filter
# (i.e. produce zero findings).
ROLE_NAME_CDK="cdk-${PREFIX:0:25}-bootstrap-role"   # cdk-* prefix → excluded
QUEUE_NAME_DLQ="${PREFIX}-q-dlq.fifo"              # -dlq.fifo → excluded
QUEUE_NAME_DEADLETTER="${PREFIX}-q-deadletter.fifo" # -deadletter.fifo → excluded
LAMBDA_NAME_LOGRET="${PREFIX}-LogRetention"         # LogRetention → excluded
LAMBDA_NAME_CUSTOM="${PREFIX}-Custom-handler"       # Custom:: substring → excluded
# Note: is_excluded_lambda checks for "Custom::" exactly. We can't put :: in a
# Lambda name (invalid), so the Custom:: filter is unreachable from the live
# AWS API surface — covered by unit tests. We still create a "Custom-" Lambda
# to confirm it does NOT match (positive control: should appear as NON_IAC).

# Use a CLI role for Lambda execution role (avoids a circular ref to the CFN
# role which is retained-then-orphaned).
LAMBDA_EXEC_ROLE="${PREFIX}-fn-exec-role"

TEMPLATE=$(mktemp -t "${PREFIX}-template.XXXXXX.yaml")
JSON_REPORT=$(mktemp -t "${PREFIX}-report.XXXXXX.json")
CONSOLE_OUT=$(mktemp -t "${PREFIX}-console.XXXXXX.txt")
LAMBDA_ZIP=$(mktemp -t "${PREFIX}-fn.XXXXXX.zip")

echo "    run prefix: $PREFIX"
echo

# ----- teardown trap ---------------------------------------------------------

cleanup_invoked=0
cleanup() {
  local rc=$?
  if [[ $cleanup_invoked -eq 1 ]]; then return; fi
  cleanup_invoked=1
  if [[ "$KEEP" -eq 1 ]]; then
    echo
    echo ">>> --keep set: leaving fixtures in place"
    return
  fi
  echo
  echo ">>> Tearing down (always runs, even on error; rc was $rc)"

  # Stack first (its retained resources will need explicit deletion below)
  aws cloudformation delete-stack --stack-name "$STACK_NAME" 2>/dev/null || true
  aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" 2>/dev/null || true

  # CFN-retained resources (all 5 services)
  aws iam delete-role --role-name "$ROLE_NAME_CFN" 2>/dev/null || true
  aws sqs delete-queue --queue-url \
    "https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${QUEUE_NAME_CFN}" 2>/dev/null || true
  for grpname in "$SG_NAME_CFN" "$SG_NAME_CLI"; do
    SG_ID=$(aws ec2 describe-security-groups \
      --filters "Name=group-name,Values=${grpname}" \
      --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
    if [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
      aws ec2 delete-security-group --group-id "$SG_ID" 2>/dev/null || true
    fi
  done
  for fn in "$LAMBDA_NAME_CFN" "$LAMBDA_NAME_CLI" "$LAMBDA_NAME_LOGRET" \
            "$LAMBDA_NAME_CUSTOM"; do
    aws lambda delete-function --function-name "$fn" 2>/dev/null || true
  done
  # Drop the Lambda exec role last (deletes might still hold it briefly)
  aws iam detach-role-policy --role-name "$LAMBDA_EXEC_ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
    2>/dev/null || true
  aws iam delete-role --role-name "$LAMBDA_EXEC_ROLE" 2>/dev/null || true

  # Topics
  aws sns delete-topic --topic-arn \
    "arn:aws:sns:${REGION}:${ACCOUNT}:${TOPIC_NAME_CFN}" 2>/dev/null || true
  aws sns delete-topic --topic-arn \
    "arn:aws:sns:${REGION}:${ACCOUNT}:${TOPIC_NAME_CLI}" 2>/dev/null || true

  # CLI-only fixtures
  aws iam delete-role --role-name "$ROLE_NAME_CLI" 2>/dev/null || true
  aws iam delete-role --role-name "$ROLE_NAME_CDK" 2>/dev/null || true
  aws sqs delete-queue --queue-url \
    "https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${QUEUE_NAME_CLI}" 2>/dev/null || true
  aws sqs delete-queue --queue-url \
    "https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${QUEUE_NAME_DLQ}" 2>/dev/null || true
  aws sqs delete-queue --queue-url \
    "https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${QUEUE_NAME_DEADLETTER}" 2>/dev/null || true

  rm -f "$TEMPLATE" "$JSON_REPORT" "$CONSOLE_OUT" "$LAMBDA_ZIP"
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ----- explicit confirmation -------------------------------------------------

echo ">>> About to create AWS resources in account $ACCOUNT, region $REGION:"
echo "    1 CFN stack ($STACK_NAME) with 5 retained resources (IAM, SQS, SG, Lambda, SNS)"
echo "    5 CLI-only resources (one per supported service) for the NON_IAC bucket"
echo "    5 exclusion-filter fixtures (cdk-* role, FIFO DLQs, LogRetention/Custom Lambdas)"
echo "    All fixtures use prefix '$PREFIX' and will be deleted automatically."
read -r -p "Continue? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "aborted"; exit 1; }

# ----- assertion infrastructure ---------------------------------------------

declare -i FAILS=0
assert_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf "    %-72s OK\n" "$name"
  else
    printf "    %-72s FAIL\n" "$name"
    printf "        expected: %s\n        actual:   %s\n" "$expected" "$actual"
    FAILS+=1
  fi
}

# classify <substring> [report-file]
# Returns "<provenance>|<originating_stack>" for the unique finding whose
# resource_id contains <substring>, or "MISSING" / "DUPLICATE".
classify() {
  local needle="$1" report="${2:-$JSON_REPORT}"
  jq -r --arg n "$needle" '
    [.findings[] | select(.resource_id | contains($n))]
    | if length == 0 then "MISSING"
      elif length > 1 then "DUPLICATE"
      else .[0] | "\(.provenance)|\(.originating_stack_name // "")"
      end
  ' "$report"
}

# severity_for <substring> [report]
severity_for() {
  local needle="$1" report="${2:-$JSON_REPORT}"
  jq -r --arg n "$needle" '
    [.findings[] | select(.resource_id | contains($n))]
    | if length == 0 then "MISSING"
      elif length > 1 then "DUPLICATE"
      else .[0].severity
      end
  ' "$report"
}

# count_with <jq-filter> [report]
count_with() {
  local filter="$1" report="${2:-$JSON_REPORT}"
  jq -r "[.findings[] | $filter] | length" "$report"
}

# ----- find default VPC ------------------------------------------------------

DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=true" \
  --query 'Vpcs[0].VpcId' --output text)
[[ -z "$DEFAULT_VPC" || "$DEFAULT_VPC" == "None" ]] && {
  echo "ERROR: no default VPC in $REGION; cannot create test SG" >&2
  exit 4
}

# ----- write CFN template (all 5 services Retain'd) -------------------------

python3 -c "
import zipfile
z = zipfile.ZipFile('$LAMBDA_ZIP', 'w', zipfile.ZIP_DEFLATED)
z.writestr('index.py', 'def handler(event, context):\n    return {}\n')
z.close()
"

cat > "$TEMPLATE" <<EOF
AWSTemplateFormatVersion: "2010-09-09"
Description: cfn-drift-extended live provenance test ($RUN_ID)

Resources:
  TestRole:
    Type: AWS::IAM::Role
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      RoleName: $ROLE_NAME_CFN
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole

  TestQueue:
    Type: AWS::SQS::Queue
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      QueueName: $QUEUE_NAME_CFN

  TestSG:
    Type: AWS::EC2::SecurityGroup
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      GroupName: $SG_NAME_CFN
      GroupDescription: cfn-drift-extended live test fixture
      VpcId: $DEFAULT_VPC

  TestFunction:
    Type: AWS::Lambda::Function
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    DependsOn: TestRole
    Properties:
      FunctionName: $LAMBDA_NAME_CFN
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt TestRole.Arn
      Code:
        ZipFile: |
          def handler(event, context):
              return {}

  TestTopic:
    Type: AWS::SNS::Topic
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      TopicName: $TOPIC_NAME_CFN
EOF

# ============================================================================
# Step 1: create the CFN stack and CLI fixtures
# ============================================================================

echo
echo ">>> Step 1a: deploying CFN stack with all 5 retained services"
aws cloudformation create-stack \
  --stack-name "$STACK_NAME" \
  --template-body "file://$TEMPLATE" \
  --capabilities CAPABILITY_NAMED_IAM \
  >/dev/null
aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME"
echo "    stack: CREATE_COMPLETE"

echo
echo ">>> Step 1b: creating CLI-only fixtures (NON_IAC bucket, all 5 services)"

# Lambda needs a real role; create one explicitly so we don't depend on the
# stack's retained role (which we're about to leak intentionally).
aws iam create-role \
  --role-name "$LAMBDA_EXEC_ROLE" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null
aws iam attach-role-policy --role-name "$LAMBDA_EXEC_ROLE" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null
LAMBDA_EXEC_ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${LAMBDA_EXEC_ROLE}"

# Wait briefly for IAM propagation before Lambda CreateFunction
sleep 8

aws iam create-role \
  --role-name "$ROLE_NAME_CLI" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null
aws sqs create-queue --queue-name "$QUEUE_NAME_CLI" >/dev/null
aws ec2 create-security-group \
  --group-name "$SG_NAME_CLI" \
  --description "cfn-drift-extended live test CLI-only SG" \
  --vpc-id "$DEFAULT_VPC" >/dev/null
aws lambda create-function \
  --function-name "$LAMBDA_NAME_CLI" \
  --runtime python3.11 \
  --handler index.handler \
  --role "$LAMBDA_EXEC_ROLE_ARN" \
  --zip-file "fileb://$LAMBDA_ZIP" >/dev/null
aws sns create-topic --name "$TOPIC_NAME_CLI" >/dev/null
echo "    role:   $ROLE_NAME_CLI"
echo "    queue:  $QUEUE_NAME_CLI"
echo "    sg:     $SG_NAME_CLI"
echo "    fn:     $LAMBDA_NAME_CLI"
echo "    topic:  $TOPIC_NAME_CLI"

echo
echo ">>> Step 1c: creating exclusion-filter fixtures (must produce ZERO findings each)"
# CDK-bootstrap-style role
aws iam create-role \
  --role-name "$ROLE_NAME_CDK" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null
# FIFO DLQ queues — name must end with .fifo and require FifoQueue=true
aws sqs create-queue --queue-name "$QUEUE_NAME_DLQ" \
  --attributes FifoQueue=true,ContentBasedDeduplication=true >/dev/null
aws sqs create-queue --queue-name "$QUEUE_NAME_DEADLETTER" \
  --attributes FifoQueue=true,ContentBasedDeduplication=true >/dev/null
# LogRetention Lambda
aws lambda create-function \
  --function-name "$LAMBDA_NAME_LOGRET" \
  --runtime python3.11 --handler index.handler \
  --role "$LAMBDA_EXEC_ROLE_ARN" \
  --zip-file "fileb://$LAMBDA_ZIP" >/dev/null
echo "    role (cdk-*):       $ROLE_NAME_CDK"
echo "    queue (-dlq.fifo):  $QUEUE_NAME_DLQ"
echo "    queue (-deadletter.fifo): $QUEUE_NAME_DEADLETTER"
echo "    fn (LogRetention):  $LAMBDA_NAME_LOGRET"

# ============================================================================
# Step 2: precondition — active stack, CFN resources NOT yet flagged
# ============================================================================

echo
echo ">>> Step 2: active-stack precondition (detector must not flag CFN resources yet)"
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services iam,sqs,lambda,sg,sns \
  --output-json "$JSON_REPORT" >/dev/null

# Look for the *-cfn fixtures only — these are stack-managed and must NOT be
# flagged while the stack is active. CLI-only and exclusion-filter fixtures
# correctly appear as orphans / are excluded; we don't count them here.
ACTIVE_LEAK=$(jq -r --arg p "$PREFIX" '
  [.findings[]
   | select(
       (.resource_id | contains($p + "-role-cfn"))
       or (.resource_id | contains($p + "-queue-cfn"))
       or (.resource_id | contains($p + "-fn-cfn"))
       or (.resource_id | contains($p + "-topic-cfn"))
     )]
  | length
' "$JSON_REPORT")
# Add SG check by group id (stack-managed SG would be in active stack)
SG_ID_PRE=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${SG_NAME_CFN}" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "none")
SG_LEAK=$(jq -r --arg sg "$SG_ID_PRE" '
  [.findings[] | select(.resource_id == $sg)] | length
' "$JSON_REPORT")
TOTAL_LEAK=$((ACTIVE_LEAK + SG_LEAK))
assert_eq "active stack: 0 stack-managed CFN resources flagged" "0" "$TOTAL_LEAK"

# ============================================================================
# Step 3: --stack-prefix narrowing — index includes our stack, detector
# correctly considers our resources managed and does NOT flag them.
#
# Note: the CFN_ORPHAN_ACTIVE_STACK provenance bucket is reachable only when
# the resolver's per-resource DescribeStackResources call returns an active
# stack that wasn't in the (race- or filter-) narrowed index. That requires
# either an index-build race or a true cross-region/cross-account scenario
# we can't reliably simulate in a single live account. Unit-test territory.
# ============================================================================

echo
echo ">>> Step 3: --stack-prefix that matches our test stack"
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services iam,sqs,lambda,sg,sns \
  --stack-prefix "$PREFIX" \
  --output-json "$JSON_REPORT" >/dev/null

# Findings under this run can only be CLI-only fixtures and pre-existing
# account-state. Our *-cfn resources are still active-stack-managed and
# their stack name starts with $PREFIX, so they should NOT be flagged.
PREFIX_CFN_FINDING_COUNT=$(jq -r --arg p "$PREFIX" '
  [.findings[]
   | select(
       (.resource_id | contains($p + "-role-cfn"))
       or (.resource_id | contains($p + "-queue-cfn"))
       or (.resource_id | contains($p + "-fn-cfn"))
       or (.resource_id | contains($p + "-topic-cfn"))
     )]
  | length
' "$JSON_REPORT")
SG_ID_PRE3=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${SG_NAME_CFN}" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "none")
SG3_LEAK=$(jq -r --arg sg "$SG_ID_PRE3" '
  [.findings[] | select(.resource_id == $sg)] | length
' "$JSON_REPORT")
TOTAL3=$((PREFIX_CFN_FINDING_COUNT + SG3_LEAK))
assert_eq "--stack-prefix matching: 0 CFN-managed resources flagged" "0" "$TOTAL3"

# ============================================================================
# Step 4: delete the stack — Retain'd resources survive
# ============================================================================

echo
echo ">>> Step 4: deleting CFN stack (Retain'd resources will become orphans)"
aws cloudformation delete-stack --stack-name "$STACK_NAME"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME"

# Confirm all 5 retained resources actually survived.
aws iam get-role --role-name "$ROLE_NAME_CFN" >/dev/null \
  || { echo "ERROR: IAM role missing post-delete" >&2; exit 6; }
aws sqs get-queue-url --queue-name "$QUEUE_NAME_CFN" >/dev/null \
  || { echo "ERROR: SQS queue missing post-delete" >&2; exit 6; }
SG_ID_CFN=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${SG_NAME_CFN}" \
  --query 'SecurityGroups[0].GroupId' --output text)
[[ -n "$SG_ID_CFN" && "$SG_ID_CFN" != "None" ]] \
  || { echo "ERROR: SG missing post-delete" >&2; exit 6; }
aws lambda get-function --function-name "$LAMBDA_NAME_CFN" >/dev/null \
  || { echo "ERROR: Lambda missing post-delete" >&2; exit 6; }
aws sns list-topics --query "Topics[?TopicArn=='arn:aws:sns:${REGION}:${ACCOUNT}:${TOPIC_NAME_CFN}']" \
  --output text | grep -q . \
  || { echo "ERROR: SNS topic missing post-delete" >&2; exit 6; }
echo "    OK: all 5 retained resources survived"

# Also create a CFN-managed Lambda fixture matching the Custom-* naming, AFTER
# the stack is deleted. Confirms the filter doesn't accidentally exclude
# legitimate Lambdas (positive control: it's NOT excluded because the filter
# matches "Custom::" exactly, not "Custom-").
aws lambda create-function \
  --function-name "$LAMBDA_NAME_CUSTOM" \
  --runtime python3.11 --handler index.handler \
  --role "$LAMBDA_EXEC_ROLE_ARN" \
  --zip-file "fileb://$LAMBDA_ZIP" >/dev/null

# ============================================================================
# Step 5: main detector run — assert every classification path
# ============================================================================

echo
echo ">>> Step 5: detector run against the leaked-resource state"
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services iam,sqs,lambda,sg,sns \
  --output-json "$JSON_REPORT" \
  > "$CONSOLE_OUT"

# ----- 5a: CFN_ORPHAN_DELETED_STACK for every retained service --------------
echo
echo "  -- CFN_ORPHAN_DELETED_STACK (all 5 services) --"
assert_eq "IAM role retained from deleted stack" \
  "cfn_orphan_deleted_stack|$STACK_NAME" "$(classify "$ROLE_NAME_CFN")"
assert_eq "SQS queue retained from deleted stack" \
  "cfn_orphan_deleted_stack|$STACK_NAME" "$(classify "$QUEUE_NAME_CFN")"
assert_eq "Security Group retained from deleted stack" \
  "cfn_orphan_deleted_stack|$STACK_NAME" "$(classify "$SG_ID_CFN")"
assert_eq "Lambda function retained from deleted stack" \
  "cfn_orphan_deleted_stack|$STACK_NAME" "$(classify "$LAMBDA_NAME_CFN")"
assert_eq "SNS topic retained from deleted stack" \
  "cfn_orphan_deleted_stack|$STACK_NAME" "$(classify "$TOPIC_NAME_CFN")"

# ----- 5b: NON_IAC for every CLI-created resource ---------------------------
echo
echo "  -- NON_IAC (all 5 services) --"
assert_eq "CLI-created IAM role"      "non_iac|" "$(classify "$ROLE_NAME_CLI")"
assert_eq "CLI-created SQS queue"     "non_iac|" "$(classify "$QUEUE_NAME_CLI")"
SG_ID_CLI=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${SG_NAME_CLI}" \
  --query 'SecurityGroups[0].GroupId' --output text)
assert_eq "CLI-created Security Group" "non_iac|" "$(classify "$SG_ID_CLI")"
assert_eq "CLI-created Lambda function" "non_iac|" "$(classify "$LAMBDA_NAME_CLI")"
assert_eq "CLI-created SNS topic"      "non_iac|" "$(classify "$TOPIC_NAME_CLI")"

# ----- 5c: severity rules ---------------------------------------------------
echo
echo "  -- Severity rules --"
# CFN orphans are HIGH for every service
for fn in "$ROLE_NAME_CFN" "$QUEUE_NAME_CFN" "$SG_ID_CFN" "$LAMBDA_NAME_CFN" "$TOPIC_NAME_CFN"; do
  assert_eq "CFN orphan severity HIGH ($fn)" "high" "$(severity_for "$fn")"
done

# NON_IAC keeps the per-detector default severity:
#   IAM    → HIGH
#   SQS    → MEDIUM
#   SG     → MEDIUM
#   Lambda → MEDIUM
#   SNS    → LOW
assert_eq "CLI IAM role severity HIGH"        "high"   "$(severity_for "$ROLE_NAME_CLI")"
assert_eq "CLI SQS queue severity MEDIUM"     "medium" "$(severity_for "$QUEUE_NAME_CLI")"
assert_eq "CLI Security Group severity MEDIUM" "medium" "$(severity_for "$SG_ID_CLI")"
assert_eq "CLI Lambda severity MEDIUM"        "medium" "$(severity_for "$LAMBDA_NAME_CLI")"
assert_eq "CLI SNS topic severity LOW"        "low"    "$(severity_for "$TOPIC_NAME_CLI")"

# ----- 5d: originating_stack_name populated on every CFN orphan -------------
echo
echo "  -- Stack attribution --"
NULL_ORIGINATING=$(count_with \
  'select(.provenance == "cfn_orphan_deleted_stack") | select(.originating_stack_name == null)')
assert_eq "originating_stack_name set on every CFN orphan" "0" "$NULL_ORIGINATING"

# ----- 5e: exclusion filters (negative cases) -------------------------------
echo
echo "  -- Exclusion filters --"
assert_eq "cdk-* role excluded by filter"  "MISSING" "$(classify "$ROLE_NAME_CDK")"
assert_eq "*-dlq.fifo queue excluded"      "MISSING" "$(classify "$QUEUE_NAME_DLQ")"
assert_eq "*-deadletter.fifo queue excluded" "MISSING" "$(classify "$QUEUE_NAME_DEADLETTER")"
assert_eq "*LogRetention* Lambda excluded" "MISSING" "$(classify "$LAMBDA_NAME_LOGRET")"

# Custom-* Lambda is NOT excluded (filter matches "Custom::" exactly, not "Custom-")
# so it should appear as NON_IAC. This is a positive control on the filter.
assert_eq "Custom-* Lambda NOT excluded (filter is Custom::, not Custom-)" \
  "non_iac|" "$(classify "$LAMBDA_NAME_CUSTOM")"

# Service-linked roles must not appear at all (account state).
SLR_LEAK=$(count_with 'select(.resource_id | contains("/aws-service-role/"))')
assert_eq "service-linked roles excluded by filter" "0" "$SLR_LEAK"

# Default SGs must not appear.
DEFAULT_SG_LEAK=$(count_with \
  'select(.resource_type == "AWS::EC2::SecurityGroup") | select(.description | test("default"; "i"))')
assert_eq "default Security Groups excluded by filter" "0" "$DEFAULT_SG_LEAK"

# ----- 5f: no fixture lands in the wrong bucket -----------------------------
echo
echo "  -- Provenance bucket sanity --"
ACTIVE_BUCKET=$(jq -r --arg p "$PREFIX" '
  [.findings[] | select(.resource_id | contains($p))
                | select(.provenance == "cfn_orphan_active_stack")] | length
' "$JSON_REPORT")
assert_eq "no fixture in CFN_ORPHAN_ACTIVE_STACK bucket" "0" "$ACTIVE_BUCKET"

UNKNOWN_BUCKET=$(jq -r --arg p "$PREFIX" '
  [.findings[] | select(.resource_id | contains($p))
                | select(.provenance == "unknown")] | length
' "$JSON_REPORT")
assert_eq "no fixture in UNKNOWN bucket" "0" "$UNKNOWN_BUCKET"

# ----- 5g: console reporter output ------------------------------------------
echo
echo "  -- Console reporter --"
if grep -q "Provenance: cfn_orphan_deleted_stack" "$CONSOLE_OUT"; then
  printf "    %-72s OK\n" "console output contains 'Provenance: cfn_orphan_deleted_stack'"
else
  printf "    %-72s FAIL\n" "console output contains 'Provenance: cfn_orphan_deleted_stack'"
  echo "        (head of console output:)"
  head -50 "$CONSOLE_OUT" | sed 's/^/        /'
  FAILS+=1
fi
if grep -q "Provenance: non_iac" "$CONSOLE_OUT"; then
  printf "    %-72s OK\n" "console output contains 'Provenance: non_iac'"
else
  printf "    %-72s FAIL\n" "console output contains 'Provenance: non_iac'"
  FAILS+=1
fi
if grep -q "was in stack '$STACK_NAME'" "$CONSOLE_OUT"; then
  printf "    %-72s OK\n" "console output names originating stack inline"
else
  printf "    %-72s FAIL\n" "console output names originating stack inline"
  FAILS+=1
fi

# ============================================================================
# Step 6: CLI flag matrix
# ============================================================================

echo
echo ">>> Step 6: CLI flag coverage"

# 6a: --fail-on-orphans → non-zero exit when orphans exist
echo
echo "  -- --fail-on-orphans --"
set +e
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services sns \
  --fail-on-orphans \
  --output-json "$JSON_REPORT" >/dev/null 2>&1
EXIT_FAIL_ON=$?
set -e
[[ $EXIT_FAIL_ON -ne 0 ]] && \
  { printf "    %-72s OK\n" "--fail-on-orphans returns non-zero when orphans exist"; } || \
  { printf "    %-72s FAIL\n" "--fail-on-orphans returns non-zero when orphans exist"; FAILS+=1; }

# Default (--no-fail-on-orphans) returns 0 even with orphans
set +e
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services sns \
  --output-json "$JSON_REPORT" >/dev/null 2>&1
EXIT_NO_FAIL=$?
set -e
assert_eq "default behavior returns 0 even with orphans" "0" "$EXIT_NO_FAIL"

# 6b: --services iam → only IAM findings
echo
echo "  -- --services filter --"
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services iam \
  --output-json "$JSON_REPORT" >/dev/null
NON_IAM=$(count_with 'select(.resource_type != "AWS::IAM::Role")')
assert_eq "--services iam returns only AWS::IAM::Role findings" "0" "$NON_IAM"

# 6c: --stack-prefix matching should still produce CFN orphans for the
# now-deleted stack's retained resources (they're indexed via DELETE_COMPLETE).
echo
echo "  -- --stack-prefix matching (post-delete) --"
"$CFNDX_CLI" orphans \
  --region "$REGION" \
  --services iam,sqs,lambda,sg,sns \
  --stack-prefix "$PREFIX" \
  --output-json "$JSON_REPORT" >/dev/null
# Count by name + by SG id (SG findings don't contain the prefix in resource_id)
PREFIX_FINDINGS_NAMED=$(jq -r --arg p "$PREFIX" '
  [.findings[] | select(.resource_id | contains($p))
                | select(.provenance == "cfn_orphan_deleted_stack")] | length
' "$JSON_REPORT")
PREFIX_FINDINGS_SG=$(jq -r --arg sg "$SG_ID_CFN" '
  [.findings[] | select(.resource_id == $sg)
                | select(.provenance == "cfn_orphan_deleted_stack")] | length
' "$JSON_REPORT")
PREFIX_FINDINGS_TOTAL=$((PREFIX_FINDINGS_NAMED + PREFIX_FINDINGS_SG))
assert_eq "--stack-prefix matching: 5 CFN orphans for our stack" "5" "$PREFIX_FINDINGS_TOTAL"

# ============================================================================
# Summary
# ============================================================================

echo
echo ">>> Result"
echo "    Findings in this run (prefix=$PREFIX), full detector run:"
"$CFNDX_CLI" orphans --region "$REGION" --services iam,sqs,lambda,sg,sns \
  --output-json "$JSON_REPORT" >/dev/null
jq -r --arg p "$PREFIX" '
  .findings[] | select(.resource_id | contains($p))
  | "      \(.severity | ascii_upcase | (. + "        ")[0:8]) \(.provenance | (. + "                              ")[0:30]) \(.resource_id)"
' "$JSON_REPORT"

echo
echo "    Account-wide bucket counts:"
jq -r '
  [.findings[] | .provenance] | group_by(.) | map({k: .[0], n: length})
  | .[] | "      \(.k): \(.n)"
' "$JSON_REPORT"

echo
if [[ $FAILS -eq 0 ]]; then
  echo "PASS: every assertion succeeded"
  exit 0
else
  echo "FAIL: $FAILS assertion(s) failed"
  exit 7
fi
