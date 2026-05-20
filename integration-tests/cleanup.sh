#!/usr/bin/env bash
set -euo pipefail

# Clean up the integration test environment.

STACK_NAME="drift-test-stack"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="drift-test-templates-${ACCOUNT_ID}"

echo "=== Cleaning Up Integration Test Environment ==="
echo ""

# First, detach manually-attached managed policies (CFN can't delete roles with extra attachments)
echo "→ Detaching manually-attached policies..."
for role in drift-test-basic-lambda drift-test-multi-drift; do
    # List and detach non-CFN managed policies
    attached=$(aws iam list-attached-role-policies --role-name "${role}" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)
    for arn in ${attached}; do
        # Only detach policies we manually added
        if [[ "${arn}" == *"AmazonS3ReadOnlyAccess"* ]] || [[ "${arn}" == *"AdministratorAccess"* ]]; then
            aws iam detach-role-policy --role-name "${role}" --policy-arn "${arn}" 2>/dev/null || true
            echo "  Detached ${arn} from ${role}"
        fi
    done
done

# Delete manually-added inline policies
echo "→ Deleting manually-added inline policies..."
for role in drift-test-basic-lambda drift-test-multi-drift drift-test-bare; do
    policies=$(aws iam list-role-policies --role-name "${role}" --query 'PolicyNames[]' --output text 2>/dev/null || true)
    for policy in ${policies}; do
        # Only delete policies we manually added (not CFN-managed ones)
        case "${policy}" in
            ManualS3Access|UnauthorizedEC2Access|UnauthorizedIAMAccess|SneakyPolicy)
                aws iam delete-role-policy --role-name "${role}" --policy-name "${policy}" 2>/dev/null || true
                echo "  Deleted ${policy} from ${role}"
                ;;
        esac
    done
done

# Restore the modified policy on ProcessorRole to its original state
echo "→ Restoring modified policy on drift-test-processor..."
aws iam put-role-policy \
    --role-name drift-test-processor \
    --policy-name SQSAccess \
    --policy-document "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [{
            \"Effect\": \"Allow\",
            \"Action\": [\"sqs:ReceiveMessage\", \"sqs:DeleteMessage\"],
            \"Resource\": \"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:drift-test-queue\"
        }]
    }" 2>/dev/null || true

# Delete the CloudFormation stack
echo "→ Deleting CloudFormation stack..."
aws cloudformation delete-stack --stack-name "${STACK_NAME}" --region "${REGION}"
echo "  Waiting for stack deletion..."
aws cloudformation wait stack-delete-complete --stack-name "${STACK_NAME}" --region "${REGION}" 2>/dev/null || true

# Delete the S3 bucket
echo "→ Deleting template bucket..."
aws s3 rm "s3://${BUCKET_NAME}" --recursive 2>/dev/null || true
aws s3api delete-bucket --bucket "${BUCKET_NAME}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "✓ Cleanup complete."
