#!/usr/bin/env bash
set -euo pipefail

# Deploy the cfn-drift-extended integration test environment.
# Prerequisites: AWS credentials configured, aws CLI available.

STACK_NAME="drift-test-stack"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="drift-test-templates-${ACCOUNT_ID}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== cfn-drift-extended Integration Test Deployment ==="
echo "Account:  ${ACCOUNT_ID}"
echo "Region:   ${REGION}"
echo "Stack:    ${STACK_NAME}"
echo ""

# Create S3 bucket for nested template (if it doesn't exist)
echo "→ Creating template bucket..."
if ! aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
    aws s3api create-bucket --bucket "${BUCKET_NAME}" --region "${REGION}" \
        $(if [ "${REGION}" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=${REGION}"; fi)
fi

# Upload nested template
echo "→ Uploading nested template..."
aws s3 cp "${SCRIPT_DIR}/nested-template.yaml" "s3://${BUCKET_NAME}/nested.yaml"

# Deploy the main stack
echo "→ Deploying test stack..."
aws cloudformation deploy \
    --template-file "${SCRIPT_DIR}/template.yaml" \
    --stack-name "${STACK_NAME}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "${REGION}" \
    --no-fail-on-empty-changeset

echo ""
echo "✓ Test stack deployed successfully."
echo ""
echo "Next step: Run ./introduce-drift.sh to create known drift scenarios."
