#!/usr/bin/env bash
set -euo pipefail

# Validate cfn-drift-extended against the known drift scenarios.
# Run this AFTER introduce-drift.sh.

STACK_NAME="drift-test-stack"
REGION="${AWS_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/drift-report.json"

echo "=== Validating cfn-drift-extended ==="
echo ""

# Run the tool
echo "→ Running cfn-drift-extended audit..."
echo ""

cfn-drift-extended audit \
    --stack-name "${STACK_NAME}" \
    --region "${REGION}" \
    --output-json "${REPORT_FILE}" \
    --no-fail-on-drift

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Validation Results"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Parse the JSON report and validate expected findings
TOTAL_FINDINGS=$(python3 -c "
import json, sys

with open('${REPORT_FILE}') as f:
    report = json.load(f)

findings = report['findings']
errors = report.get('errors', [])

print(f\"Stacks scanned:    {report['stacks_scanned']}\")
print(f\"Resources scanned: {report['resources_scanned']}\")
print(f\"Findings:          {len(findings)}\")
print(f\"Errors:            {len(errors)}\")
print()

# Expected findings
expected = {
    'drift-test-basic-lambda': {
        'inline_policy_added': ['ManualS3Access'],
        'managed_policy_attached': ['arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'],
    },
    'drift-test-processor': {
        'inline_policy_modified': ['SQSAccess'],
    },
    'drift-test-multi-drift': {
        'inline_policy_added': ['UnauthorizedEC2Access', 'UnauthorizedIAMAccess'],
        'managed_policy_attached': ['arn:aws:iam::aws:policy/AdministratorAccess'],
    },
    'drift-test-bare': {
        'inline_policy_added': ['SneakyPolicy'],
    },
}

# Roles that should be in sync
expected_clean = ['drift-test-cdk-style', 'drift-test-nested-role']

# Check expected findings
passed = 0
failed = 0

for role_name, expected_drifts in expected.items():
    role_findings = [f for f in findings if f['resource_id'] == role_name]
    for drift_type, expected_extras in expected_drifts.items():
        for extra in expected_extras:
            matched = [
                f for f in role_findings
                if f['drift_type'] == drift_type and extra in str(f.get('extra', ''))
            ]
            if matched:
                print(f'  ✓ PASS: {role_name} — {drift_type}: {extra}')
                passed += 1
            else:
                print(f'  ✗ FAIL: {role_name} — expected {drift_type}: {extra}')
                failed += 1

# Check roles that should be clean
for role_name in expected_clean:
    role_findings = [f for f in findings if f['resource_id'] == role_name]
    if not role_findings:
        print(f'  ✓ PASS: {role_name} — correctly reported as IN_SYNC')
        passed += 1
    else:
        print(f'  ✗ FAIL: {role_name} — expected IN_SYNC but got {len(role_findings)} finding(s)')
        for f in role_findings:
            print(f'         {f[\"drift_type\"]}: {f.get(\"extra\", \"\")}')
        failed += 1

print()
print(f'Results: {passed} passed, {failed} failed')
print()

if failed > 0:
    print('⚠ Some validations failed. Review the findings above.')
    sys.exit(1)
else:
    print('✓ All validations passed!')
    sys.exit(0)
")

echo ""
echo "JSON report saved to: ${REPORT_FILE}"
