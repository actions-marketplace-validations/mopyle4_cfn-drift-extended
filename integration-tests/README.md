# Integration Test Environment

This directory contains scripts to deploy a controlled test environment
and introduce known drift scenarios for validating cfn-drift-extended.

## Usage

```bash
# 1. Deploy the test stacks
./deploy.sh

# 2. Introduce known drift (manual changes outside CFN)
./introduce-drift.sh

# 3. Run cfn-drift-extended and verify it catches everything
./validate.sh

# 4. Clean up
./cleanup.sh
```

## Test Scenarios

| # | Scenario | Expected Detection |
|---|----------|-------------------|
| 1 | Extra inline policy added to a role | INLINE_POLICY_ADDED |
| 2 | Extra managed policy attached to a role | MANAGED_POLICY_ATTACHED |
| 3 | Extra statement added to existing inline policy | INLINE_POLICY_MODIFIED |
| 4 | Role with CDK-style external AWS::IAM::Policy (no drift) | IN_SYNC |
| 5 | Nested stack with role (no drift) | IN_SYNC |
| 6 | Multiple extra policies on one role | Multiple findings |
| 7 | Role with no policies, then add one | INLINE_POLICY_ADDED |
| 8 | Managed policy from another account attached | MANAGED_POLICY_ATTACHED |
