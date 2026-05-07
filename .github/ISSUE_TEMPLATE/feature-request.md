---
name: "✨ Feature Request"
about: "Suggest an enhancement or new capability for BKS"
title: "[FEATURE] "
labels: ["type: enhancement"]
---

## Summary
One-line description:

## Affected Area
- [ ] CLI (new command or flag)
- [ ] Library API (`bedrock_keys_security` package)
- [ ] Detection content (new Sigma rule, EventBridge pattern, CloudTrail Lake or Athena query, CloudWatch Insights query)
- [ ] SCP template (new policy or variant in `scps/`)
- [ ] IaC module (`scps/terraform/` or `scps/cloudformation/`)
- [ ] Documentation
- [ ] Other:

## Motivation & Use Case
What problem does this solve? Who benefits? Be specific:

## Proposed Solution
How should this work from a user's perspective?

## Example Usage

```bash
# CLI example, or YAML / JSON / SQL for detection rules and SCPs
bks new-command --some-flag value
```

## Alternative Approaches
Other ways to solve this? Why is your proposal preferred?

## Implementation Notes (optional)

## Scope Boundary
- [ ] Stays within BKS's scope (Bedrock API key security lifecycle: discovery, incident response, forensics, cleanup, prevention, detection content).
- [ ] Not already covered by existing AWS native tooling or third-party tools.

## Related
- Related to #
- Blocks #
