# Contributing

PRs welcome. Here's how to get started.

## Setup

```bash
git clone https://github.com/BeyondTrust/bedrock-keys-security.git
cd bedrock-keys-security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## What We're Looking For

- Bug fixes
- IaC templates (Terraform/CloudFormation)
- Additional attack scenarios
- GovCloud support
- Documentation improvements

## Before Submitting

1. Fork the repo and create a feature branch
2. Test your changes (SCPs on non-prod OUs first)
3. Make sure `bedrock-keys` still runs clean
4. No sensitive data in commits (keys, secrets, account IDs)
5. One PR per issue/feature

## Commit Messages

```
feat: Add Terraform module for SCP deployment
fix: Handle missing access keys in bedrock-keys
docs: Update SCP deployment instructions
```

## Code Style

- Python: PEP 8, 120 char line length
- Use type hints for function signatures
- Test all commands before documenting

## Testing

There is no automated test suite. Test manually before submitting:

```bash
# Test the tool runs without errors
./bedrock-keys
./bedrock-keys --json
./bedrock-keys --verbose
./bedrock-keys --decode-key "ABSKQmVkcm9ja0FQSUtleS..." # test with a sample key

# Test SCPs on non-prod OUs first - never deploy directly to production
```

## Need Help?

- [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues)
- [GitHub Discussions](https://github.com/BeyondTrust/bedrock-keys-security/discussions)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
