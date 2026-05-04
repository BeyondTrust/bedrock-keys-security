# Contributing

Pull requests welcome. This guide walks through the full workflow, including
the repo's signing and review requirements; read it before submitting your
first PR.

## Setup

```bash
git clone https://github.com/BeyondTrust/bedrock-keys-security.git
cd bedrock-keys-security
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Branch protection rules (read first)

The `main` branch is protected by a Repository ruleset. Your PR will be
**blocked from merging** until all of these are satisfied:

| Requirement | What it means for you |
|---|---|
| **Required signatures** | Every commit you push must be cryptographically signed (GPG or SSH). Unsigned commits will block the merge regardless of approvals. |
| **2 approving reviews** | At least two reviewers must approve the latest pushed commit. |
| **Code-owner review** | A member of `@beyondtrust/research` must be one of the approvers. |
| **Linear history** | No merge commits in the PR branch. Rebase, don't merge from upstream. |
| **Squash merge only** | The PR is squashed into a single commit on `main` at merge time. |
| **CodeQL must pass** | The Python and Actions analysis workflows must complete with no high-severity alerts. |
| **Stale review dismissal** | Force-pushing dismisses prior approvals; reviewers must re-approve the new HEAD. |
| **Last-push approval required** | The latest commit must itself be approved (a stale approval on an earlier commit doesn't count). |

## Set up commit signing

If you have not signed commits before, this is the one-time setup. Pick GPG
or SSH; both are accepted.

### Option A: GPG

```bash
# Generate a key (skip if you already have one)
gpg --full-generate-key            # choose RSA 4096, your GitHub email

# List your key and capture the long ID
gpg --list-secret-keys --keyid-format=long

# Export the public key and upload it to GitHub
gpg --armor --export <KEY_ID>      # copy the output
# → https://github.com/settings/gpg/new

# Tell git to sign every commit with this key
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

### Option B: SSH

```bash
# Use an existing SSH key or generate a new one
ssh-keygen -t ed25519 -C "your-email@example.com"

# Tell git to sign with SSH
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Upload the public key to GitHub as a SIGNING key (not just an auth key)
# → https://github.com/settings/ssh/new (key type: Signing Key)
```

### Verify your setup works

```bash
git commit --allow-empty -m "test: verify signing"
git log -1 --show-signature
# Should show "Good signature" (GPG) or "Good "git" signature" (SSH)
```

## PR workflow

```bash
# 1. Fork on GitHub, then clone YOUR fork
git clone git@github.com:<your-username>/bedrock-keys-security.git
cd bedrock-keys-security
git remote add upstream https://github.com/BeyondTrust/bedrock-keys-security.git

# 2. Create a topic branch off the latest main
git fetch upstream
git checkout -b fix/short-description upstream/main

# 3. Make changes, commit with a SIGNED commit
git add path/to/file
git commit -S -m "Short imperative subject (under 70 chars)

Longer body explaining the *why*. Wrap at 72 columns. The why matters
more than the what; reviewers can read the diff for what changed."

# 4. Run the smoke checks before pushing
python3 -c "import py_compile, os; [py_compile.compile(os.path.join(r,f), doraise=True) for r,_,fs in os.walk('bedrock_keys_security') for f in fs if f.endswith('.py')]"
bks --version
bks scan --help

# 5. Push to your fork and open a PR against upstream/main
git push origin fix/short-description
gh pr create --repo BeyondTrust/bedrock-keys-security --base main --web
```

### If a reviewer requests changes

Amend or add commits, **always signed**, then force-push:

```bash
# Add a new commit (preferred for contributors: clear review history)
git commit -S -m "Address review feedback: rename foo to bar"
git push origin fix/short-description

# OR squash before force-pushing (only if you understand the implications)
git rebase -i upstream/main
# mark commits as 'squash' / 'fixup', then:
git rebase --exec 'git commit --amend --no-edit -S' upstream/main
git push --force-with-lease origin fix/short-description
```

`--force-with-lease` is safer than `--force`. It fails if anyone else pushed
to the branch since your last fetch.

### If a maintainer rebases or signs your branch

Maintainers may push directly to your fork (you allow this by checking
"Allow edits by maintainers" when opening the PR). They'll typically use this
to re-sign commits if you forgot, or to rebase onto a new `main`. Pull their
changes back with:

```bash
git fetch origin
git reset --hard origin/<your-branch-name>
```

## Commit message conventions

```
Subject line in imperative mood, under 70 chars

Body explains why this change is needed: the constraint, incident, or
rationale that prompted it. Reference issues with #N. Wrap at 72 cols.
```

- **Use English.** All commits, comments, and PR descriptions.
- **No `Co-authored-by` trailers** unless someone genuinely co-authored the
  work. The signature already establishes accountability.
- **One logical change per commit.** Refactors, fixes, and new features go
  in separate commits within the same PR if related.

## What we're looking for

- Bug fixes (especially flag-scoping, JSON serialization, or boto3 edge cases)
- Detection content additions (Sigma, CloudTrail Lake, Athena, Splunk)
- IaC improvements (additional Terraform inputs, AWS Organizations
  StackSet templates)
- Additional attack scenarios (new SCPs, new privilege-escalation paths)
- GovCloud and China-region support
- Documentation improvements (worked examples, recovery runbooks)

## Code style

- Python 3.10+. The `publish` workflow runs on 3.11. **Avoid f-string
  features that require PEP 701 (Python 3.12+)**, in particular re-using
  the same quote character inside an f-string expression. Extract a
  variable instead:

  ```python
  # Bad on 3.10/3.11 (same quote nested):
  f"{f'{"yes" if cond else "no"}'}"

  # Good:
  noun = "yes" if cond else "no"
  f"{noun}"
  ```

- PEP 8, 120-char lines.
- Type hints on function signatures.
- Default to writing no comments. Only add one when the *why* is non-obvious
  (a hidden constraint, a workaround, a behavior that would surprise a
  reader). Don't explain what well-named identifiers already say.

## Testing

There is currently no automated test suite. Every PR must pass these manual
checks before merge:

```bash
# Static syntax check (catches PEP 701 issues)
python3 -c "import py_compile, os; [py_compile.compile(os.path.join(r,f), doraise=True) for r,_,fs in os.walk('bedrock_keys_security') for f in fs if f.endswith('.py')]"

# CLI smoke tests
bks --version
bks --help
bks scan --help
bks decode-key "ABSKQmVkcm9ja..."  # offline, safe to run anywhere

# If you changed AWS-touching code, run against a sandbox account
bks scan --profile sandbox --json | python3 -m json.tool > /dev/null

# If you changed SCPs, validate JSON
for f in scps/*.json; do python3 -m json.tool "$f" > /dev/null && echo "OK $f"; done
```

Never run `cleanup` or `revoke-key` against production accounts during
development. Use `--dry-run` to preview, or a sandbox account.

## Sensitive data hygiene

- **No real AWS account IDs in commits.** Use `123456789012`-style
  placeholders.
- **No real credentials.** Even in tests or examples; every public ABSK key
  in this repo's history would be flagged by AWS GuardDuty within minutes.
- **No customer or internal incident data.** If you have real incident data
  to share, sanitize first or redirect to a private channel.

## Need help?

- [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues): bugs and feature requests
- Twitter: [@btphantomlabs](https://x.com/btphantomlabs)

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
