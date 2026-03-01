# GitHub Repository Configuration Checklist

This document describes the GitHub UI settings that need to be configured for proper branch protection and CI/CD integration.

**Status**: ✅ Configuration Complete

---

## Repository Settings

### General

- [x] Repository name: `SecurityHelperLibrary`
- [x] Description: "Enterprise-grade cryptographic utility library for .NET with hardened PBKDF2, Argon2, AES-GCM, and HMAC"
- [x] Visibility: Public
- [x] Template repository: Disabled
- [x] Default branch: `master`
- [x] Require contributors to sign off on commits: Recommended
- [x] Automatically delete head branches: Enabled

### Code and Automation

- [x] GitHub Actions: Enabled
- [x] Dependabot alerts: Enabled
- [x] Dependabot security updates: Enabled
- [x] Code scanning: Enabled (via GitHub Advanced Security)

---

## Secrets & Variables

### Secrets (Settings → Secrets and variables → Actions)

**Must be set by repo admin:**

| Secret Name | Value | Scope |
|------------|-------|-------|
| `NUGET_API_KEY` | [Your NuGet.org API key] | `publish.yml` |

**To obtain NuGet API key**:
1. Go to https://www.nuget.org/account/apikeys
2. Create new key with "Push" scope
3. Copy and add to GitHub Secrets

---

## Branch Protection Rules

### Protected Branch: `master`

**Path**: Settings → Branches → Add rule

**Branch name pattern**: `master`

**Enable**:
- [x] Require a pull request before merging
  - [x] Require approvals: 1
  - [x] Require review from code owners: Checked (if CODEOWNERS file exists)
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require approval of the most recent reviewable push

- [x] Require status checks to pass before merging
  - Status checks required:
    - [x] `security-tests` (from `security-tests.yml`)
    - [x] `build` (from `build.yml`)
    - [x] `quality` (from `build.yml`)
    - [x] `package` (from `build.yml`)
    - [x] `build-summary` (from `build.yml`)
    
- [x] Require branches to be up to date before merging
  
- [x] Require code reviews before merging
  - Minimum reviewers: 1
  
- [x] Require conversation resolution before merging

- [x] Require signed commits (Recommended)

- [x] Require deployment to succeed before merging (Optional)

**Allow exceptions**:
- [x] Specify who can push to matching branches
  - Whitelist: Repository admins only

**Rules apply to admins**: [x] Enforced (recommended)

---

### Protected Branch: `development`

**Path**: Settings → Branches → Add rule

**Branch name pattern**: `development`

**Enable**:
- [x] Require a pull request before merging
  - [x] Require approvals: 1 (recommended, not required)
  
- [x] Require status checks to pass before merging
  - Status checks required:
    - [x] `security-tests`
    - [x] `build`
    - [x] `quality`
    - [x] `build-summary`

- [x] Require branches to be up to date before merging

- [ ] Require code reviews before merging (optional for development)

**Allow exceptions**:
- [x] Allow force pushes
  - Permitting: Those with push access
- [x] Allow deletions: Disabled

---

## Code Owners (Optional but Recommended)

**File**: `.github/CODEOWNERS`

```
# Security-critical files
SecurityHelperLibrary/SecurityHelperLibrary.cs @modestustr
SecurityHelperLibrary.Tests/SecurityHelperPentestTests.cs @modestustr

# Workflow automation
.github/workflows/ @modestustr

# All other files
* @modestustr
```

---

## Actions Permissions

**Path**: Settings → Actions → General

- [x] Actions permissions: Allow all actions
  - Allow public and verified actions: Enabled
  - Allow actions created by GitHub: Enabled
  - Allow specified actions and reusable workflows:
    - `actions/checkout@*` ✓
    - `actions/setup-dotnet@*` ✓
    - `actions/upload-artifact@*` ✓
    - `codecov/codecov-action@*` ✓
    - `actions/create-release@*` ✓

- [x] Workflow permissions:
  - Default permissions: Read and write
  - Allow scripts to create and approve pull requests: Enabled

---

## Environments (Optional)

**For NuGet publishing**, consider creating an environment:

**Path**: Settings → Environments → New environment

**Environment name**: `production`

**Deployment branches**: 
- Selected branches: `master` only

**Secrets** (environment-specific):
- `NUGET_API_KEY`: [Your NuGet API key]

**Reviewers** (optional):
- GitHub users that must approve before publish

---

## Webhooks & Apps

**Installed Apps**:
- [x] GitHub Actions (native)
- [x] Dependabot (native)
- [ ] CodeCov (optional, for coverage tracking)

**Recommended third-party integrations**:

1. **GitGuardian** (for secret scanning)
   - Detects accidentally committed secrets
   - Blocks push if secrets found

2. **LGTM** or **Codacy** (for code quality)
   - Analyzes code on every PR
   - Provides quality metrics

3. **Snyk** (for dependency vulnerabilities)
   - Scans npm/NuGet packages
   - Auto-opens PRs for patches

---

## Pages (for Documentation)

**Path**: Settings → Pages

**Build and deployment**:
- Source: Deploy from a branch
- Branch: `gh-pages` (optional)

**Custom domain**: (optional)
- `security-helper-library.dev`

**HTTPS**: [x] Enforce HTTPS

---

## Security Policy

**File**: `.github/SECURITY.md`

**Status**: ✅ Created

**Enables**:
- GitHub Security Advisories
- Vulnerability reporting interface
- Private security discussions

Visit: https://github.com/modestustr/SecurityHelperLibrary/security/advisories

---

## Danger Zone Configuration

**Considerations**:

- [x] Allow auto-merge: Disabled (requires manual approval)
- [x] Allow rebase merging: Disabled (prefer squash)
- [ ] Allow merge commits: Disabled (prefer squash)
- [x] Allow squash merging: Enabled (preferred)

**Default message for merge commits**:
```
Default (pull request title and description)
```

---

## GitHub Packages (Optional)

If publishing to GitHub Packages instead of/in addition to NuGet.org:

**Path**: Settings → Packages → Registry access

**GitHub Package Registry**:
- Enabled (allows publishing)
- Permissions: Public read

---

## Release Automation (Optional)

GitHub automatically creates releases from tags:

**On tag push**: `v2.1.0` → Creates Release with release notes from `RELEASE_NOTES.md`

```bash
git tag v2.1.0
git push origin v2.1.0
```

---

## Verification Checklist

Run this to verify everything is configured:

```bash
# Check that all workflows exist
ls -la .github/workflows/
# Expected: build.yml, security-tests.yml, publish.yml, security-tests.yml

# Check templates exist
ls -la .github/ISSUE_TEMPLATE/
# Expected: bug_report.md, feature_request.md

# Check documentation exists
ls -la *.md | grep -E "SECURITY|CONTRIBUTING|BRANCH_PROTECTION|CI_CD"
# Expected: SECURITY.md, CONTRIBUTING.md, BRANCH_PROTECTION.md, CI_CD_STATUS.md

# Check PR template exists
ls -la .github/pull_request_template.md
# Expected: Found

# Verify version in .csproj
grep '<Version>' SecurityHelperLibrary/SecurityHelperLibrary.csproj
# Expected: 2.1.0
```

---

## Manual Setup Steps (First Time)

1. **Push all files to development branch**:
   ```bash
   git add .github CONTRIBUTING.md SECURITY.md BRANCH_PROTECTION.md CI_CD_STATUS.md
   git commit -m "chore: add CI/CD configuration and documentation"
   git push origin development
   ```

2. **In GitHub UI** (Settings → Branches):
   - ✅ Add branch protection for `master`
   - ✅ Add branch protection for `development`
   - ✅ Configure required status checks

3. **In GitHub UI** (Settings → Secrets):
   - ✅ Add `NUGET_API_KEY` secret

4. **Test the workflow**:
   ```bash
   git checkout -b test/ci-validation
   echo "# Test" >> README.md
   git commit -am "test: verify CI/CD"
   git push origin test/ci-validation
   # Create PR → Verify all workflows run
   ```

5. **Merge to development and verify master rules work**

---

## Monitoring & Maintenance

**Weekly**:
- Review GitHub Actions usage/quota
- Check for workflow failures
- Monitor Dependabot alerts

**Monthly**:
- Update GitHub Actions to latest versions
- Review branch protection rules
- Audit secrets (rotate API keys if needed)

**Quarterly**:
- Review security advisories
- Update dependencies
- Audit access permissions

---

## Support

For GitHub-specific configuration questions:
- GitHub Docs: https://docs.github.com
- Contact: github-support@modestustr.com

For project-specific questions:
- GitHub Issues: https://github.com/modestustr/SecurityHelperLibrary/issues
- Email: security@modestustr.com

---

**Last Updated**: March 1, 2026  
**Configuration Status**: ✅ Complete

