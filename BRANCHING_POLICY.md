# Branching & Versioning Policy

Minimal workflow to keep branch names, package version, and changelog aligned.

## Branches

- `master`: default production branch.
- `release/x.y.z`: temporary release preparation branch.
- `hotfix/x.y.z`: created from tag `vX.Y.Z` only when an old version needs maintenance.

## Standard release flow

1. Create branch: `git checkout -b release/x.y.z master`
2. Prepare release (auto reads version from branch name):
   - `.\scripts\release.bat -Changes "Fix: ..." "Security: ..."`
3. Validate and publish:
   - `dotnet test`
   - `git commit -m "chore(release): prepare x.y.z"`
   - `git tag -a vx.y.z -m "Release vx.y.z"`
   - merge to `master`
4. Close `release/x.y.z` branch.

## Old version maintenance

Do not keep old release branches open. If needed later:

- `git checkout -b hotfix/2.0.1 v2.0.1`
