---
inclusion: always
---

# Sentinel — Autonomous Workflow & Release Policy

## Autonomous execution

- When given a multi-step task or a spec, work through it to completion without pausing between
  steps for approval. Do not stop early to check in on routine progress.
- Only pause for genuine decision forks where guessing wrong would waste significant work
  (e.g. "should this feature exist at all", conflicting requirements). At such forks, prefer
  making a reasonable decision and recording it over interrupting — ask only when the choice is
  both consequential and ambiguous.
- Verify before declaring done: build must be 0W/0E and the relevant tests green.

## Versioning policy (STRICT — never make big version jumps)

Versions are `MAJOR.MINOR.PATCH`. The version is bumped by exactly **one patch** per release,
**regardless of how much work was done**. A large changeset never justifies a larger jump.

Carry rule (no component may exceed 9):

- Normal: `2.5.3` → `2.5.4`.
- Patch hits 9 → carry into minor: `2.5.9` → `2.6.0`.
- Minor and patch both 9 → carry into major: `2.9.9` → `3.0.0`
  (this is the user's shorthand "2.9 → 3.0").

`version.txt` at the repo root is the single source of truth. `installer/build.ps1` stamps every
`*.csproj` (except `tools/`) and `installer/setup.iss` from it. Never hand-edit version numbers in
csproj/iss files — change `version.txt` and let the build stamp.

The bump is implemented and enforced in `installer/release.ps1` (`Get-NextVersion`). Use it rather
than computing versions by hand.

## End-of-work release sequence

When a unit of work (a spec, a feature, a fix) is complete and verified, perform a release:

1. **Update docs.** Add a `docs/CHANGELOG.md` entry headed with the version the release will
   produce — i.e. the result of the carry rule applied to the current `version.txt` (compute it
   with `installer/release.ps1 -DryRun`). The release publishes GitHub notes by extracting this
   section, so the heading must exactly match the released `MAJOR.MINOR.PATCH`. Update
   `docs/THREAT_MODEL.md`, `docs/requirements.md`, or `docs/design.md` if behavior changed.
2. **Release.** Run `installer/release.ps1`, which:
   - computes the next version per the policy and writes `version.txt`,
   - runs `installer/build.ps1` (publish Service + Agent, stamp, compile the Inno Setup installer,
     copy to `releases/<version>/`),
   - commits all changes as `Release <version>`,
   - pushes to `origin` (branch `main`),
   - creates a GitHub release `v<version>` with the installer attached (via `gh`).
3. Use `installer/release.ps1 -DryRun` first if unsure; `-NoPublish` to skip the GitHub release.

### Git safety for releases

- Push to `origin` on the current branch; never force-push (see `git-rules.md`).
- Only the release commit is created automatically. Do not amend or rewrite pushed history.
- Flag (do not commit) any file that looks like a secret before it enters a release commit.
