---
inclusion: auto
---

# Git Rules for Sentinel Repository

## NEVER force push

**`git push --force` and `git push --force-with-lease` are FORBIDDEN on this repository.**

This rule exists because a previous force push destroyed 183 commits of project history. The history was recovered, but this must never happen again.

### What to do instead:
- If a push is rejected, investigate why — do NOT force it through
- If commits need to be reverted, use `git revert` (creates new commits, preserves history)
- If a branch is behind remote, use `git pull --rebase` or `git merge`
- If you accidentally committed large files that GitHub rejects, remove them with a new commit (not by rewriting history)

### Also forbidden:
- `git reset --hard` on commits that have been pushed
- `git rebase` on commits that have been pushed to remote
- Any history-rewriting operation on shared branches

### Allowed:
- `git reset --soft` or `git reset` (unstaging) on LOCAL unpushed work
- `git rebase` on LOCAL unpushed commits before first push
- `git commit --amend` ONLY on unpushed commits
