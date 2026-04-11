# CipherFlag Developer Workflow Guide

## Repository Layout

| Repo | Purpose | License | Visibility |
|------|---------|---------|------------|
| `net4n6-dev/cipherflag` | Community Edition (CE) | Apache 2.0 | Public |
| `net4n6-dev/cipherflag-EE` | Enterprise Edition (EE) | Proprietary | Private |

**CE** is frozen at v1.1. It receives only security patches and community bug fixes.

**EE** is the active commercial product. It contains the full CE history plus all commercial features (Layer 0+).

## Local Setup

### Clone both repos

```bash
cd ~/projects

# Community Edition (already exists)
# git clone git@github-net4n6:net4n6-dev/cipherflag.git

# Enterprise Edition
git clone git@github-net4n6:net4n6-dev/cipherflag-EE.git
```

### Configure remotes on CE repo (already done)

```bash
cd ~/projects/cipherflag
git remote -v
# origin    git@github-net4n6:net4n6-dev/cipherflag.git
# ee        git@github-net4n6:net4n6-dev/cipherflag-EE.git
```

If the `ee` remote is missing:
```bash
git remote add ee git@github-net4n6:net4n6-dev/cipherflag-EE.git
```

---

## Workflow 1: Developing New EE Features

All new commercial features are developed on the EE repo.

```bash
cd ~/projects/cipherflag-EE

# 1. Create a feature branch from main
git checkout main
git pull origin main
git checkout -b feat/layer1-discovery-scripts

# 2. Develop, test, commit
#    ... make changes ...
git add -A
git commit -m "feat: add shared discovery scripts for endpoint platforms"

# 3. Push feature branch
git push -u origin feat/layer1-discovery-scripts

# 4. Create PR on GitHub (or merge directly)
gh pr create --title "Layer 1: Shared Discovery Scripts" --body "..."

# 5. After review, merge to main
git checkout main
git pull origin main
```

### Using worktrees for isolation (recommended for large features)

```bash
cd ~/projects/cipherflag-EE
git worktree add .claude/worktrees/layer1-scripts -b feat/layer1-scripts

# Work in the worktree
cd .claude/worktrees/layer1-scripts
# ... develop ...

# When done, push and clean up
git push origin feat/layer1-scripts
cd ~/projects/cipherflag-EE
git worktree remove .claude/worktrees/layer1-scripts
```

---

## Workflow 2: Security Patches on CE (open-source)

Security fixes and critical bugs go to CE first, then get cherry-picked to EE.

```bash
cd ~/projects/cipherflag

# 1. Create fix branch on CE
git checkout main
git pull origin main
git checkout -b fix/null-pem-crash

# 2. Fix, test, commit
git add -A
git commit -m "fix: handle NULL raw_pem in certificate scan"

# 3. Push to CE and merge
git push -u origin fix/null-pem-crash
# Merge via PR or directly:
git checkout main
git merge fix/null-pem-crash
git push origin main

# 4. Tag a patch release on CE
git tag -a v1.1.1 -m "v1.1.1 — security patch"
git push origin v1.1.1

# 5. Cherry-pick to EE
cd ~/projects/cipherflag-EE
git checkout main
git pull origin main
git cherry-pick <commit-hash-from-CE>
git push origin main
```

### Alternative: use the `ee` remote from the CE repo

```bash
cd ~/projects/cipherflag
# After merging the fix to CE main:
git push ee main  # This will fail if EE has diverged — use cherry-pick instead
```

**Important:** After Layer 0, CE and EE have diverged. You cannot `git push ee main` or `git merge` across them. Always cherry-pick individual fixes.

---

## Workflow 3: Pulling CE Bug Fixes into EE

If the community contributes a bug fix to CE that EE also needs:

```bash
cd ~/projects/cipherflag-EE

# 1. Add CE as a remote (one-time)
git remote add ce git@github-net4n6:net4n6-dev/cipherflag.git
git fetch ce

# 2. Cherry-pick the specific fix
git cherry-pick <commit-hash-from-ce/main>

# 3. Resolve conflicts if any (EE may have modified the same files)
# ... resolve ...
git cherry-pick --continue

# 4. Push
git push origin main
```

---

## Workflow 4: Running Integration Tests

The EE codebase has integration tests that require PostgreSQL.

### Start the test database

```bash
# Dedicated test container (doesn't conflict with CE or other projects)
docker run -d --name cipherflag-test-db \
  -e POSTGRES_DB=cipherflag \
  -e POSTGRES_USER=cipherflag \
  -e POSTGRES_PASSWORD=changeme \
  -p 5434:5432 \
  postgres:15-alpine

# Create test database
docker exec cipherflag-test-db psql -U cipherflag -c "CREATE DATABASE cipherflag_test;"
```

### Run tests

```bash
# Unit tests (no database needed)
go test ./... -count=1

# Integration tests (requires database)
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/store/... -v -count=1
```

### Stop the test database

```bash
docker stop cipherflag-test-db
docker start cipherflag-test-db  # restart later without recreating
```

---

## Workflow 5: Releasing EE Versions

EE versions are tagged separately from CE.

```bash
cd ~/projects/cipherflag-EE

# Tag
git tag -a v2.0.0-ee -m "v2.0.0-ee — cryptographic posture management"
git push origin v2.0.0-ee
```

EE tags use the `-ee` suffix to distinguish from CE tags (v1.0, v1.1).

---

## Port Allocation

Local development uses these ports to avoid conflicts:

| Service | Port | Project |
|---------|------|---------|
| PostgreSQL | 5432 | Testify |
| PostgreSQL | 5433 | CF-UVM (Amend) |
| PostgreSQL | 5434 | CipherFlag EE (test DB) |
| CipherFlag API | 8443 | CipherFlag CE/EE |

---

## Branch Naming Conventions

| Pattern | Example | Used For |
|---------|---------|----------|
| `feat/<name>` | `feat/layer1-scripts` | New features |
| `fix/<name>` | `fix/null-pem-crash` | Bug fixes |
| `refactor/<name>` | `refactor/zeek-pipeline` | Refactoring |
| `docs/<name>` | `docs/deployment-guide` | Documentation |
| `chore/<name>` | `chore/update-deps` | Maintenance |

---

## Quick Reference

```bash
# Where am I?
git remote -v                    # which repo
git branch                       # which branch
git log --oneline -5             # recent commits

# CE: push a fix
cd ~/projects/cipherflag
git checkout -b fix/something
# ... fix ...
git push origin fix/something

# EE: start a feature
cd ~/projects/cipherflag-EE
git checkout -b feat/something
# ... build ...
git push origin feat/something

# Cherry-pick CE fix into EE
cd ~/projects/cipherflag-EE
git remote add ce git@github-net4n6:net4n6-dev/cipherflag.git  # one-time
git fetch ce
git cherry-pick <hash>
git push origin main

# Run EE integration tests
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./internal/store/... -v
```
