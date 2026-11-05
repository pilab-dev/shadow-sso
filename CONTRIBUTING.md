# Contributing to shadow-sso

Thank you for your interest in contributing! Please read this guide first.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.

## Before you start

- Search existing issues/PRs to avoid duplicates.
- For questions, use GitHub Discussions (if enabled) instead of issues.
- For security issues, see [SECURITY.md](SECURITY.md) — do not open public issues.

## Branching (GitFlow)

- `main` — production-ready, tagged releases only.
- `develop` — integration branch for the next release.
- Feature work: branch from `develop` as `feature/<short-slug>`.
- Bug fixes: `bugfix/<short-slug>` from `develop`.
- Urgent production fixes: `hotfix/<short-slug>` from `main`.
- Releases: `release/<version>` from `develop`.

Never push directly to `main` or `develop` — open a PR.

## Commit messages (Conventional Commits)

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
`ci`, `chore`, `revert`.

Examples:

- `feat(trace): add S3 storage backend`
- `fix(recorder): handle nil logger`
- `docs: update README badges`

Breaking changes: add `!` after type or `BREAKING CHANGE:` in footer.

## Development setup

```bash
git clone https://github.com/pilab-dev/shadow-sso.git
cd shadow-sso
git checkout develop
go mod download
make lint
make test
```

## Making changes

1. Fork the repo and create a feature branch from `develop`.
2. Write code + tests.
3. Run `gofmt`/`goimports` and `golangci-lint run`.
4. Run `go test -race ./...`.
5. Update `CHANGELOG.md` under `[Unreleased]`.
6. Commit using Conventional Commits.
7. Push and open a PR against `develop`.

## Pull request requirements

- Target branch: `develop` (or `main` for hotfixes).
- All CI checks green (lint, tests, race).
- Tests added/updated for code changes.
- Exported APIs documented (godoc).
- No more than a reasonable number of commits; squash WIP commits.

## Code style

- Follow `gofmt` and `go vet`.
- Respect `.golangci.yml`.
- Keep functions small and focused; prefer table-driven tests.
- Document exported symbols.

## Releasing (maintainers)

See `OPENSOURCE_PLAYBOOK.md` §20 (or `skills/opensource-playbook/PLAYBOOK.md` in this skill pack).
