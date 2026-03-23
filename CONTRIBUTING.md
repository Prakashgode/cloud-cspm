# Contributing

## Setup

```bash
uv sync --locked --all-extras --dev
```

## Local Checks

Run these before opening a PR:

```bash
uv run ruff format .
uv run ruff check .
uv run mypy
uv run pytest -v
```

## Guidelines

- Keep changes focused and easy to review
- Add or update tests for any new scanner or behavior change
- Prefer simple scanner logic over new abstraction layers
- Update the README or policy files when behavior changes
- Branch from `master` and open PRs back into `master`
