# Contributing to Bug Hunter Pro

Thank you for improving Bug Hunter Pro. Contributions should preserve its defensive, authorization-first purpose and cross-platform behavior.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. Install the Nmap executable separately for network scanner development.

## Change Guidelines

1. Keep scanner requests bounded by configured timeouts.
2. Isolate individual checks so one network error cannot terminate a scan.
3. Use daemon threads and honor scanner stop events.
4. Use a separate SQLite connection for every operation under the database lock.
5. Preserve the shared finding dictionary contract in `scanners/base_scanner.py`.
6. Escape untrusted data before rendering it into dashboard or report HTML.
7. Do not add destructive payloads, broad credential lists, persistence, evasion, or unauthorized access features.
8. Keep Windows, macOS, and Linux path handling portable.

## Validation

Run these checks before submitting:

```bash
python -m compileall -q .
python -c "from main import create_app; app=create_app(); print(app.url_map)"
```

Exercise report generation and API routes with synthetic findings. Do not point automated contribution tests at public systems.

## Pull Requests

Describe the behavior changed, security implications, tests performed, and any new dependencies. Keep unrelated refactoring out of focused fixes. User-facing changes should include relevant README updates.

## Security Reports

Follow [SECURITY.md](SECURITY.md) for vulnerabilities in the project. Do not place exploit details or secrets in a public issue.
