# Contributing to AppShip

Thank you for considering a contribution.

## Development setup

- Python 3.10 or newer.
- No third-party runtime dependency is required for the scanner/CLI.
- Tkinter is needed to run the Desktop UI.

## Before opening a pull request

```bash
python -m compileall -q app.py appship tests
python -m unittest discover -s tests -v
python -m appship.cli doctor
```

Please include regression tests for new scanner rules, CLI behavior, unsafe archive handling, or patch constraints. Keep checks explainable and err toward manual review when the tool cannot infer intent reliably.

## Contribution principles

- Avoid making source changes that cannot be validated safely.
- Never commit real credentials, signing keys, user data, large build output or IDE caches.
- Keep policy values centralized and cite official platform sources in the code/docs.
- Distinguish a static finding from a confirmed runtime failure.
- Do not advertise a finding count, score, or passing build as a guarantee of app-store acceptance.
