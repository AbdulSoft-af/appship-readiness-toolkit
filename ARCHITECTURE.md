# AppShip architecture

AppShip is a local-first Python application with no required third-party runtime package.

- `app.py`: Tkinter desktop interface.
- `appship/project_io.py`: bounded ZIP/folder intake, path safety, limited safe fixes and source ZIP generation.
- `appship/analyzer.py`: source-level detector and report data model.
- `appship/policy.py`: dated Android profile thresholds and official policy URLs.
- `appship/reports.py`: Markdown report and release checklist.
- `appship/html_report.py`: offline, escaped, branded HTML report.
- `appship/build_runner.py`: opt-in build/test execution on a temporary copy and result ZIP packaging.
- `appship/ai_assist.py`: loopback-only Ollama request, secret-aware context selection and constrained unified-diff application.
- `appship/cli.py`: local scanning, policy/doctor output, strict mode, file inventory, prepared ZIP, artifact verification and explicitly opted-in Build & Test.
- `appship/artifact_verifier.py`: APK/AAB/IPA structure and metadata inspection; local APK/AAB signature tools and macOS `codesign` verification for IPA app bundles reconstructed in a temporary directory.
- `tests/`: standard-library unit and integration tests.

## Trust boundaries

1. Static scanning does not execute project code.
2. A project archive is read in memory and never blindly extracted; archive paths, entry counts and size bounds are checked.
3. The build runner writes source to a temporary copy and invokes selected project toolchains only after explicit user consent. This is not an operating-system sandbox.
4. Local AI requests go only to loopback Ollama. The output is treated as untrusted and can patch only limited existing text files in a review copy.
5. A prepared ZIP is a new artifact. It must be re-scanned and build-tested after safe fixes because it can differ from the input source.
6. No store credentials, signing identities, private keys or upload actions are handled by AppShip.
7. Artifact verification never executes an app. IPA signature verification on macOS temporarily reconstructs only the selected `.app` subtree to run `codesign`; symlink or platform constraints produce REVIEW rather than a false PASS. Signature verification depends on local platform tools.

## Design rule

Prefer a finding plus a precise recommendation over a speculative source rewrite. Platform rules and policy thresholds are time-sensitive, so the report records the policy snapshot date and links official sources.
