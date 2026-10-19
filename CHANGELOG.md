# Changelog

## v3.1.0 — 2026-10-19

### Fixed
- AI Repair now has a local Ollama settings dialog, endpoint test, installed-model discovery, saved preferences, actionable setup errors, and an opt-in in-app model download command.
- Added loopback-only Ollama health/model APIs and tests; requests continue to bypass proxy settings and remote AI endpoints remain blocked.
- Replaced the intentional failing Android demo placeholder with a minimal Android API 36 project, Java activity, unit test, plugin configuration and SHA-256-pinned Gradle bootstrap scripts for Windows/macOS/Linux.
- Added an Android sample CI workflow to build/test the real fixture and publish build outputs for inspection.
- IPA verification now attempts cryptographic app-bundle verification using `codesign --verify --deep --strict` on macOS, with safe temporary extraction of the selected `.app` subtree; non-macOS hosts honestly report REVIEW.
- Added tests for Ollama discovery, per-user settings, Android fixture completeness, and macOS/iOS signature-verification decision paths.

### Limits made explicit
- Android Gradle builds still require JDK 17, Android SDK Platform 36 and network access for first-time Gradle/Maven dependencies unless dependencies are cached.
- iOS cryptographic verification needs macOS/Xcode tools; Windows/Linux cannot truthfully verify an iOS code signature.
- A release build without the developer's valid signing configuration is not upload-ready.


## v3.0.0 — 2026-10-19

### Added
- Command-line interface: `scan`, `doctor`, `policies`, and `verify-artifact`.
- Offline branded HTML report export with HTML-escaping of project/finding content.
- Configurable Android target API profile for Standard, Wear OS, Automotive OS, Android TV, and Android XR.
- Source file inventory with SHA-256 hashes and sensitive/machine-local file markers.
- Prepared ZIP generation from CLI, including checklist, Markdown/HTML/JSON reports, inventory and limited safe-fix log.
- Strict-mode exit status for CI use when Critical/High findings exist.
- Explicit opt-in CLI Build & Test acknowledgement and separate flag for dependency/network installation.
- Dated policy snapshot, centralized official policy links, release checklist enhancements.
- GitHub Actions workflow, contribution instructions, security reporting guidance, and additional CLI/policy/HTML tests.
- Desktop Android profile selector and HTML report export.
- Desktop release-artifact verification screen for APK/AAB/IPA with asynchronous inspection and Markdown/HTML report export.
- Read-only APK/AAB/IPA structural verifier with archive traversal/size checks, metadata extraction and best-effort local Android signature verification.
- Warning for likely floating Gradle dependency/plugin versions.

### Safety and scope
- No direct Store upload was added; Store credentials remain with the developer.
- Build/Test still runs project scripts on a temporary working copy and is not a full OS sandbox.
- Static analysis and tests are not a guarantee of app quality or Store approval.

## v2.0.0 — 2026-10-19

- Local Ollama repair suggestion flow with constrained patch application to an in-memory review copy.
- Build & Test runner for supported project types, result bundle packaging and log redaction.
- Android/iOS source scanner enhancements, prepared ZIP and policy checklist.

## v1.0.0

- Initial local-first source scanner and Desktop UI.
