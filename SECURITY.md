# Security Policy

## Supported version

Security fixes target the latest release on the default branch. This project is currently a Release Candidate.

## Reporting a vulnerability

Do not open a public issue with a live exploit, production credential, signing key, private customer source or personal data. Until a private security reporting channel is configured for this repository, contact the repository maintainer privately through a verified GitHub profile/contact method and share only the minimum redacted reproduction needed to investigate.

## Safety model

- Static scanning reads source into memory and never extracts ZIP archives to disk.
- Build & Test is opt-in and uses a temporary source copy, but it is **not a full OS sandbox**. Source build scripts may execute arbitrary code with the current user's permissions.
- Optional AI assistance is restricted to a loopback Ollama endpoint. Never configure it to an untrusted non-loopback service.
- AI repair patches only a constrained review copy; inspect all diffs, then re-run tests.
- Source inventory records file names, sizes and hashes; do not publish it if file names themselves are confidential.
- Reports redact common secret values in build logs, but no redaction system is perfect. Review reports before sharing.

## Recommended use

Use a disposable VM/container with restricted permissions and network for untrusted projects. Never store real signing keys, `.env` values, service account credentials or production user data in a public repository or shared report.
