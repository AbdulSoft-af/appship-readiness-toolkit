# AppShip software release checklist

- [ ] Re-run `python -m compileall -q app.py appship tests`.
- [ ] Re-run `python -m unittest discover -s tests -v`.
- [ ] Smoke-test the Desktop UI on at least one desktop OS with Tkinter, including Local AI Settings and timeout validation.
- [ ] Run CLI `--help`, `doctor`, the sample Android scan, and verify the Gradle bootstrap version/checksum strings match.
- [ ] Confirm `VERSION.txt`, `appship.__version__`, UI version, README and release tag match.
- [ ] Re-check current Google Play and Apple official policy links; update `appship/policy.py` and `POLICY_SNAPSHOT.json` if policy changed.
- [ ] Inspect the Git diff for secrets, test reports containing local paths, machine-specific files, generated caches and duplicate code.
- [ ] Verify the final ZIP contains one source tree, not nested old release ZIPs or `__pycache__` files.
- [ ] Run `.github/workflows/android-sample-build.yml` on GitHub and inspect the real Gradle build result before claiming the demo builds on CI.
- [ ] If validating AI repair, install Ollama and a coding model and execute an end-to-end patch/build test.
- [ ] If validating IPA signatures, run on macOS with `codesign` against a real signed IPA.
- [ ] Publish as a Release Candidate until broader real-device/framework testing has been completed.
- [ ] Do not advertise Store approval, full OS sandboxing, a complete SBOM, or direct Store upload unless those features are separately implemented and tested.
