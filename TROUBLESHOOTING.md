# Troubleshooting

## `python` is not recognized (Windows)

Install Python 3.10+ from <https://www.python.org/downloads/windows/> and enable **Add python.exe to PATH**. Close and reopen terminals after installation. Try `py -3 --version` if `python --version` fails.

## The Desktop window will not open / Tkinter is missing

Re-run the official Python installer and include Tcl/Tk. The CLI can still run without Tkinter:

```powershell
python -m appship.cli scan .\my-app.zip --format html --output report.html
```

## `No Gradle wrapper` or missing Android toolchain

The project ZIP may not contain `gradlew`, `gradlew.bat` and the wrapper directory, or the local computer may not have a compatible JDK / Android SDK. Run `python -m appship.cli doctor`, then install the framework's official toolchain. Never add private signing files to the repository just to make a scan pass.

## Gradle or dependency resolution fails offline

Build & Test minimizes dependency/network actions by default, but Gradle wrapper bootstrapping or a native tool can still need downloads. For trusted source only, enable the dependency installation option. For untrusted projects, use a disposable VM/container with restricted permissions and networking.

## iOS build is skipped on Windows

Signed iOS Store artifacts require macOS and Xcode. A Windows scan can still identify source-level issues and prepare a checklist, but cannot create a signed App Store archive.

## Local AI cannot connect

Install/start Ollama locally, download a model such as `qwen2.5-coder:7b`, and verify `http://127.0.0.1:11434` is running. AppShip deliberately restricts the endpoint to loopback. AI assistance is optional; scanning and report export work without it.

## A prepared ZIP still has findings

Only narrow deterministic fixes are automatic. Permissions, application IDs, SDK migrations, privacy disclosure, account deletion, signing and store metadata need decisions based on the app's actual behavior. Re-scan and build-test the exact prepared ZIP; inspect its report and fix log.

## The scanner says ready, but a Store rejects the app

A static scan cannot reproduce the full app review process. Read the rejection message, compare it with the current official platform guideline, correct the underlying app behavior and submission declarations, then rebuild and test the exact release artifact.


## Artifact verification shows REVIEW

- For APK files, install Android SDK Build Tools and ensure `apksigner` is available on `PATH`, or set `ANDROID_HOME` / `ANDROID_SDK_ROOT`.
- For AAB files, install a supported JDK and ensure `jarsigner` is on `PATH`.
- For IPA files, this release inspects metadata and signature markers but does not run `codesign` against an extracted app. Validate the exact archive with Xcode or Apple's upload/validation flow on a trusted macOS machine.
- `--require-signature` fails closed when all required checks are not `PASS`. It is intended for CI policies that require confirmation, not as a statement that the app is otherwise defective.
