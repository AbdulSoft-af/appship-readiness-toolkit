<div align="center">

  <h1>🚀 AppShip Readiness Toolkit</h1>

  <p>
    <strong>Find problems early. Fix them carefully. Ship with confidence.</strong>
  </p>

  <p>
    A practical toolkit for checking mobile app projects,
    finding common release issues, and preparing for
    Google Play and Apple App Store submission.
  </p>

  <p>
    <img src="https://img.shields.io/badge/Version-3.1.0--Beta-2563EB?style=for-the-badge"
         alt="Version 3.1.0 Beta">

    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"
         alt="Python 3.10 or newer">

    <img src="https://img.shields.io/badge/AI-Ollama%20Optional-64748B?style=for-the-badge"
         alt="Optional local AI">

    <img src="https://img.shields.io/badge/Focus-Android%20%26%20iOS-16A34A?style=for-the-badge"
         alt="Android and iOS">
  </p>

  <p>
    <a href="https://github.com/AbdulSoft/appship-readiness-toolkit/stargazers">
      <img src="https://img.shields.io/github/stars/YOUR_USERNAME/appship-readiness-toolkit?style=social"
           alt="GitHub Stars">
    </a>
  </p>

  <p>
    <a href="#features">Features</a> ·
    <a href="#getting-started">Getting Started</a> ·
    <a href="#security">Security</a> ·
    <a href="#contributing">Contributing</a>
  </p>

</div>

---

## About AppShip

AppShip is a developer tool for checking mobile app projects
before release. It helps identify common configuration issues,
review potential security risks, run available build and test
tools, and generate reports that make problems easier to understand.

The project also supports optional local AI assistance through
Ollama. Suggested code changes can be reviewed before they are
applied to a separate working copy.

AppShip is being developed to make the app release process
easier to understand and less error-prone.

> **Note:** AppShip cannot guarantee approval by Google Play or
> Apple App Store. Build results, signing, device testing, privacy
> requirements, and store policies must still be verified.

---

<p align="center">
  <img src="assets/appship-logo.svg" width="280" alt="AppShip logo">
</p>

# AppShip Readiness Toolkit

AppShip helps you check a mobile app project before you send it to Google Play or the Apple App Store. It looks for common setup problems, gives you a report you can work through, and can run selected build and test commands on a separate copy of your project.

The idea is straightforward: catch the obvious problems early and keep the checks in one place, without uploading your source code to an online scanning service.

**Current version:** `3.1.0` · **Status:** Release candidate · **License:** MIT

> AppShip is a developer aid, not an official Apple or Google validation tool. A clean report does not guarantee that an app is safe, works correctly on every device, or will be accepted by either store.

## What it can do

- Scan a project folder or ZIP file without extracting an uploaded archive to an arbitrary path.
- Check common Android and iOS configuration issues, including manifest settings, SDK markers, permissions, privacy-related files, placeholders and possible hard-coded secrets.
- Show findings by severity and export a Markdown, JSON or offline HTML report.
- Create a release checklist and a file-hash inventory for the source files.
- Apply a couple of deliberately limited fixes: add `android:exported` to a clearly identified Android launcher activity when appropriate, and create a conservative `.gitignore`. Other findings are advice, not automatic edits.
- Use an optional local Ollama model to suggest code changes. Proposed patches are reviewed before they are applied to a temporary review copy.
- Run selected build and test commands on a temporary copy when the needed toolchain is installed.
- Inspect APK, AAB and IPA files for basic package structure and run the signature checks supported by the tools available on your computer.

AppShip does **not** upload apps to either store, keep your signing keys, or replace device testing and store review.

## Get started on Windows

1. Download the project and extract it.
2. Install [Python 3.10 or newer](https://www.python.org/downloads/windows/). Make sure Tcl/Tk is included and enable **Add Python to PATH** in the installer.
3. Double-click `run_windows.bat`.
4. Choose **Open project ZIP** or **Scan project folder**, then select your project.
5. Click **Run scan** and start with any Critical or High findings.
6. Export a report, fix what applies to your app, and run the scan again.

The scanner, command-line tools and desktop interface use Python's standard library and Tkinter; no third-party Python package is needed for a normal scan.

## Command-line use

Open a terminal in the AppShip project folder. Here are a few useful commands.

Scan a project and write an HTML report:

```powershell
python -m appship.cli scan "C:\path\to\your-app" --format html --output appship-report.html
```

Scan a ZIP and create a report, checklist, inventory and prepared copy:

```powershell
python -m appship.cli scan .\my-app.zip --format json --output report.json --checklist checklist.md --inventory inventory.json --prepared-zip prepared.zip
```

Fail a CI check when Critical or High findings remain:

```powershell
python -m appship.cli scan .\my-app.zip --strict
```

Check which development tools AppShip can find:

```powershell
python -m appship.cli doctor
```

Show the bundled policy snapshot and official links:

```powershell
python -m appship.cli policies
```

Check a release file and save a report:

```powershell
python -m appship.cli verify-artifact .\app-release.aab --format html --output artifact-report.html
```

For the full list of options, run `python -m appship.cli --help` or `python -m appship.cli scan --help`.

## Optional: local AI repair

AI assistance is optional. It uses [Ollama](https://ollama.com/download) running on your own computer; AppShip does not call a hosted AI API for this feature.

1. Install Ollama and make sure its local service is running.
2. Open a project in AppShip and run a scan.
3. Select **AI Repair (Local Ollama)**.
4. In **Local AI Settings**, test the connection and refresh the model list.
5. Select an installed coding model, or download one from the settings window. Model downloads can be several gigabytes.
6. Read the suggested patch before applying it. Then run the scan and tests again.

AI-generated changes stay in AppShip's review copy; the folder you originally selected is not edited. You can undo the last patch or discard the review copy. Still read the diff: a local model can make mistakes, including changes that look reasonable but break your app.

## Build and test

AppShip can run supported build and test commands on a temporary copy. This is useful, but it is not a full operating-system sandbox. Build scripts and dependency tools can execute code with your user permissions, so only run builds for projects you trust. Keep network dependency downloads disabled unless you specifically need them.

To run AppShip's own tests:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app.py appship tests
```

There is also a small Android example in `examples/sample_android_project/`. It is intended for trying the scan and build workflow, not as a production app. Its README explains the JDK, Android SDK and first-run download requirements. The Android GitHub Actions workflow attempts a sample build; use the actual workflow result as evidence that the build passed.

## Checking APK, AAB and IPA files

Use **Verify APK/AAB/IPA** in the desktop app, or run `verify-artifact` from the CLI. The verifier checks package structure and selected metadata, then attempts the signature checks supported by the installed tools.

The result has three possible meanings:

- **PASS** — the checks that AppShip could perform on this computer passed.
- **FAIL** — at least one implemented check failed.
- **REVIEW** — a required tool or a manual/platform-specific check is still needed.

For Android, signature verification may use `apksigner` or `jarsigner`. Verifying an iOS app's code signature requires macOS and Apple's `codesign` tool; on other systems AppShip reports that further review is needed. A `PASS` is not a guarantee of runtime safety or store approval.

## Store rules change

AppShip includes a dated policy snapshot and links to the relevant official documentation. Those rules can change, and requirements may differ by app category or submission type. Check the current guidance before every release:

- [Google Play target API requirements](https://support.google.com/googleplay/android-developer/answer/11926878)
- [Google Play user data and privacy](https://support.google.com/googleplay/android-developer/answer/10144311)
- [Google Play account deletion](https://support.google.com/googleplay/android-developer/answer/13327111)
- [Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [Apple in-app account deletion](https://developer.apple.com/support/offering-account-deletion-in-your-app/)
- [Apple upload builds](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds)
- [Apple privacy manifests](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files)

## Project layout

```text
app.py                         Desktop app entry point
appship/                       Scanner, reports, AI helper and verification code
assets/                        App logo and assets
examples/sample_android_project/ Android demo project
tests/                         Automated tests
.github/workflows/              CI workflows
README.md                       Project guide
README_PASHTO.md                Pashto guide
SECURITY.md                     Security reporting guidance
CONTRIBUTING.md                 Contribution notes
```

## Before you publish

- Read the findings and check whether they apply to your app; a static scanner cannot know everything about runtime behaviour.
- Test the app on real devices or emulators.
- Check privacy declarations, account deletion, content rights, reviewer access and signing configuration yourself.
- Never commit `.env` files, API keys, passwords, signing keys, provisioning profiles or customer data.
- Read `SECURITY.md`, `CONTRIBUTING.md` and `LICENSE` before opening a pull request or redistributing the project.

Bug reports are welcome. Please include your operating system, Python version and a short, redacted error message. Do not attach private production source code or credentials.
