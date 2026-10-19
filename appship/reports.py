from __future__ import annotations
from typing import Dict, List
from .analyzer import ScanReport
from .policy import (
    GOOGLE_TARGET_API_URL, GOOGLE_USER_DATA_URL, APPLE_REVIEW_URL,
    APPLE_PRIVACY_MANIFEST_URL, POLICY_CHECKED_ON, get_android_profile,
)

SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}

def to_markdown(report: ScanReport, extra_notes: List[str] | None = None) -> str:
    s = report.summary
    stacks = ", ".join(report.stacks)
    lines = [
        f"# AppShip Readiness Report — {report.project_name}",
        "",
        f"- **Generated:** {report.generated_at}",
        f"- **Source:** {report.project_source}",
        f"- **Detected platform(s):** {stacks}",
        f"- **Files scanned:** {report.files_scanned:,}",
        f"- **Indicative score:** {report.indicative_score}/100 *(prioritization aid only; not an approval probability)*",
        f"- **Android profile:** {get_android_profile(report.android_app_category).label} (API {get_android_profile(report.android_app_category).required_target_api} preflight threshold)",
        f"- **Policy snapshot checked:** {report.policy_checked_on}",
        "",
        "## Findings summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for key in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {SEVERITY_LABEL[key]} | {s.get(key, 0)} |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings were emitted. This does not mean the app is approved or fully tested.")
    for idx, f in enumerate(report.findings, 1):
        lines.extend([
            f"### {idx}. [{SEVERITY_LABEL.get(f.severity, f.severity.upper())}] {f.title}",
            f"- **Rule:** `{f.id}`",
            f"- **Platform:** {f.platform}",
            f"- **File:** `{f.path}`",
            f"- **Category:** {f.category}",
            f"- **Auto-fixable in this tool:** {'Yes' if f.auto_fixable else 'No'}",
            f"- **Finding:** {f.detail}",
            f"- **Recommended action:** {f.recommendation}",
            "",
        ])
    if extra_notes:
        lines.extend(["## Scan/import notes", ""])
        lines.extend(f"- {note}" for note in extra_notes)
        lines.append("")
    lines.extend([
        "## Important limitations",
        "",
        "- This is local static analysis. The tool does not execute uploaded code, build the app, test runtime screens, inspect a signed APK/AAB/IPA, or submit anything to a store.",
        "- A source ZIP may omit generated or environment-specific configuration. Findings can be false positives or miss issues in resolved dependencies/build variants.",
        "- Store approval depends on current platform rules, actual behavior, SDKs, permissions, privacy declarations, content rights, account setup, signing and reviewer decisions.",
        "- Verify current official requirements before each submission:",
        f"  - Google Play target API requirements: {GOOGLE_TARGET_API_URL}",
        f"  - Google Play User Data / privacy policy / account deletion: {GOOGLE_USER_DATA_URL}",
        f"  - Apple App Review Guidelines: {APPLE_REVIEW_URL}",
        f"  - Apple privacy manifests: {APPLE_PRIVACY_MANIFEST_URL}",
        f"  - Policy snapshot checked on {POLICY_CHECKED_ON}; review source links before every submission.",
        "",
    ])
    return "\n".join(lines)


def checklist_markdown(stacks: List[str], android_profile: str = "standard") -> str:
    has_android = any(x in stacks for x in ["Android native", "Flutter / Dart", "React Native", "Ionic / Capacitor"])
    has_ios = any(x in stacks for x in ["iOS / Apple platform", "Flutter / Dart", "React Native", "Ionic / Capacitor"])
    profile = get_android_profile(android_profile)
    lines = [
        "# App Store / Google Play Release Checklist",
        "",
        f"- **Android preflight profile:** {profile.label} (target API {profile.required_target_api}+)",
        f"- **Policy snapshot checked:** {POLICY_CHECKED_ON}",
        "",
        "This checklist is a human verification aid, not an approval guarantee.",
        "",
        "## Before building",
        "- [ ] Confirm application purpose, ownership, open-source licenses and rights to all content/assets.",
        "- [ ] Remove debug-only screens, sample data, placeholder text and demo credentials.",
        "- [ ] Do not embed server secrets, private keys, signing keys or service-account credentials in source/app bundles.",
        "- [ ] Build the production/release variant from a clean checkout and record toolchain versions.",
        "- [ ] Run automated tests, lint/static analysis, dependency/security review and real-device or emulator tests.",
        "- [ ] Test network failures, empty states, slow responses, offline mode (if claimed), permissions and accessibility.",
        "",
        "## Google Play (if submitting Android)",
    ]
    if has_android:
        lines += [
            f"- [ ] Verify the effective target SDK from the final release build; selected profile '{profile.label}' uses API {profile.required_target_api}+ as a preflight threshold. Confirm category and exception details on the official page: {GOOGLE_TARGET_API_URL}",
            "- [ ] Generate and validate a signed Android App Bundle (AAB) where required; never include signing secrets in the source ZIP.",
            "- [ ] Verify application ID, versionCode, versionName, icon, screenshots, feature graphic, listing and contact information.",
            "- [ ] Review every permission and third-party SDK; complete the Data safety form accurately.",
            "- [ ] Provide a public privacy policy URL and link/text in the app as required.",
            "- [ ] If account creation is offered, provide in-app account deletion and a web deletion resource; explain any legitimate data retention.",
            "- [ ] Complete content rating, target audience, ads, app access/reviewer instructions, and other Play Console declarations.",
            "- [ ] If required for the account type, complete the Google Play closed-testing period before production access.",
        ]
    else:
        lines.append("- [ ] Android project not detected; perform this checklist if you later add an Android build.")
    lines += ["", "## Apple App Store (if submitting iOS)"]
    if has_ios:
        lines += [
            "- [ ] Build and test the Archive with a supported macOS/Xcode toolchain; verify signing, team, bundle ID and provisioning.",
            "- [ ] Increment build number, set version and test the release configuration on supported devices/OS versions.",
            f"- [ ] Review the current App Review Guidelines and all App Store Connect metadata: {APPLE_REVIEW_URL}",
            f"- [ ] Ensure privacy disclosures match actual app and SDK data collection; verify required PrivacyInfo.xcprivacy manifests and required-reason APIs where applicable: {APPLE_PRIVACY_MANIFEST_URL}",
            "- [ ] If account creation is supported, users must be able to initiate account deletion inside the app.",
            "- [ ] Provide reviewer access/instructions for gated features, plus valid support and privacy-policy links.",
            "- [ ] Verify screenshots, age rating, export compliance/encryption answers, rights to content and all required store listing assets.",
        ]
    else:
        lines.append("- [ ] iOS project not detected; perform this checklist if you later add an iOS build.")
    lines += [
        "",
        "## Final gate",
        "- [ ] Resolve all Critical/High findings or document an informed reason not to change them.",
        "- [ ] Re-run this scanner after modifications.",
        "- [ ] Install and test the exact release artifact that will be uploaded.",
        "- [ ] Check official policies again on the submission date; rules change over time.",
        "",
    ]
    return "\n".join(lines)
