"""Local-first static readiness checks for Android and iOS source projects.

This tool never executes uploaded project code and never extracts uploaded ZIPs.
It is a preflight scanner, not an official Apple/Google approval validator.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple
from .policy import DEFAULT_ANDROID_PROFILE, get_android_profile, POLICY_CHECKED_ON
import json
import re
import xml.etree.ElementTree as ET
import plistlib

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
ANDROID_API_REQUIRED = 36  # General Google Play new-app / update requirement from 2026-08-31.

@dataclass
class Finding:
    id: str
    severity: str
    platform: str
    title: str
    path: str
    detail: str
    recommendation: str
    auto_fixable: bool = False
    category: str = "technical"

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanReport:
    project_name: str
    project_source: str
    stacks: List[str]
    files_scanned: int
    total_text_bytes: int
    findings: List[Finding]
    generated_at: str
    scanner_version: str = "3.1.0"
    android_app_category: str = DEFAULT_ANDROID_PROFILE
    policy_checked_on: str = POLICY_CHECKED_ON

    @property
    def summary(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        counts["total"] = len(self.findings)
        counts["auto_fixable"] = sum(1 for f in self.findings if f.auto_fixable)
        return counts

    @property
    def indicative_score(self) -> int:
        # A prioritization indicator only, not an approval probability.
        penalty = {"critical": 25, "high": 15, "medium": 6, "low": 2, "info": 0}
        return max(0, min(100, 100 - sum(penalty.get(f.severity, 0) for f in self.findings)))

    def to_dict(self):
        return {
            "project_name": self.project_name,
            "project_source": self.project_source,
            "stacks": self.stacks,
            "files_scanned": self.files_scanned,
            "total_text_bytes": self.total_text_bytes,
            "generated_at": self.generated_at,
            "scanner_version": self.scanner_version,
            "android_app_category": self.android_app_category,
            "policy_checked_on": self.policy_checked_on,
            "indicative_score": self.indicative_score,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "limitations": [
                "Static source inspection only; the app was not built or executed.",
                "A readiness score is not a probability of store approval.",
                "Store listing declarations and runtime behavior require human verification.",
            ],
        }

TEXT_EXTENSIONS = {
    ".xml", ".gradle", ".kts", ".properties", ".java", ".kt", ".dart", ".swift",
    ".m", ".mm", ".h", ".plist", ".xcconfig", ".json", ".yaml", ".yml", ".toml",
    ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".env", ".md", ".txt",
    ".php", ".py", ".rb", ".sh", ".bat", ".ps1", ".sql", ".lock", ".pbxproj", ".podspec",
}
SKIP_PARTS = {".git", "node_modules", "vendor", "Pods", "build", "dist", ".dart_tool", ".gradle", "DerivedData", "__pycache__"}
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I), "A private-key block appears in a source/config file."),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "An AWS access-key identifier pattern appears in a source/config file."),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "A token resembling a GitHub credential appears in a source/config file."),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "A string resembling a Google API key appears in a source/config file."),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "A token resembling a Slack credential appears in a source/config file."),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{24,}"), "A bearer-token-looking value appears in a source/config file."),
    ("generic_secret", re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|storePassword|keyPassword)\s*[:=]\s*['\"]?(?!your_|example|changeme|replace|<|\$\{)[A-Za-z0-9_\-./+=]{12,}"), "A possible hard-coded credential was found. This can be a false positive; inspect it locally."),
]
DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "microphone/audio recording",
    "android.permission.ACCESS_FINE_LOCATION": "precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts write access",
    "android.permission.READ_SMS": "SMS messages",
    "android.permission.SEND_SMS": "sending SMS",
    "android.permission.READ_CALL_LOG": "call log",
    "android.permission.READ_PHONE_STATE": "phone state",
    "android.permission.READ_EXTERNAL_STORAGE": "shared storage (legacy permission)",
    "android.permission.WRITE_EXTERNAL_STORAGE": "shared storage write (legacy permission)",
    "android.permission.READ_MEDIA_IMAGES": "photos/images",
    "android.permission.READ_MEDIA_VIDEO": "videos",
    "android.permission.READ_MEDIA_AUDIO": "audio files",
    "android.permission.POST_NOTIFICATIONS": "notifications",
    "android.permission.BODY_SENSORS": "body sensors/health-related data",
}


def _normalize_path(path: str) -> str:
    normalized = str(PurePosixPath(path.replace("\\", "/")))
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _text(data: bytes, limit: int = 2_000_000) -> str:
    if len(data) > limit:
        data = data[:limit]
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return ""


def _match_paths(files: Dict[str, bytes], pattern: str) -> List[str]:
    # Portable suffix/path matching without case-sensitive filename assumptions.
    pat = pattern.lower()
    return [p for p in files if p.lower().endswith(pat)]


def _find_rooted(files: Dict[str, bytes], endings: Iterable[str]) -> List[str]:
    lower_endings = tuple(e.lower() for e in endings)
    return [p for p in files if p.lower().endswith(lower_endings)]


def _add(findings: List[Finding], fid: str, severity: str, platform: str, title: str,
         path: str, detail: str, recommendation: str, auto_fixable: bool = False,
         category: str = "technical"):
    # De-duplicate by rule id + path, keeping reports readable.
    if not any(x.id == fid and x.path == path for x in findings):
        findings.append(Finding(fid, severity, platform, title, path or "—", detail, recommendation, auto_fixable, category))


def detect_stacks(files: Dict[str, bytes]) -> List[str]:
    lower = {p.lower(): p for p in files}
    names = set(lower)
    stacks = []
    if any(p.endswith("/pubspec.yaml") or p == "pubspec.yaml" for p in names):
        stacks.append("Flutter / Dart")
    package_text = _text(files[lower[next(p for p in names if p.endswith("package.json"))]]) if any(p.endswith("package.json") for p in names) else ""
    if "react-native" in package_text.lower() or any("react-native" in p for p in names):
        stacks.append("React Native")
    if any(p.endswith("/capacitor.config.ts") or p.endswith("/capacitor.config.json") or p in {"capacitor.config.ts", "capacitor.config.json"} for p in names):
        stacks.append("Ionic / Capacitor")
    if any(p.endswith("/androidmanifest.xml") for p in names) or any(p.endswith("/build.gradle") or p.endswith("/build.gradle.kts") for p in names):
        stacks.append("Android native")
    if any(p.endswith("/info.plist") for p in names) or any(".xcodeproj/project.pbxproj" in p for p in names) or any(p.endswith("/package.swift") for p in names):
        stacks.append("iOS / Apple platform")
    if not stacks:
        stacks.append("Unknown / generic source")
    # Collapse generic Android marker when Flutter/RN describes a cross-platform project.
    if "Flutter / Dart" in stacks and "Android native" in stacks:
        stacks.remove("Android native")
    if "React Native" in stacks and "Android native" in stacks:
        stacks.remove("Android native")
    return stacks


def _scan_secrets(files: Dict[str, bytes], findings: List[Finding]):
    for path, data in files.items():
        p = path.lower()
        suffix = PurePosixPath(p).suffix
        base_name = PurePosixPath(p).name.lower()
        if suffix not in TEXT_EXTENSIONS and base_name not in {".env", ".env.local", ".env.production", ".env.development"}:
            continue
        if any(seg.lower() in SKIP_PARTS for seg in PurePosixPath(p).parts):
            continue
        if len(data) > 1_500_000:
            continue
        txt = _text(data)
        if not txt:
            continue
        for name, pattern, description in SECRET_PATTERNS:
            if pattern.search(txt):
                _add(findings, "SEC-001", "high", "All", "Possible hard-coded secret", path,
                     description, "Verify locally. Move credentials to a secure environment/secret manager, rotate exposed credentials, and never ship private keys or server secrets inside the app.", category="security")
                break
        if re.search(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", txt):
            continue


def _scan_placeholders(files: Dict[str, bytes], findings: List[Finding]):
    patterns = [
        (re.compile(r"\bcom\.example(?:\.[A-Za-z0-9_]+)*\b", re.I), "Default com.example package identifier"),
        (re.compile(r"\b(?:YOUR_API_KEY|REPLACE_ME|CHANGE_ME|your_app_name|example\.com)\b", re.I), "Template or placeholder value"),
        (re.compile(r"\bTODO\b|\bFIXME\b", re.I), "TODO/FIXME marker"),
    ]
    checked = 0
    for path, data in files.items():
        if PurePosixPath(path).suffix.lower() not in TEXT_EXTENSIONS or len(data) > 1_000_000:
            continue
        if any(seg.lower() in SKIP_PARTS for seg in PurePosixPath(path).parts):
            continue
        text_value = _text(data)
        if not text_value:
            continue
        for pattern, label in patterns:
            if pattern.search(text_value):
                _add(findings, "GEN-002", "low", "All", label, path,
                     "A possible placeholder remains in a scanned text file. Documentation and sample fixtures can produce false positives.",
                     "Review the exact occurrence and replace placeholders in release-critical files before submission.", category="quality")
                break
        checked += 1
        if checked > 20_000:
            break


def _scan_android(files: Dict[str, bytes], findings: List[Finding], required_api: int = ANDROID_API_REQUIRED, profile_key: str = DEFAULT_ANDROID_PROFILE):
    manifests = [p for p in files if p.lower().endswith("/androidmanifest.xml") or p.lower() == "androidmanifest.xml"]
    gradle_paths = [p for p in files if p.lower().endswith(("build.gradle", "build.gradle.kts"))]
    gradle_texts = {p: _text(files[p]) for p in gradle_paths}
    combined_gradle = "\n".join(gradle_texts.values())
    app_gradle_path = next((p for p in gradle_paths if "/app/" in p.lower() or p.lower().startswith("app/")), gradle_paths[0] if gradle_paths else "—")
    app_gradle_text = gradle_texts.get(app_gradle_path, combined_gradle)

    # Prefer the Android app module so a library module's SDK settings do not mask the app's release settings.
    target_match = re.search(r"(?:targetSdkVersion|targetSdk)\s*(?:=\s*)?(?:\(?\s*)?(\d{2})\b", app_gradle_text) or re.search(r"(?:targetSdkVersion|targetSdk)\s*(?:=\s*)?(?:\(?\s*)?(\d{2})\b", combined_gradle)
    compile_match = re.search(r"(?:compileSdkVersion|compileSdk)\s*(?:=\s*)?(?:\(?\s*)?(\d{2})\b", app_gradle_text) or re.search(r"(?:compileSdkVersion|compileSdk)\s*(?:=\s*)?(?:\(?\s*)?(\d{2})\b", combined_gradle)
    # Handle common Flutter Gradle indirection.
    target = int(target_match.group(1)) if target_match else None
    compile_sdk = int(compile_match.group(1)) if compile_match else None

    profile = get_android_profile(profile_key)
    if target is None:
        _add(findings, "AND-001", "medium", "Google Play", "Could not verify target SDK", app_gradle_path,
             "The scanner could not resolve a numeric targetSdk setting. Build scripts may use variables or convention plugins.",
             f"Resolve the final target SDK from the effective Gradle configuration. The selected profile '{profile.label}' uses a preflight threshold of API {required_api}; see the official target API policy for current exceptions and transitions.", category="policy")
    elif target < required_api:
        _add(findings, "AND-002", "high", "Google Play", f"Target SDK is below API {required_api}", app_gradle_path,
             f"Detected target SDK API {target}; the selected '{profile.label}' profile currently uses a threshold of API {required_api}.",
             f"Review migration to API {required_api} or higher, Android behavior changes, and dependency compatibility. Do not change the number alone without building and testing. Check the official policy for the exact app category and submission situation.", category="policy")
    else:
        _add(findings, "AND-003", "info", "Google Play", f"Target SDK appears to be API {target}", app_gradle_path,
             f"A numeric target SDK meeting the selected '{profile.label}' preflight threshold (API {required_api}) was found. This does not validate all build settings or platform exceptions.",
             "Confirm the effective release variant and run a clean release build. Recheck the official target API table on the submission date.", category="policy")

    if compile_sdk is not None and target is not None and compile_sdk < target:
        _add(findings, "AND-004", "high", "Google Play", "compileSdk is lower than targetSdk", app_gradle_path,
             f"Detected compileSdk API {compile_sdk} but targetSdk API {target}; build configuration is likely inconsistent.",
             "Set compileSdk to a compatible version at least as high as targetSdk, then verify plugin/Gradle compatibility.")

    if not any(p.lower().endswith("gradlew") or p.lower().endswith("gradlew.bat") for p in files):
        _add(findings, "AND-005", "low", "Android", "Gradle wrapper not found", "—",
             "No Gradle wrapper script was detected in the archive.",
             "Include the standard Gradle wrapper files when the project is expected to build reproducibly from source.", category="build")

    if not manifests:
        _add(findings, "AND-006", "high", "Android", "AndroidManifest.xml not found", "—",
             "Gradle files were detected but no Android manifest was found in the scanned project.",
             "Confirm this is a complete Android project or that the manifest lives in a module/root omitted from the ZIP.", category="build")
    else:
        for manifest in manifests:
            raw = _text(files[manifest])
            try:
                root = ET.fromstring(raw)
                app = root.find("application")
                if app is not None:
                    if app.attrib.get(ANDROID_NS + "debuggable", "").lower() == "true":
                        _add(findings, "AND-007", "high", "Android", "Debuggable application setting is enabled", manifest,
                             "android:debuggable is explicitly true in the manifest.",
                             "Ensure the final release variant disables debugging. Verify the merged release manifest rather than changing debug behavior blindly.", category="security")
                    if app.attrib.get(ANDROID_NS + "usesCleartextTraffic", "").lower() == "true":
                        _add(findings, "AND-008", "high", "Android", "Cleartext HTTP traffic is allowed", manifest,
                             "android:usesCleartextTraffic is true; HTTP traffic may be exposed to interception.",
                             "Prefer HTTPS and disable cleartext traffic unless a documented exception is essential. Check Network Security Config as well.", category="security")
                    if app.attrib.get(ANDROID_NS + "allowBackup", "").lower() == "true":
                        _add(findings, "AND-009", "medium", "Android", "App backup is allowed", manifest,
                             "android:allowBackup is true. This is not automatically wrong, but private app data may be included in backup depending on configuration.",
                             "Review backup/data-extraction rules against your data sensitivity and privacy promises.", category="security")
                    launchers = []
                    missing_exported = []
                    for elem in list(app):
                        if elem.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
                            continue
                        intents = elem.findall("intent-filter")
                        if not intents:
                            continue
                        exported = elem.attrib.get(ANDROID_NS + "exported")
                        is_launcher = any(
                            any((a.attrib.get(ANDROID_NS + "name") == "android.intent.action.MAIN") for a in it.findall("action")) and
                            any((c.attrib.get(ANDROID_NS + "name") == "android.intent.category.LAUNCHER") for c in it.findall("category"))
                            for it in intents
                        )
                        if is_launcher:
                            launchers.append(elem)
                        if exported is None:
                            missing_exported.append((elem.tag, elem.attrib.get(ANDROID_NS + "name", "(unnamed)"), is_launcher))
                    for tag, name, is_launcher in missing_exported:
                        _add(findings, "AND-010", "high" if target and target >= 31 else "medium", "Android", "Component with intent-filter has no android:exported", manifest,
                             f"Detected {tag} '{name}' with an intent-filter but no android:exported attribute.",
                             "Declare android:exported explicitly. For the recognizable MAIN/LAUNCHER activity the safe conventional value is true; for other components, decide based on intended external access. This issue is auto-fixable only for recognized launcher activities.",
                             auto_fixable=is_launcher, category="build")
                permissions = sorted({e.attrib.get(ANDROID_NS + "name", "") for e in root.findall("uses-permission") if e.attrib.get(ANDROID_NS + "name", "") in DANGEROUS_PERMISSIONS})
                if permissions:
                    readable = ", ".join(DANGEROUS_PERMISSIONS[p] for p in permissions)
                    _add(findings, "AND-011", "medium", "Google Play", "Sensitive permissions need policy review", manifest,
                         f"Detected permissions related to: {readable}.",
                         "Confirm every permission is required and used, request it at the right time, disclose data accurately, and complete the Play Data safety form consistently with actual behavior.", category="privacy")
                app_id = re.search(r"\bapplicationId\s*(?:=\s*)?['\"]([^'\"]+)['\"]", app_gradle_text) or re.search(r"\bapplicationId\s*(?:=\s*)?['\"]([^'\"]+)['\"]", combined_gradle)
                if app_id and ("com.example" in app_id.group(1).lower() or "your" in app_id.group(1).lower()):
                    _add(findings, "AND-012", "high", "Google Play", "Application ID looks like a placeholder", app_gradle_path,
                         f"Detected applicationId '{app_id.group(1)}'.", "Choose the permanent unique reverse-domain ID before the first publication; changing it later generally creates a different app.", category="release")
                if not re.search(r"\bversionCode\b", app_gradle_text) and not re.search(r"\bversionCode\b", combined_gradle):
                    _add(findings, "AND-013", "medium", "Android", "Could not find versionCode", app_gradle_path,
                         "No literal versionCode definition was detected in scanned Gradle files.",
                         "Verify the effective release versionCode and ensure it increases for every update. Version catalogs/variables can cause false positives.", category="release")
                if not re.search(r"\bversionName\b", app_gradle_text) and not re.search(r"\bversionName\b", combined_gradle):
                    _add(findings, "AND-014", "low", "Android", "Could not find versionName", app_gradle_path,
                         "No literal versionName definition was detected in scanned Gradle files.",
                         "Verify the effective user-facing version name for the release build.", category="release")
            except ET.ParseError as exc:
                _add(findings, "AND-015", "high", "Android", "Manifest XML is not well formed", manifest,
                     f"XML parser error: {exc}.", "Fix the XML syntax and re-run the scanner. Do not upload a malformed manifest.", category="build")

    # Privacy policy and account deletion are policy/process checks, not code-only guarantees.
    privacy_files = [p for p in files if re.search(r"(privacy.?policy|privacy_policy|privacy\.md)", p, re.I)]
    _add(findings, "POL-001", "medium" if not privacy_files else "info", "Google Play", "Privacy policy evidence check", privacy_files[0] if privacy_files else "—",
         "A privacy-policy-looking file was found." if privacy_files else "No privacy policy file was detected in the source archive; a hosted policy can exist outside the repository.",
         "Provide a public, accessible privacy policy URL in Play Console and in the app where required. Confirm the policy accurately describes actual data collection and sharing.", category="privacy")
    all_text = "\n".join(_text(v) for p, v in files.items() if PurePosixPath(p).suffix.lower() in {".kt", ".java", ".dart", ".js", ".jsx", ".ts", ".tsx", ".swift", ".xml", ".html"} and len(v) < 500_000).lower()
    account_hints = any(s in all_text for s in ["create account", "sign up", "signup", "register", "createaccount", "create_account"])
    if account_hints:
        deletion_hints = any(s in all_text for s in [
            "delete account", "deleteaccount", "delete_account", "account deletion", "remove account",
            "request account deletion", "deleteuser", "delete_user", "account-delete", "delete-account",
        ])
        external_delete_hints = any(s in all_text for s in [
            "delete-account", "delete_account", "account-deletion", "request-deletion", "data-deletion",
        ])
        severity = "medium" if deletion_hints else "high"
        detail_parts = ["Account-creation-related text or identifiers were detected."]
        detail_parts.append("Possible account-deletion UI/API hints were also found, but their behavior cannot be proven statically." if deletion_hints else "No obvious account-deletion implementation hints were found in scanned text; this may be a false positive if account creation is not actually offered.")
        if not external_delete_hints:
            detail_parts.append("No obvious external account-deletion web-resource path was detected; a hosted web page may exist outside the source archive.")
        _add(findings, "POL-002", severity, "Google Play + Apple", "Account deletion requirement needs manual verification", "—",
             " ".join(detail_parts),
             "If users can create accounts, Apple requires an easy in-app option to initiate account deletion. Google Play requires both an in-app path and an external web resource for deletion requests. Ensure associated data is deleted or legitimate retention is explained; verify the workflow end-to-end and complete the relevant Play Console declarations.", category="policy")


def _scan_ios(files: Dict[str, bytes], findings: List[Finding]):
    plists = [p for p in files if p.lower().endswith("info.plist")]
    for path in plists:
        data = files[path]
        plist = None
        try:
            plist = plistlib.loads(data)
        except Exception:
            txt = _text(data)
            try:
                plist = plistlib.loads(txt.encode("utf-8"))
            except Exception:
                plist = None
        if not isinstance(plist, dict):
            _add(findings, "IOS-001", "medium", "Apple App Store", "Could not parse Info.plist", path,
                 "Info.plist was found but this scanner could not parse it. Binary plists and unusual encodings may need Xcode validation.",
                 "Open the file in Xcode/Property List Editor and verify it is valid in the built app bundle.", category="build")
            continue
        for key, title, rec in [
            ("CFBundleIdentifier", "Bundle identifier missing", "Set a permanent reverse-domain bundle identifier and ensure it matches the provisioning profile/App Store Connect app."),
            ("CFBundleShortVersionString", "Marketing version missing", "Set the user-facing release version."),
            ("CFBundleVersion", "Build number missing", "Set a build number and increment it as required for each uploaded build."),
        ]:
            if not plist.get(key):
                _add(findings, "IOS-002", "high" if key == "CFBundleIdentifier" else "medium", "Apple App Store", title, path,
                     f"Required release metadata key '{key}' was not detected.", rec, category="release")
        bundle_id = str(plist.get("CFBundleIdentifier", ""))
        if "com.example" in bundle_id.lower() or "your_app" in bundle_id.lower():
            _add(findings, "IOS-003", "high", "Apple App Store", "Bundle identifier looks like a placeholder", path,
                 f"Detected bundle identifier '{bundle_id}'.", "Replace the placeholder with the permanent App ID before provisioning and publication.", category="release")
        ats = plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
            _add(findings, "IOS-004", "high", "Apple App Store", "App Transport Security allows arbitrary loads", path,
                 "NSAllowsArbitraryLoads is true, which weakens Apple's default transport security.",
                 "Use HTTPS and narrow exceptions to specific domains only when technically required and documented.", category="security")
        sensitive_keys = [k for k in plist if k.endswith(("UsageDescription", "AddUsageDescription"))]
        if sensitive_keys:
            _add(findings, "IOS-005", "medium", "Apple App Store", "Sensitive access purpose strings found", path,
                 "The app declares privacy-sensitive access descriptions: " + ", ".join(sensitive_keys) + ".",
                 "Ensure each message accurately explains the feature to the user and is present in the final app bundle. Also check privacy disclosures match actual behavior.", category="privacy")
    native_ios = any(".xcodeproj/project.pbxproj" in p.lower() or p.lower().endswith(".xcworkspace/contents.xcworkspacedata") or p.lower().endswith("package.swift") for p in files)
    privacy_manifests = [p for p in files if p.lower().endswith("privacyinfo.xcprivacy")]
    pod_or_packages = "\n".join(_text(v) for p, v in files.items() if p.lower().endswith(("podfile", "podfile.lock", "package.json", "package.resolved", "pubspec.yaml")) and len(v) < 500_000).lower()
    known_sdk_hint = any(x in pod_or_packages for x in ["firebase", "realm", "facebook", "googleanalytics", "adjust", "amplitude", "appsflyer", "onesignal"])
    if native_ios and known_sdk_hint and not privacy_manifests:
        _add(findings, "IOS-006", "medium", "Apple App Store", "Review privacy-manifest requirements for included SDKs", "—",
             "Some third-party SDK names associated with privacy/data processing were detected, but no PrivacyInfo.xcprivacy file was found in the source archive. A manifest is not universally required for every app; requirements depend on SDKs and API use.",
             "Check Apple's current list of SDKs requiring privacy manifests/signatures and review required-reason APIs and data collection. Add valid manifests where required, including SDK-provided manifests.", category="privacy")

    if native_ios:
        _add(findings, "IOS-007", "medium", "Apple App Store", "Apple submission metadata and runtime review", "—",
             "Static code analysis cannot inspect App Store Connect metadata, signing, screenshots, actual runtime flows or review login credentials.",
             "Use the current App Review Guidelines and complete privacy disclosures, age rating, export compliance, screenshots, support contact, signing and reviewer instructions before submission.", category="policy")


def _scan_general(files: Dict[str, bytes], findings: List[Finding], stacks: List[str]):
    if len(files) == 0:
        _add(findings, "GEN-001", "critical", "All", "No files to scan", "—", "The selected project contains no readable files.", "Choose a project folder or ZIP containing source files.")
        return
    if not any(PurePosixPath(p).name.lower() in {"readme.md", "readme.txt", "readme"} for p in files):
        _add(findings, "GEN-003", "low", "All", "README not found", "—",
             "A README was not detected in the source bundle.",
             "Document setup, build, permissions, test accounts (without secrets), environment configuration and known limitations.", category="quality")
    lockfiles = [p for p in files if PurePosixPath(p).name.lower() in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pubspec.lock", "podfile.lock", "gradle.lockfile"}]
    if any(s in stacks for s in ["Flutter / Dart", "React Native", "Ionic / Capacitor"]) and not lockfiles:
        _add(findings, "GEN-004", "low", "All", "Dependency lockfile not detected", "—",
             "No common dependency lockfile was found for this cross-platform project.",
             "Commit the appropriate lockfile when the project framework recommends it, then build from a clean checkout.", category="build")
    # Warn about floating Gradle versions: a build can change without a source change.
    for path, data in files.items():
        low = path.lower()
        if not low.endswith(("build.gradle", "build.gradle.kts", "libs.versions.toml")):
            continue
        txt = _text(data)
        dynamic_version = any(
            re.search(r"(?i)(?:latest\.release|latest\.integration|:\s*\+['\"])", line)
            and re.search(r"(?i)\b(?:implementation|api|classpath|plugin|version|id)\b", line)
            for line in txt.splitlines()
        )
        if dynamic_version:
            _add(findings, "GEN-007", "medium", "Build", "Floating dependency/plugin version", path,
                 "A Gradle declaration may use a dynamic or floating version, so a later build can resolve different code even when source has not changed.",
                 "Pin compatible versions or use a reviewed version catalog/lock strategy, then build from a clean checkout. Verify this finding against the exact dependency declaration.", category="build")
    # Inform that runtime test execution is intentionally not performed.
    _add(findings, "GEN-005", "info", "All", "Runtime/build verification not performed", "—",
         "The scanner never runs uploaded code or build scripts. Compile errors, crashes and broken flows cannot be confirmed by static scanning alone.",
         "Build in a trusted local environment and run tests on representative devices/emulators, including the release variant.", category="build")


def analyze_files(
    files: Dict[str, bytes],
    project_name: str = "Selected project",
    project_source: str = "local source",
    android_app_category: str = DEFAULT_ANDROID_PROFILE,
) -> ScanReport:
    from datetime import datetime, timezone
    normalized = {_normalize_path(k): v for k, v in files.items() if k and isinstance(v, (bytes, bytearray))}
    normalized = {k: bytes(v) for k, v in normalized.items()}
    profile = get_android_profile(android_app_category)
    stacks = detect_stacks(normalized)
    findings: List[Finding] = []
    _scan_general(normalized, findings, stacks)
    _scan_placeholders(normalized, findings)
    _scan_secrets(normalized, findings)
    if any(s in stacks for s in ["Android native", "Flutter / Dart", "React Native", "Ionic / Capacitor"]):
        _scan_android(normalized, findings, profile.required_target_api, profile.key)
        _add(findings, "POL-003", "medium", "Google Play", "Play Console declaration review required", "—",
             "The source bundle cannot prove the accuracy of the Data safety form, ads declaration, content rating, target audience, app access instructions or store listing.",
             "Compare every Play Console declaration with the final production build and third-party SDK behavior.", category="policy")
    if any(s in stacks for s in ["iOS / Apple platform", "Flutter / Dart", "React Native", "Ionic / Capacitor"]):
        _scan_ios(normalized, findings)
    if stacks == ["Unknown / generic source"]:
        _add(findings, "GEN-006", "high", "All", "Mobile platform not confidently detected", "—",
             "No recognizable Android/iOS/cross-platform project markers were found.",
             "Upload the complete project root containing build files and platform folders. This tool does not convert unrelated source into a mobile app.", category="build")
    # Findings stable order: severity first then platform / title.
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.platform, f.id, f.path))
    total_text = sum(
        len(v) for path, v in normalized.items()
        if PurePosixPath(path).suffix.lower() in TEXT_EXTENSIONS
        or PurePosixPath(path).name.lower().startswith(".env")
    )
    return ScanReport(
        project_name, project_source, stacks, len(normalized), total_text, findings,
        datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        android_app_category=profile.key,
    )
