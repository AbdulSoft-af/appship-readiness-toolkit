"""Read-only structural and best-effort signature checks for release artifacts.

No artifact is executed. IPA code-signature verification may safely reconstruct the
.app subtree in a temporary directory on macOS; other checks read the archive in place.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from .project_io import safe_member_name

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARTIFACT_ENTRIES = 150_000
MAX_ARTIFACT_UNCOMPRESSED = 5 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 5 * 1024 * 1024


@dataclass
class ArtifactCheck:
    check_id: str
    status: str  # PASS, FAIL, REVIEW
    title: str
    details: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ArtifactReport:
    artifact_name: str
    artifact_type: str
    size_bytes: int
    generated_at: str
    overall_status: str
    checks: List[ArtifactCheck]
    metadata: Dict[str, Any]
    limitations: List[str]

    def to_dict(self) -> dict:
        return {
            "tool": "AppShip Readiness Toolkit",
            "schema": "https://appship.dev/schemas/artifact-verification/v1",
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "size_bytes": self.size_bytes,
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "checks": [c.to_dict() for c in self.checks],
            "metadata": self.metadata,
            "limitations": self.limitations,
        }


def _find_apksigner() -> Optional[str]:
    found = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if found:
        return found
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    home = Path.home()
    roots.extend([
        str(home / "AppData/Local/Android/Sdk"),
        str(home / "Android/Sdk"),
        str(home / "Library/Android/sdk"),
    ])
    candidates: List[Path] = []
    for root_text in roots:
        if not root_text:
            continue
        root = Path(root_text).expanduser()
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        try:
            for version_dir in build_tools.iterdir():
                if version_dir.is_dir():
                    for name in ("apksigner", "apksigner.bat", "apksigner.exe"):
                        candidate = version_dir / name
                        if candidate.is_file():
                            candidates.append(candidate)
        except OSError:
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda p: (p.parent.name, p.name.lower()), reverse=True)
    return str(candidates[0])


def _find_jarsigner() -> Optional[str]:
    found = shutil.which("jarsigner")
    if found:
        return found
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        names = ("jarsigner.exe", "jarsigner.bat", "jarsigner")
        for name in names:
            candidate = Path(java_home) / "bin" / name
            if candidate.is_file():
                return str(candidate)
    return None


def _run_verifier(command: List[str], timeout: int = 120) -> tuple[int | None, str]:
    actual = list(command)
    if os.name == "nt" and actual and str(actual[0]).lower().endswith((".bat", ".cmd")):
        # A command string is needed only to launch a verified local batch script; no user shell text is accepted.
        import subprocess as _sp
        cmdline = _sp.list2cmdline(actual)
        actual = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", cmdline]
    try:
        result = subprocess.run(
            actual, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, shell=False, check=False,
        )
        output = result.stdout[-80_000:]
        # Avoid echoing common token/private-key material if a local tool happens to print paths/logs.
        output = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*([:=])\s*[^\s,;]+", r"\1\2[REDACTED]", output)
        return result.returncode, output
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return None, str(raw)[-80_000:] + f"\nVerifier timed out after {timeout} seconds."
    except OSError as exc:
        return None, f"Could not start local verifier: {exc}"


def _verify_ipa_codesign(archive: zipfile.ZipFile, infos: List[zipfile.ZipInfo], info_plist_path: str, symlink_names: List[str]) -> tuple[str, str]:
    """Verify the embedded app bundle with macOS codesign when possible.

    Extraction is restricted to the selected Payload/*.app subtree, paths are checked
    again, and symlink entries cause a REVIEW rather than being followed.
    """
    if platform.system() != "Darwin":
        return "REVIEW", "Cryptographic IPA verification requires macOS. Transfer the exact IPA to a Mac and run codesign/Xcode validation."
    codesign = shutil.which("codesign")
    if not codesign:
        return "REVIEW", "The macOS codesign utility was not found. Install/repair Xcode Command Line Tools and retry."
    if symlink_names:
        return "REVIEW", "The IPA contains symbolic links. AppShip will not recreate these links during verification; verify the IPA with Apple's Xcode/Transporter tools on macOS."

    parts = PurePosixPath(info_plist_path).parts
    app_index = next((i for i, part in enumerate(parts) if part.lower().endswith(".app")), None)
    if app_index is None:
        return "FAIL", "Could not determine the .app bundle root from Payload metadata."
    app_prefix = "/".join(parts[:app_index + 1])
    with tempfile.TemporaryDirectory(prefix="appship_ipa_codesign_") as temp_dir:
        root = Path(temp_dir).resolve()
        app_root = (root / Path(*PurePosixPath(app_prefix).parts)).resolve()
        if root not in app_root.parents:
            return "FAIL", "Resolved app bundle path escaped the temporary verification directory."
        found_file = False
        directory_modes: List[tuple[Path, int]] = []
        for info in infos:
            name = info.filename.replace("\\", "/").rstrip("/")
            if name != app_prefix and not name.startswith(app_prefix + "/"):
                continue
            if not safe_member_name(name):
                return "FAIL", f"Unsafe IPA member name inside app bundle: {name[:160]}"
            target = (root / Path(*PurePosixPath(name).parts)).resolve()
            if root not in target.parents and target != root:
                return "FAIL", f"App bundle member escaped verification directory: {name[:160]}"
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                stored_mode = (info.external_attr >> 16) & 0o777
                if stored_mode:
                    directory_modes.append((target, stored_mode))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            stored_mode = (info.external_attr >> 16) & 0o777
            if stored_mode:
                try:
                    target.chmod(stored_mode)
                except OSError:
                    return "REVIEW", f"Could not preserve file mode while reconstructing IPA member {name[:160]}; verify with Xcode/Transporter."
            found_file = True
        # Apply directory modes after writing children, so restrictive archive modes
        # cannot prevent safe reconstruction before the signature check.
        for directory, stored_mode in sorted(directory_modes, key=lambda entry: len(entry[0].parts), reverse=True):
            try:
                directory.chmod(stored_mode)
            except OSError:
                return "REVIEW", "Could not preserve app-bundle directory modes during reconstruction; verify with Xcode/Transporter."
        if not found_file or not app_root.is_dir():
            return "FAIL", "AppShip could not reconstruct the app bundle for codesign verification."
        code, output = _run_verifier([codesign, "--verify", "--deep", "--strict", "--verbose=2", str(app_root)], timeout=180)
        if code == 0:
            return "PASS", "macOS codesign cryptographic verification succeeded for the extracted app bundle.\n" + output[-3500:]
        if code is None:
            return "REVIEW", "macOS codesign did not complete; review the verifier output.\n" + output[-3500:]
        return "FAIL", f"macOS codesign rejected the app bundle (exit {code}).\n" + output[-3500:]


def _overall(checks: List[ArtifactCheck]) -> str:
    if any(c.status == "FAIL" for c in checks):
        return "FAIL"
    if any(c.status == "REVIEW" for c in checks):
        return "REVIEW"
    return "PASS"


def _make_report(path: Path, artifact_type: str, checks: List[ArtifactCheck], metadata: dict | None = None) -> ArtifactReport:
    try:
        size = path.stat().st_size if path.is_file() else 0
    except OSError:
        size = 0
    return ArtifactReport(
        artifact_name=path.name,
        artifact_type=artifact_type,
        size_bytes=size,
        generated_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        overall_status=_overall(checks),
        checks=checks,
        metadata=metadata or {},
        limitations=[
            "This checks package structure and attempts local signature verification where possible (APK/AAB on a configured toolchain; IPA codesign on macOS); it does not run the app.",
            "A valid cryptographic signature is not proof of app safety, policy compliance or Store approval.",
            "No upload to Google Play Console or App Store Connect is performed.",
        ],
    )


def verify_artifact(path_text: str) -> ArtifactReport:
    path = Path(path_text).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError("Choose an existing APK, AAB or IPA artifact file.")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError("The artifact file is empty.")
    if size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"Artifact exceeds the {MAX_ARTIFACT_BYTES // (1024**3)} GiB safety limit.")
    artifact_type = path.suffix.lower().lstrip(".")
    if artifact_type not in {"apk", "aab", "ipa"}:
        raise ValueError("Supported artifact extensions are .apk, .aab and .ipa.")

    checks: List[ArtifactCheck] = []
    metadata: Dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARTIFACT_ENTRIES:
                checks.append(ArtifactCheck("ZIP-001", "FAIL", "Too many archive entries", f"Found {len(infos):,} entries; maximum is {MAX_ARTIFACT_ENTRIES:,}."))
                return _make_report(path, artifact_type, checks, metadata)
            total_uncompressed = 0
            unsafe_names = []
            symlink_names = []
            for info in infos:
                if info.is_dir():
                    continue
                if not safe_member_name(info.filename):
                    unsafe_names.append(info.filename[:160])
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    symlink_names.append(info.filename[:160])
                total_uncompressed += max(0, info.file_size)
                if total_uncompressed > MAX_ARTIFACT_UNCOMPRESSED:
                    checks.append(ArtifactCheck("ZIP-002", "FAIL", "Archive expanded size exceeds limit", f"Declared uncompressed size exceeds {MAX_ARTIFACT_UNCOMPRESSED // (1024**3)} GiB."))
                    return _make_report(path, artifact_type, checks, metadata)
            if unsafe_names:
                checks.append(ArtifactCheck("ZIP-003", "FAIL", "Unsafe archive path detected", "Path traversal / absolute path member(s) detected: " + ", ".join(unsafe_names[:10])))
                return _make_report(path, artifact_type, checks, metadata)
            if symlink_names:
                checks.append(ArtifactCheck("ZIP-004", "REVIEW", "Symbolic-link entries exist", "Symbolic-link entries are not followed or extracted. Inspect the artifact packaging process."))
            checks.append(ArtifactCheck("ZIP-000", "PASS", "Archive is readable", f"{len(infos):,} entries; declared expanded size {total_uncompressed:,} bytes."))
            entries = {info.filename.replace("\\", "/"): info for info in infos if not info.is_dir()}
            low_entries = {name.lower(): name for name in entries}

            if artifact_type == "apk":
                if "androidmanifest.xml" not in low_entries:
                    checks.append(ArtifactCheck("APK-001", "FAIL", "Android manifest missing", "No root AndroidManifest.xml entry was found."))
                else:
                    checks.append(ArtifactCheck("APK-001", "PASS", "Android manifest present", "AndroidManifest.xml entry found. The binary manifest contents were not parsed here."))
                dexes = [name for name in low_entries if re.fullmatch(r"classes(\d*)\.dex", PurePosixPath(name).name)]
                if dexes:
                    checks.append(ArtifactCheck("APK-002", "PASS", "DEX bytecode present", f"Found {len(dexes)} classes*.dex file(s)."))
                else:
                    checks.append(ArtifactCheck("APK-002", "REVIEW", "No classes*.dex file detected", "This can be legitimate for unusual/native APKs, but verify that the APK contains the expected executable payload."))
                apksigner = _find_apksigner()
                if apksigner:
                    code, output = _run_verifier([apksigner, "verify", "--verbose", "--print-certs", str(path)])
                    if code == 0:
                        checks.append(ArtifactCheck("APK-SIG", "PASS", "APK signature verified", f"Local apksigner verification succeeded.\n{output[-3500:]}"))
                    elif code is None:
                        checks.append(ArtifactCheck("APK-SIG", "REVIEW", "APK signature not verified", output[-3500:]))
                    else:
                        checks.append(ArtifactCheck("APK-SIG", "FAIL", "APK signature verification failed", f"apksigner returned {code}.\n{output[-3500:]}"))
                else:
                    checks.append(ArtifactCheck("APK-SIG", "REVIEW", "Android signature verifier not found", "Install Android SDK Build Tools or add apksigner to PATH, then run this check again. The file's signature was not cryptographically verified."))

            elif artifact_type == "aab":
                required = ["base/manifest/androidmanifest.xml", "bundleconfig.pb"]
                missing = [entry for entry in required if entry not in low_entries]
                if missing:
                    checks.append(ArtifactCheck("AAB-001", "FAIL", "App Bundle structure is incomplete", "Missing expected entry(s): " + ", ".join(missing)))
                else:
                    checks.append(ArtifactCheck("AAB-001", "PASS", "App Bundle structure detected", "BundleConfig.pb and base/manifest/AndroidManifest.xml were found."))
                base_dex = any(name.startswith("base/dex/classes") and name.endswith(".dex") for name in low_entries)
                if base_dex:
                    checks.append(ArtifactCheck("AAB-002", "PASS", "Base-module DEX found", "At least one base-module DEX file was detected."))
                else:
                    checks.append(ArtifactCheck("AAB-002", "REVIEW", "Base-module DEX not detected", "Verify the bundle's base module and expected executable payload."))
                jarsigner = _find_jarsigner()
                if jarsigner:
                    code, output = _run_verifier([jarsigner, "-verify", "-verbose", "-certs", str(path)])
                    if code == 0 and "jar is unsigned" not in output.lower():
                        checks.append(ArtifactCheck("AAB-SIG", "PASS", "AAB JAR signature verified", f"Local jarsigner verification succeeded.\n{output[-3500:]}"))
                    elif code is None:
                        checks.append(ArtifactCheck("AAB-SIG", "REVIEW", "AAB signature not verified", output[-3500:]))
                    else:
                        checks.append(ArtifactCheck("AAB-SIG", "FAIL", "AAB signature verification failed", f"jarsigner returned {code} or reported an unsigned archive.\n{output[-3500:]}"))
                else:
                    checks.append(ArtifactCheck("AAB-SIG", "REVIEW", "JDK jarsigner not found", "Install a supported JDK and add jarsigner to PATH, then verify the App Bundle signature."))

            else:  # IPA
                app_plists = []
                code_resources = []
                provisioning = []
                for name in entries:
                    parts = PurePosixPath(name).parts
                    if len(parts) >= 3 and parts[0].lower() == "payload" and any(part.lower().endswith(".app") for part in parts) and parts[-1].lower() == "info.plist":
                        app_plists.append(name)
                    if "/_codesignature/coderesources" in name.lower():
                        code_resources.append(name)
                    if len(parts) >= 3 and parts[0].lower() == "payload" and parts[-1].lower() == "embedded.mobileprovision":
                        provisioning.append(name)
                if not app_plists:
                    checks.append(ArtifactCheck("IPA-001", "FAIL", "App bundle Info.plist missing", "No Payload/*.app/Info.plist was found."))
                else:
                    checks.append(ArtifactCheck("IPA-001", "PASS", "iOS app bundle metadata present", f"Found {len(app_plists)} Info.plist file(s)."))
                    info_path = sorted(app_plists, key=lambda item: (item.count("/"), item))[0]
                    info = entries[info_path]
                    if info.file_size <= MAX_METADATA_BYTES:
                        try:
                            with archive.open(info) as source:
                                raw = source.read(MAX_METADATA_BYTES + 1)
                            if len(raw) <= MAX_METADATA_BYTES:
                                parsed = plistlib.loads(raw)
                                if isinstance(parsed, dict):
                                    for key, out_key in [("CFBundleIdentifier", "bundle_identifier"), ("CFBundleShortVersionString", "version"), ("CFBundleVersion", "build")]:
                                        if parsed.get(key) is not None:
                                            metadata[out_key] = str(parsed.get(key))
                                    missing_metadata = [key for key, out_key in [("CFBundleIdentifier", "bundle_identifier"), ("CFBundleShortVersionString", "version"), ("CFBundleVersion", "build")] if not metadata.get(out_key)]
                                    checks.append(ArtifactCheck("IPA-002", "FAIL" if missing_metadata else "PASS", "iOS release metadata", "Missing required metadata: " + ", ".join(missing_metadata) if missing_metadata else f"Bundle ID {metadata.get('bundle_identifier')}; version {metadata.get('version')}; build {metadata.get('build')}."))
                                else:
                                    checks.append(ArtifactCheck("IPA-002", "FAIL", "Info.plist is not a dictionary", "The selected Info.plist could not be interpreted as a property-list dictionary."))
                            else:
                                checks.append(ArtifactCheck("IPA-002", "REVIEW", "Info.plist is too large", "Metadata size exceeds the local parsing limit."))
                        except Exception as exc:
                            checks.append(ArtifactCheck("IPA-002", "FAIL", "Info.plist parse failed", f"Could not read the iOS metadata: {exc}"))
                    else:
                        checks.append(ArtifactCheck("IPA-002", "REVIEW", "Info.plist is too large", "Metadata size exceeds the local parsing limit."))
                if code_resources:
                    checks.append(ArtifactCheck("IPA-003", "PASS", "Code-signature resources present", f"Found {len(code_resources)} CodeResources entry(s). Cryptographic signature verification was not run on this IPA file."))
                else:
                    checks.append(ArtifactCheck("IPA-003", "FAIL", "Code-signature resources missing", "No Payload/*.app/_CodeSignature/CodeResources was found. Re-archive and sign in Xcode, then inspect the resulting IPA."))
                if provisioning:
                    checks.append(ArtifactCheck("IPA-004", "PASS", "Embedded provisioning profile present", f"Found {len(provisioning)} embedded.mobileprovision file(s). This does not confirm the profile is valid for App Store distribution."))
                else:
                    checks.append(ArtifactCheck("IPA-004", "REVIEW", "Provisioning profile not found in IPA", "Some distribution workflows may package profiles differently. Verify signing/export with Xcode or Transporter."))
                if app_plists:
                    sig_status, sig_details = _verify_ipa_codesign(archive, infos, sorted(app_plists, key=lambda item: (item.count("/"), item))[0], symlink_names)
                    checks.append(ArtifactCheck("IPA-SIG", sig_status, "iOS app-bundle code signature", sig_details))
                else:
                    checks.append(ArtifactCheck("IPA-SIG", "REVIEW", "Cryptographic iOS signature not verified", "No candidate .app bundle was found for codesign verification."))

    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
        checks.append(ArtifactCheck("ZIP-ERR", "FAIL", "Artifact archive could not be read", f"The artifact is not a readable ZIP-based mobile package: {exc}"))
        return _make_report(path, artifact_type, checks, metadata)

    return _make_report(path, artifact_type, checks, metadata)


def artifact_report_markdown(report: ArtifactReport) -> str:
    lines = [
        f"# AppShip Artifact Verification — {report.artifact_name}", "",
        f"- **Overall status:** {report.overall_status}",
        f"- **Artifact type:** {report.artifact_type.upper()}",
        f"- **Size:** {report.size_bytes:,} bytes",
        f"- **Generated:** {report.generated_at}",
        "",
        "## Checks", "",
        "| Status | Check | Result |", "|---|---|---|",
    ]
    for check in report.checks:
        lines.append(f"| {check.status} | {check.title.replace('|', '/')} (`{check.check_id}`) | {check.details.replace('|', '/').replace(chr(10), ' ')} |")
    if report.metadata:
        lines.extend(["", "## Metadata", "", "```json", json.dumps(report.metadata, indent=2, ensure_ascii=False), "```"])
    lines.extend(["", "## Limits", ""])
    lines.extend(f"- {item}" for item in report.limitations)
    lines.append("")
    return "\n".join(lines)


def artifact_report_html(report: ArtifactReport) -> str:
    from html import escape
    colors = {"PASS": "#15803d", "FAIL": "#b91c1c", "REVIEW": "#b45309"}
    cards = []
    for check in report.checks:
        color = colors.get(check.status, "#475569")
        cards.append(
            f'<article class="check"><span class="badge" style="background:{color}">{escape(check.status)}</span>'
            f'<span class="rule">{escape(check.check_id)}</span><h3>{escape(check.title)}</h3>'
            f'<p>{escape(check.details)}</p></article>'
        )
    metadata = ""
    if report.metadata:
        metadata = "<section><h2>Metadata</h2><pre>" + escape(json.dumps(report.metadata, indent=2, ensure_ascii=False)) + "</pre></section>"
    status_color = colors.get(report.overall_status, "#475569")
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AppShip Artifact Verification</title>
<style>body{{margin:0;background:#f3f6fb;color:#172033;font:15px/1.6 Inter,Segoe UI,Arial,sans-serif}}header{{padding:30px max(20px,calc((100% - 980px)/2));background:#0b1220;color:#fff}}header p{{color:#c4d2e6}}main{{max-width:980px;margin:24px auto;padding:0 20px 40px}}.badge{{color:#fff;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:800}}h1{{margin:8px 0}}h2{{font-size:20px}}.check,section{{background:white;border:1px solid #e1e7f0;border-radius:12px;padding:17px 19px;margin:12px 0}}.rule{{margin-left:9px;color:#64748b;font-size:12px}}h3{{display:inline-block;margin:0 0 0 8px;font-size:17px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fb;padding:12px;border-radius:8px}}footer{{margin-top:25px;border-top:1px solid #d6dfeb;padding-top:18px;color:#64748b;font-size:13px}}@media print{{body{{background:white}}header{{background:white;color:#111;border-bottom:2px solid #111;padding:20px}}header p{{color:#333}}main{{max-width:none}}.check,section{{break-inside:avoid}}}}</style></head><body>
<header><strong style="letter-spacing:.16em;color:#93c5fd">APPSHIP · BUILD · VERIFY · SHIP</strong><h1>Artifact verification</h1><p>{escape(report.artifact_name)} — {report.artifact_type.upper()} · {report.size_bytes:,} bytes</p><p>Overall status: <span class="badge" style="background:{status_color}">{escape(report.overall_status)}</span></p></header>
<main><section><h2>What this means</h2><p>Package structure and locally available signature verification were checked. REVIEW means additional verification is needed, not necessarily that the artifact is invalid. This report does not execute the app or predict Store approval.</p></section>
<section><h2>Checks</h2>{''.join(cards)}</section>{metadata}<section><h2>Limitations</h2><ul>{''.join('<li>'+escape(x)+'</li>' for x in report.limitations)}</ul></section><footer>Generated locally by AppShip Readiness Toolkit. No Store account access or upload was performed.</footer></main></body></html>'''
