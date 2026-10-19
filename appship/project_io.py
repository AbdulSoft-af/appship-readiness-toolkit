"""Safe source loading/export helpers. Uploaded code is never extracted or executed."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
from typing import Dict, List, Tuple
import os
import re
import stat
import zipfile

MAX_ARCHIVE_BYTES = 250 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
MAX_MEMBER_BYTES = 15 * 1024 * 1024
MAX_FILES = 40_000
SKIP_ARCHIVE_PARTS = {".git", "node_modules", "vendor", "pods", "build", "dist", ".dart_tool", ".gradle", "deriveddata", "__pycache__", ".next", "coverage"}


def safe_member_name(name: str) -> bool:
    name = name.replace("\\", "/")
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts:
        return False
    if any(part in ("..", "") for part in p.parts):
        return False
    # Drive letter / Windows absolute path, even if opened on Unix.
    if p.parts and ":" in p.parts[0]:
        return False
    return True


def load_zip(path: str) -> Tuple[Dict[str, bytes], List[str]]:
    notes: List[str] = []
    archive_path = Path(path)
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"ZIP is larger than the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB safety limit.")
    files: Dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"ZIP contains more than {MAX_FILES} entries.")
        for info in infos:
            if info.is_dir():
                continue
            if not safe_member_name(info.filename):
                notes.append(f"Skipped unsafe archive path: {info.filename[:160]}")
                continue
            if any(part.lower() in SKIP_ARCHIVE_PARTS for part in PurePosixPath(info.filename.replace("\\", "/")).parts):
                notes.append(f"Skipped generated/dependency directory entry: {info.filename[:160]}")
                continue
            # Ignore Unix symlinks; never follow links from archives.
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                notes.append(f"Skipped symbolic link: {info.filename[:160]}")
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                notes.append(f"Skipped very large file ({info.file_size} bytes): {info.filename[:160]}")
                continue
            if total + info.file_size > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError(f"ZIP expands beyond the {MAX_TOTAL_UNCOMPRESSED // (1024 * 1024)} MB safety limit.")
            try:
                # Read bounded chunks so a forged ZIP size header cannot force a huge one-shot allocation.
                with zf.open(info, "r") as stream:
                    data = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES:
                        notes.append(f"Skipped file whose expanded size exceeds the per-file limit: {info.filename[:160]}")
                        continue
                    if stream.read(1):
                        notes.append(f"Skipped file whose actual expanded size exceeds the per-file limit: {info.filename[:160]}")
                        continue
                if info.file_size and len(data) != info.file_size:
                    notes.append(f"Archive size metadata did not match file contents: {info.filename[:160]}")
                    continue
            except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
                notes.append(f"Could not read {info.filename}: {exc}")
                continue
            actual_size = len(data)
            total += actual_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError(f"ZIP expands beyond the {MAX_TOTAL_UNCOMPRESSED // (1024 * 1024)} MB safety limit.")
            files[info.filename.replace("\\", "/")] = data
    if not files:
        raise ValueError("No safe, readable files were found in the ZIP.")
    return files, notes


def load_folder(path: str) -> Tuple[Dict[str, bytes], List[str]]:
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError("The selected path is not a folder.")
    files: Dict[str, bytes] = {}
    notes: List[str] = []
    total = 0
    visited = 0
    for current, dirs, filenames in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_ARCHIVE_PARTS]
        for filename in filenames:
            visited += 1
            if visited > MAX_FILES:
                raise ValueError(f"Folder contains more than {MAX_FILES} files. Exclude generated/dependency directories and scan again.")
            p = Path(current) / filename
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                size = p.stat().st_size
                if size > MAX_MEMBER_BYTES:
                    notes.append(f"Skipped very large file ({size} bytes): {p.relative_to(root)}")
                    continue
                total += size
                if total > MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError(f"Folder exceeds the {MAX_TOTAL_UNCOMPRESSED // (1024 * 1024)} MB safety limit.")
                rel = p.relative_to(root).as_posix()
                files[rel] = p.read_bytes()
            except (OSError, ValueError) as exc:
                if isinstance(exc, ValueError):
                    raise
                notes.append(f"Could not read {p}: {exc}")
    if not files:
        raise ValueError("No readable files found in the selected folder.")
    return files, notes



def is_sensitive_local_file(path: str, data: bytes = b"") -> bool:
    """Identify common local-only secrets/signing artifacts for bundle safety prompts."""
    p = PurePosixPath(path.replace("\\", "/"))
    name = p.name.lower()
    suffix = p.suffix.lower()
    if name in {".env", ".env.local", ".env.production", ".env.development", ".env.test", ".npmrc", ".pypirc", "key.properties"}:
        return True
    if name.startswith(".env.") and name not in {".env.example", ".env.sample", ".env.template"}:
        return True
    if suffix in {".jks", ".keystore", ".p12", ".pfx", ".pem", ".key", ".p8", ".mobileprovision"}:
        return True
    if "service-account" in name and suffix == ".json":
        return True
    if "credentials" in name and suffix in {".json", ".properties", ".txt", ".yaml", ".yml"}:
        return True
    if name == "gradle.properties" and re.search(rb"(?i)(password|secret|token|api.?key|signing.?key)\s*[:=]\s*[^\s#]+", data):
        return True
    return False


def is_machine_specific_file(path: str) -> bool:
    return PurePosixPath(path.replace("\\", "/")).name.lower() in {"local.properties", ".ds_store", "thumbs.db"}

def _project_prefix(files: Dict[str, bytes]) -> str:
    paths = [PurePosixPath(p).parts for p in files if p]
    if not paths:
        return ""
    first = {parts[0] for parts in paths if len(parts) >= 2}
    root_files = any(len(parts) == 1 for parts in paths)
    if not root_files and len(first) == 1:
        return next(iter(first)) + "/"
    return ""


def apply_safe_fixes(files: Dict[str, bytes]) -> Tuple[Dict[str, bytes], List[str]]:
    """Only apply narrow, deterministic changes that should not change app behavior.

    - Add android:exported="true" to a recognizable MAIN/LAUNCHER activity only.
    - Add a conservative .gitignore if missing.

    All other findings remain recommendations. This function never executes code.
    """
    patched = dict(files)
    changes: List[str] = []
    import re
    for path, data in list(patched.items()):
        if not path.lower().endswith("androidmanifest.xml"):
            continue
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
        # Limit the fix to an explicitly identifiable launcher activity with MAIN + LAUNCHER.
        activity_re = re.compile(r"<activity(?![\w-])\b[^>]*>.*?</activity\s*>", re.I | re.S)
        def fix_activity(match):
            block = match.group(0)
            start_match = re.match(r"<activity\b[^>]*>", block, re.I | re.S)
            if not start_match:
                return block
            start_tag = start_match.group(0)
            if re.search(r"\bandroid:exported\s*=", start_tag, re.I):
                return block
            if not re.search(r"android\.intent\.action\.MAIN", block, re.I):
                return block
            if not re.search(r"android\.intent\.category\.LAUNCHER", block, re.I):
                return block
            new_start = start_tag[:-1].rstrip() + ' android:exported="true">'
            changes.append(f"Added android:exported=\"true\" to launcher activity in {path}")
            return new_start + block[start_match.end():]
        new_text = activity_re.sub(fix_activity, text)
        if new_text != text:
            patched[path] = new_text.encode("utf-8")

    prefix = _project_prefix(patched)
    gitignore_path = prefix + ".gitignore"
    if gitignore_path not in patched:
        gitignore = """# AppShip conservative generated/build artifacts\n# Review this file for your own workflow before committing.\n\n# Android / Gradle\n.gradle/\n**/build/\nlocal.properties\n*.hprof\n\n# Flutter / Dart\n.dart_tool/\n.packages\n.flutter-plugins\n.flutter-plugins-dependencies\n\n# iOS / Xcode\nDerivedData/\n*.xcuserstate\nxcuserdata/\nPods/\n\n# JavaScript tooling\nnode_modules/\ncoverage/\n\n# Local environment and credentials (keep real production secrets out of source control)\n.env\n.env.*\n!.env.example\n!.env.sample\n!.env.template\n*.keystore\n*.jks\n*.p12\n*.pfx\n*.pem\n*.key\n*.p8\n*.mobileprovision\n*.provisionprofile\nkey.properties\n.npmrc\n.pypirc\ncredentials*.json\nservice-account*.json\n\n# Editor / OS files\n.DS_Store\nThumbs.db\n"""
        patched[gitignore_path] = gitignore.encode("utf-8")
        changes.append(f"Added a conservative .gitignore at {gitignore_path}")
    if not changes:
        changes.append("No safe automatic source fix was applicable. Review remaining findings manually.")
    return patched, changes


def create_zip_from_files(files: Dict[str, bytes], output_path: str, additions: Dict[str, bytes] | None = None):
    additions = additions or {}
    combined = dict(files)
    for path, data in additions.items():
        combined[path] = data
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path, data in sorted(combined.items()):
            if not safe_member_name(path):
                continue
            zf.writestr(path, data)
