"""Centralized, dated platform policy profiles used by AppShip checks.

Policy tables are intentionally transparent and easy to update. These rules are
preflight hints; official platform pages always take precedence.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict

POLICY_CHECKED_ON = "2026-10-19"
DEFAULT_ANDROID_PROFILE = "standard"

@dataclass(frozen=True)
class AndroidProfile:
    key: str
    label: str
    required_target_api: int
    description: str

ANDROID_PROFILES: Dict[str, AndroidProfile] = {
    "standard": AndroidProfile(
        "standard", "Standard Android app", 36,
        "General Google Play apps: new apps and updates submitted from 31 August 2026.",
    ),
    "wear-os": AndroidProfile(
        "wear-os", "Wear OS", 35,
        "Wear OS has a separate target API requirement.",
    ),
    "automotive": AndroidProfile(
        "automotive", "Android Automotive OS", 35,
        "Android Automotive OS has a separate target API requirement.",
    ),
    "android-tv": AndroidProfile(
        "android-tv", "Android TV", 34,
        "Android TV has a separate target API requirement.",
    ),
    "android-xr": AndroidProfile(
        "android-xr", "Android XR", 34,
        "Android XR has a separate target API requirement.",
    ),
}

GOOGLE_TARGET_API_URL = "https://support.google.com/googleplay/android-developer/answer/11926878"
GOOGLE_USER_DATA_URL = "https://support.google.com/googleplay/android-developer/answer/10144311"
GOOGLE_ACCOUNT_DELETION_URL = "https://support.google.com/googleplay/android-developer/answer/13327111"
APPLE_REVIEW_URL = "https://developer.apple.com/app-store/review/guidelines/"
APPLE_ACCOUNT_DELETION_URL = "https://developer.apple.com/support/offering-account-deletion-in-your-app/"
APPLE_UPLOAD_BUILDS_URL = "https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds"
APPLE_PRIVACY_MANIFEST_URL = "https://developer.apple.com/documentation/bundleresources/privacy-manifest-files"


def get_android_profile(profile: str | None = None) -> AndroidProfile:
    key = (profile or DEFAULT_ANDROID_PROFILE).strip().lower()
    if key not in ANDROID_PROFILES:
        valid = ", ".join(ANDROID_PROFILES)
        raise ValueError(f"Unknown Android profile '{profile}'. Choose one of: {valid}.")
    return ANDROID_PROFILES[key]


def policy_snapshot() -> dict:
    return {
        "checked_on": POLICY_CHECKED_ON,
        "android_profiles": {
            key: {
                "label": profile.label,
                "required_target_api": profile.required_target_api,
                "description": profile.description,
            }
            for key, profile in ANDROID_PROFILES.items()
        },
        "official_sources": {
            "google_target_api": GOOGLE_TARGET_API_URL,
            "google_user_data": GOOGLE_USER_DATA_URL,
            "google_account_deletion": GOOGLE_ACCOUNT_DELETION_URL,
            "apple_app_review": APPLE_REVIEW_URL,
            "apple_account_deletion": APPLE_ACCOUNT_DELETION_URL,
            "apple_upload_builds": APPLE_UPLOAD_BUILDS_URL,
            "apple_privacy_manifests": APPLE_PRIVACY_MANIFEST_URL,
        },
        "disclaimer": "This dated snapshot is a helper, not an official policy engine. Recheck the linked platform documentation before every submission.",
    }
