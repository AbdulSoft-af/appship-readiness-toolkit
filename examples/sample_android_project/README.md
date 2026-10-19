# AppShip Demo Android Project

This is a small, **buildable Android sample** for validating AppShip's scan, Gradle Build & Test, and APK/AAB verification flows. It is intentionally minimal, not a product app.

## Requirements

- JDK 17
- Android SDK Platform 36 and Android SDK Build Tools (Android Studio can install these)
- Internet for the first build to download the pinned Gradle distribution and Maven/Google dependencies
- The Gradle bootstrap script downloads Gradle 8.14.6 from `services.gradle.org` and verifies its SHA-256 before running it. It stores the distribution in the user's Gradle cache.

## Build

Windows PowerShell / CMD:

```bat
gradlew.bat test assembleDebug
```

macOS / Linux:

```sh
./gradlew test assembleDebug
```

Release-bundle build (unsigned unless release signing is configured):

```sh
./gradlew bundleRelease
```

Expected outputs:

- `app/build/outputs/apk/debug/app-debug.apk`
- `app/build/outputs/bundle/release/app-release.aab` (release bundle; not automatically signed for Play upload)

## AppShip

Open this folder with AppShip and use `Run scan`. For the first Build & Test, allow dependency downloads; selecting offline mode will fail until all Gradle and Android dependencies are already cached. AppShip runs source builds on a temporary copy, which is not a full OS sandbox.

The project targets API 36 and declares a launcher activity with `android:exported="true"`. No signing keys, API secrets, or personal credentials are included.
