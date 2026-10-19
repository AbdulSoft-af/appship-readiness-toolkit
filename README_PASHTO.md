<p align="center"><img src="assets/appship-logo.svg" width="320" alt="AppShip — Build, Verify, Ship"></p>

# AppShip Readiness Toolkit v3.1.0

**Build · Verify · Ship** — د Android او iOS اپلیکیشنونو د ارزونې، د عامو خپرولو خنډونو د موندلو او د Google Play / Apple App Store لپاره د چمتووالي محلي وسیله.

> **حالت: Release Candidate.** دا وسیله د تخنیکي ستونزو په موندلو، راپور جوړولو او د تایید شوي Build/Test په چلولو کې مرسته کوي؛ خو رسمي Apple/Google Validator نه دی او د سټور د منلو تضمین نه کوي.

## په دې نسخه کې څه شته؟

- د Windows او نورو ملاتړ شوو کمپیوټرونو لپاره Desktop کړکۍ؛ د ستونزو لټون، د شدت کچې، د پروژې پېژندنه او د Markdown/JSON/HTML راپور.
- د Command Line وسیله د CI لپاره، د سخت Release Gate، راپورونو، د سیسټم د Toolchain کتنې او د تیارې ZIP بستې لپاره.
- د ZIP او فولډر خوندي سکین؛ د ناامنو مسیرونو مخنیوی، د لویو ZIP فایلونو محدودیت، د ZIP نه Extract کول او د Symbolic Linkونو نه تعقیبول.
- د Android Manifest، Target/Compile SDK، Exported Components، حساس Permissions، Placeholder IDs، Debug/Cleartext تنظیماتو، iOS `Info.plist`، Privacy Manifest نښو، د حساب حذف، احتمالي Secrets او د Dependencies د نسخو کتنه.
- محدودې اتومات اصلاحات: یوازې پېژندل شوی Android MAIN/LAUNCHER Activity چې `android:exported` ونه لري، او د `.gitignore` جوړول. نورې ستونزې د Developer د ارزونې لپاره راپور کېږي.
- اختیاري Local AI د Ollama له لارې. AI وړاندیزونه په جلا Review Copy کې تطبیقېږي؛ اصلي پروژه نه بدلوي. د Undo او Discard اختیارونه لري.
- اختیاري Build/Test د موقتي کاپي پر بنسټ، که د پروژې اړین SDK او Toolchain نصب وي.
- د سټور چک‌لېسټ، د فایلونو SHA-256 Inventory او د برانډ لرونکی آف‌لاین HTML راپور.
- د APK/AAB/IPA د جوړښت او Metadata ارزونه؛ اپلیکیشن نه اجرا کوي. په macOS کې د IPA د Signature تایید لپاره یوازې د `.app` Bundle موقتي کاپي جوړولای شي.

## په Windows کې د چالانولو طریقه

1. `AppShip_Readiness_Toolkit_v3.1.0.zip` ډاونلوډ او Extract کړه.
2. Python 3.10 یا نوې نسخه له <https://www.python.org/downloads/windows/> نصب کړه. `Add python.exe to PATH` او Tcl/Tk فعال کړه.
3. `run_windows.bat` دوه ځله کلیک کړه.
4. د `Open project ZIP` یا `Scan project folder` له لارې د اپلیکیشن سرچینه وټاکه.
5. د Android لپاره سم Profile انتخاب کړه او `Run scan` کلیک کړه.
6. لومړی Critical او High ستونزې حل کړه؛ راپور په Markdown، JSON یا HTML صادر کړه.
7. `Create prepared ZIP` جلا کاپي جوړوي چې محدود Safe Fixes، راپورونه او چک‌لېسټ لري. اصلي فولډر نه بدلوي. که احتمالي Hard-coded Secret پاتې وي، CLI د ZIP جوړول بندوي؛ `--allow-suspected-secrets` یوازې هغه وخت وکاروه چې په خپله دې وڅېړله او ریښتینی راز پکې نه وي.

د Static Scanner، Desktop UI او CLI لپاره د Python اضافي Runtime کتابتونونه لازم نه دي.

## د CLI استعمال

د پروژې له اصلي فولډر څخه دا امرونه اجرا کړه:

```powershell
# لنډ سکین
python -m appship.cli scan "C:\path\to\mobile-project"

# د برانډ لرونکی HTML راپور
python -m appship.cli scan "C:\path\to\mobile-project" --format html --output appship-report.html

# JSON راپور، چک‌لېسټ، د فایلونو Inventory او تیار ZIP
python -m appship.cli scan .\my-app.zip --format json --output report.json --checklist checklist.md --inventory inventory.json --prepared-zip prepared.zip

# د Wear OS د API شرط
python -m appship.cli scan .\my-app.zip --android-profile wear-os

# که Critical/High پاتې وي، د CI لپاره ناکام Exit Code
python -m appship.cli scan .\my-app.zip --strict

# د Toolchain تشخیص او د پالیسۍ Snapshot
python -m appship.cli doctor
python -m appship.cli policies

# د Release فایل (APK/AAB/IPA) کتنه او د HTML راپور جوړول
python -m appship.cli verify-artifact .\app-release.aab --format html --output artifact-report.html
python -m appship.cli verify-artifact .\app-release.apk --format markdown --output apk-check.md

# د CI لپاره: که لاسلیک په بشپړ ډول تایید نه شي، غیرصفر Exit Code ورکړي
python -m appship.cli verify-artifact .\app-release.apk --require-signature
```

### د APK، AAB او IPA د وروستي فایل ارزونه

په Desktop اپ کې د `Verify APK/AAB/IPA` تڼۍ وکاروه؛ یا د CLI له لارې `verify-artifact` اجرا کړه. دا د Archive لوستل، ناامنه مسیرونه، اړین فایلونه او Release Metadata ګوري. که نصب وي، د APK لپاره `apksigner` او د AAB لپاره `jarsigner` کاروي. په macOS کې د IPA د `.app` بسته موقتي فولډر ته په خوندي ډول راوباسي او د Apple `codesign --verify --deep --strict` اجرا کوي. په Windows/Linux کې یا د سم ډول نه ساتل کېدونکو symbolic links په صورت کې `REVIEW` ښيي؛ د وروستي تایید لپاره په Mac کې Xcode/Transporter وکاروه.

- `PASS`: هغه موجودې اوزاریزې کتنې بریالۍ شوې؛ دا د اپلیکیشن د خوندي‌والي یا Store Approval تضمین نه دی.
- `FAIL`: په ټاکل شوو جوړښتي یا امنیتي کتنو کې ستونزه پیدا شوه.
- `REVIEW`: د یوه Tool یا لاسي/پلاتفورمي تایید اړتیا پاتې ده.
- `--require-signature`: Exit Code یوازې هغه وخت صفر ورکوي چې ټولې کتنې `PASS` وي. په Windows/Linux کې د IPA لپاره `REVIEW` تمه کېدونکې پایله ده؛ په macOS کې د `codesign` تایید اجرا کېدای شي.

Artifact Verifier اپلیکیشن نه اجرا کوي او Store ته یې Upload نه کوي. د IPA د codesign لپاره په macOS کې د `.app` Bundle په موقتي فولډر کې جوړوي؛ له تایید وروسته موقتي فایلونه حذف کېږي.

### Build/Test په احتیاط سره

Build scripts د کمپیوټر د کارونکي په اجازه هر ډول کوډ اجرا کولای شي. یوازې د باور وړ پروژې لپاره یې وکاروه:

```powershell
python -m appship.cli scan .\my-app.zip --build-test --confirm-execute-build-scripts --build-bundle build-test.zip
```

د Dependencies نصب او Network ته د اجازې لپاره جلا Flag ته اړتیا ده:

```powershell
python -m appship.cli scan .\my-app.zip --build-test --confirm-execute-build-scripts --allow-dependency-install --build-bundle build-test.zip
```

دا د Operating System بشپړ Sandbox نه دی. د نامعلومې پروژې لپاره جلا Disposable VM یا محدود Container وکاروه. ځینې Build Toolونه د Offline حالت سره هم د Wrapper یا SDK د ترلاسه کولو هڅه کولای شي.

## د Android د واقعي نمونې Build

په Repository کې `examples/sample_android_project/` یوه لږه خو Build کېدونکې Android نمونه ده؛ پخوانی قصدي ناکام Placeholder نور پکې نشته. دا Gradle 8.14.6 کاروي او د رسمي ډاونلوډ SHA-256 تاییدوي، Android Gradle Plugin 8.13.2، JDK 17 او Android SDK Platform 36 ته اړتیا لري.

په Windows کې د نمونې فولډر څخه اجرا کړه:

```bat
gradlew.bat test assembleDebug
```

په macOS/Linux کې:

```sh
./gradlew test assembleDebug
```

د لومړي ځل لپاره انټرنېټ ته اړتیا شته چې Gradle او اړوند Dependencies ډاونلوډ شي. GitHub Actions د Push او Pull Request پر مهال `test assembleDebug bundleRelease` اجرا کوي. په دې کاري چاپېریال کې native Android SDK موجود نه و، نو د واقعي Build بریا باید په خپل کمپیوټر یا GitHub Actions کې تایید شي.

## اختیاري Local AI

1. Ollama له <https://ollama.com/download> نصب او چالان کړه.
2. پروژه په AppShip کې Load او Scan کړه، بیا `AI Repair (Local Ollama)` وټاکه؛ د `Local AI Settings` کړکۍ به پرانیستل شي.
3. ادرس `http://127.0.0.1:11434` تایید کړه او `Test + Refresh Models` کېکاږه. AppShip یوازې Loopback ادرسونه مني او د دې محلي غوښتنو لپاره Proxy نه کاروي.
4. له نصب شوو Modelونو څخه یو Coding Model انتخاب کړه. که لېست تش وي، `Download Selected Model` وکاروه او د ډاونلوډ د اجازې او احتمالي لوی حجم پیغام ولوله؛ یا په Terminal کې `ollama pull qwen2.5-coder:7b` اجرا کړه. Model څو GB کېدای شي.
5. کله چې اتصال او Model تایید شي، `Continue to AI Repair` کېکاږه.
6. د AI وړاندیز په دقت وګوره؛ Apply یې یوازې جلا Review Copy ته کوي. د `Undo Last AI Patch` او `Discard Review Copy` له لارې بدلون بېرته ګرځولای شې.
7. د تازه شوې کاپي Build/Test او بیا Scan اجرا کړه.

د Endpoint او Model تنظیمات د کارونکي په AppShip settings فایل کې خوندي کېږي. محرم/لاسلیک فایلونه او Secret ته ورته متنونه د AI Context څخه ایستل کېږي؛ خو AI وړاندیز لا هم غلط کېدای شي، نو انساني کتنه او ټېسټونه ضروري دي.

## د Android د پالیسیو Profile

د دې Snapshot د وروستۍ کتنې نېټه **۱۹ اکتوبر ۲۰۲۶** ده. د Google Play د رسمي لارښود له مخې عمومي Target API Profileونه:

| Profile | د سکین د Target API حد |
|---|---:|
| Standard Android app | 36 یا لوړ |
| Wear OS | 35 یا لوړ |
| Android Automotive OS | 35 یا لوړ |
| Android TV | 34 یا لوړ |
| Android XR | 34 یا لوړ |

دا د یوې ټاکلې نېټې Snapshot دی، نه د تل لپاره ثابت قانون. د اپلیکیشن کټګوري، د موجود اپلیکیشن د وېش حالت او استثناوې توپیر لرلای شي. د خپرولو پر ورځ رسمي شرطونه بیا وګوره.

رسمي سرچینې:

- Google Play Target API: <https://support.google.com/googleplay/android-developer/answer/11926878>
- Google Play User Data او Privacy: <https://support.google.com/googleplay/android-developer/answer/10144311>
- د Google Play د حساب حذف: <https://support.google.com/googleplay/android-developer/answer/13327111>
- Apple App Review Guidelines: <https://developer.apple.com/app-store/review/guidelines/>
- Apple د اپلیکیشن دننه Account Deletion: <https://developer.apple.com/support/offering-account-deletion-in-your-app/>
- Apple Upload Builds / Xcode: <https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds>
- Apple Privacy Manifest: <https://developer.apple.com/documentation/bundleresources/privacy-manifest-files>

## Build/Test او مهم محدودیتونه

- AppShip سرچینه موقتي فولډر ته کاپي کوي؛ ټاکل شوی اصلي فولډر نه بدلوي.
- موقتي فولډر د OS بشپړ Sandbox نه دی. Build او Package Lifecycle Scripts د کارونکي په اجازه کوډ اجرا کولای شي.
- د Build لپاره اړین JDK، Android SDK، Flutter، Node یا Xcode باید نصب وي.
- د iOS لاسلیک شوې Store بستې لپاره macOS، Xcode او معتبر Developer Signing/Provisioning ته اړتیا ده.
- د APK/AAB/IPA شتون د لاسلیک د صحت، د Runtime ثبات یا د Store د منلو ثبوت نه دی.
- دا نسخه په خپله Google Play Console یا App Store Connect ته اپلیکیشن نه Upload کوي.
- Static Scan د اپلیکیشن واقعي چلند، د Privacy فورمو دقت، د محتویاتو حقونه او د Store Review پرېکړه نه شي تضمینولای.

## ازموینې

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app.py appship tests
python -m appship.cli doctor
```

دا ازموینې د Scanner Ruleونو، د ZIP خوندیتوب، د HTML Escape، د Android Profileونو، د تیار ZIP جوړولو، د AI Patch محدودیتونو او CLI فعالیت ارزونه کوي؛ د حقیقي Android/iOS Build، Device Testing او Store Review بدیل نه دي.

## د GitHub خپرولو لپاره

- `.env`، API Keys، پاسورډونه، Signing Keys، Provisioning Profiles او د کاروونکو معلومات مه خپروه.
- `LICENSE`، `SECURITY.md` او `CONTRIBUTING.md` ولوله.
- Bug report کې د ستونزې کوچنۍ او له رازونو پاکه نمونه وکاروه.
- سپارښتل شوی Tag: `v3.1.0` (Release Candidate). له پراخو حقیقي Framework او Device ټېسټونو مخکې یې د بشپړ Stable محصول په توګه مه معرفي کوه.
