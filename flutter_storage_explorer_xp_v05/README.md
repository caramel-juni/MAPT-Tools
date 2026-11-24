# Flutter Mobile Storage Explorer XP v0.5

**New in v0.5:** Security signals are now clickable and open the original evidence file; matched contexts have byte offsets, with optional on-screen heuristic redaction for screenshots. Android compiled binary XML (`AndroidManifest.xml`, `res/xml/*.xml`) is decoded into readable XML using a bundled pure-Python AXML reader. Native libraries and other binary files display extracted printable strings and matched contexts, rather than showing only a hex dump. SQLite records also honour the screenshot-redaction toggle.

**To run:**

```bash
unzip Flutter_Mobile_Storage_Explorer_XP_v0.5.zip
cd flutter_storage_explorer_xp_v05
python3 explorer.py browse
```

Open http://127.0.0.1:8765. Import an APK or IPA, and optionally a captured runtime app-data folder. Select **Security signals**, then click any finding: the file viewer opens with its matched sections. Toggle **Redact screenshot** in the toolbar before capturing screenshots.

**Security notes:** The toggle affects only *display*, not the data sent by the server to the local browser; original evidence is still in memory and available to that browser session. Masking is heuristic, not a guarantee every sensitive string is hidden. Do not expose this local server to other machines, and use synthetic test identities where possible. APK `.so` keyword matches often reflect library implementation terms rather than actual stored credentials. A finding needs contextual verification.

**Known limits:** AXML decoding covers common Android compiled XML formats and typed attributes, but newer/unusual encodings may not decode. Resource IDs might remain as `@0x...` and need resource table resolution. Extremely large files are previewed/truncated; match scanning is capped at 8 MB. Binary strings are an investigation aid, not disassembly. An APK/IPA does not contain live user storage; import that separately.

---

# Flutter Mobile Storage Explorer XP v0.3

**Local, Windows XP-inspired GUI for security review of Android APKs, iOS IPAs, and extracted runtime application data.** Python 3.10+; no pip dependencies for the explorer. Use only on devices/applications for which you have testing authorization.

## Quick start — launch the GUI with no input

```bash
unzip Flutter_Mobile_Storage_Explorer_XP_v0.3.zip -d flutter-explorer
cd flutter-explorer
python3 explorer.py browse
```

Open **http://127.0.0.1:8765** locally. Click **Import application / data**. You can now import all of the following *from within the GUI*:

- APK or IPA (application static bundle; choose file)
- A **full extracted app data directory** from Android or iOS (choose folder, not individual file)
- A ZIP of an iOS data container (choose ZIP)
- Android live data directly from ADB (**ADB snapshot** wizard) if the device permits `run-as` or `su`

The source copies are indexed into a temporary session on your machine and deleted on normal process exit. The original artifacts are not changed. The app supports importing an IPA and runtime data in the same session. Its interface uses a Windows XP-inspired blue title bar, taskbar, Explorer panes, category filters and dialogs.

**Important:** For larger evidence datasets, use `--dir` on the command line. GUI upload is limited to a total of **300 MB per session** and 30,000 individual files. Folder selection requires a browser with `webkitdirectory` support (Chromium-based browsers and other supported clients). This is not a cloud app. It binds only to `127.0.0.1`.

### Optional: open a pre-existing directory or app artifact without uploading

```bash
python3 explorer.py browse --apk ~/apps/app.apk --dir ~/evidence/android-logged-in
python3 explorer.py browse --ipa ~/apps/app.ipa --dir ~/evidence/ios-container
python3 explorer.py browse --ios-archive ~/evidence/app-container.zip
python3 explorer.py browse --dir ~/evidence/ios-container --port 8766
```

These CLI inputs can be larger than the GUI upload cap. They're inspected in place, without copying or executing data. The browser data directory remains *read-only for inspection*; avoid modifying a live application's active SQLite database while inspecting it. The GUI import feature creates temporary copies instead.

## Why there are two separate input types

An **APK / IPA** contains the application code, assets, manifest or `Info.plist`, and bundled configuration; it does **not** contain data created by users after the app runs. For a complete assessment, acquire the **live app container** separately and import it as a directory or a ZIP archive. An IPA also does not contain Keychain records. Android sandbox restrictions and iOS signing/jailbreak restrictions limit what you can acquire.

## Live Android extraction (GUI and CLI)

1. Run `adb devices -l` and ensure the emulator or test phone is connected.
2. Launch the GUI and click **ADB snapshot**.
3. Enter package ID such as `com.example.mobile`, optionally an ADB serial such as `emulator-5554`, and choose **Auto** / **run-as** / **su**.
4. Click **Collect snapshot**. The captured data appears under `adb-capture/internal/`, and device-protected files under `adb-capture/user_de/` when accessible.
5. Browse `databases/`, `shared_prefs/`, `files/`, `app_flutter/`, `app_webview/`, `cache/`, `no_backup/`, and `user_de/`.

Or collect on the command line:

```bash
python3 explorer.py snapshot --package com.example.mobile --out ./snapshots/account-A
python3 explorer.py browse --dir ./snapshots/account-A --apk ./app.apk
```

**Caveats:** `run-as` usually requires a debuggable build. Root (`su`) requires an authorised rooted test device. Capture a quiesced app when possible; if the app remains active, SQLite WAL and SHM files should be collected consistently with their main database. No unauthorised sandbox bypass is attempted.

## iOS data collection and import

- **iOS Simulator:** `xcrun simctl get_app_container booted com.example.mobile data` (run on macOS). You can select or copy that folder into GUI.
- **Development signed iPhone build via Xcode:** Xcode → Devices and Simulators → installed app → **Download Container**; inspect `.xcappdata/AppData/` and import that folder.
- **Authorised jailbroken test iPhone:** identify the app's UUID under `/var/mobile/Containers/Data/Application/<UUID>/`; copy the relevant container using SSH/SCP/rsync or tar. Import the resulting directory or ZIP.
- **Keychain:** not present as readable files in the IPA or ordinary sandbox directory; use an authorised Keychain inspection method on the device or a test instrumented build. The explorer does not extract Keychain items.

Inspect `Library/Preferences/*.plist`, `Library/Application Support/`, `Library/Caches/`, `Documents/`, `tmp/`, WebKit/website data, Core Data SQLite files and any separately acquired App Group container. Review file protection classes on-device; copied files alone cannot establish whether proper `NSFileProtection` settings were used.

## Working inside the Windows XP interface

| Area | How to use | What it tells you |
| --- | --- | --- |
| **Overview** | See number of files, heuristic signals and categories | Baseline coverage at a glance |
| **Import application / data** | Choose APK/IPA + full directory + iOS ZIP | Add evidence without restarting server |
| **ADB snapshot** | Enter package and capture from emulator | Inspect actually written data |
| **Evidence explorer** | Search path, filter category, click artifact | Navigate preference XML, plist, JSON, generic protobuf and files |
| **SQLite browser** | Click extracted `.db`, choose table, page rows | See SQL records with read-only query |
| **Security signals** | Click detected potential secrets/PII | Review heuristics; verify before reporting |
| **Assessment guide** | See methodology inside the UI | Starting points for each platform |

SQLite uses read-only SQL connections and simple paginated `SELECT` queries. Encrypted databases, Realm, Hive, Isar and LevelDB are **not** fully parsed by this version. A database inside an IPA/ZIP is inventoried, but needs extracting into a regular directory before SQL table browsing. XML and binary `.plist` are decoded; `.preferences_pb` gets a best-effort generic protobuf wire preview (not schema-aware).

## Security testing workflow for a live-data assessment

1. Capture a **fresh-install** baseline.
2. Sign in as a **synthetic test user A**; create an identifiable test marker (e.g. `STORAGE_AUDIT_CANARY_001`) in the app's data and capture the directory.
3. Browse SQLite, SharedPreferences/UserDefaults, cached documents, WebView cookies/localStorage, downloaded files, Flutter files, token-like strings and telemetry buffers. Search for the marker and avoid posting actual tokens into reports.
4. Test changes while signed in: upload/download documents, cache API results, background/foreground the app, and force a handled error. Capture a second snapshot.
5. Sign out and capture again. Compare content and investigate leftover sessions, records, and cache files. **Plaintext in private sandbox alone is not automatically a vulnerability.**
6. Sign in as **test user B**; check if A's records remain accessible or are attributed to B. Test server-side token invalidation separately.
7. Review Android backups/`dataExtractionRules`, permissions, Keystore use, and exported providers. On iOS, review Keychain attributes and file-protection classes with device-specific tools.
8. Check logs separately: `python3 explorer.py logcat --out ./logs/session.log` on Android; use Burp/OTLP Sentinel for actual remote `/v1/logs` HTTP payloads. The filesystem explorer **does not** capture every network request or SDK telemetry transmission.

To compare before and after snapshots:

```bash
python3 explorer.py compare ./snapshots/account-A ./snapshots/logged-out --out ./diff.json
```

This compares file hashes and filenames; it does not automatically prove secure erasure or authentication revocation.

## Flutter AOT reverse engineering: AOTopsy and Blutter

The explorer shows **where data is actually persisted**. For **why** those writes happen, inspect Flutter/Dart AOT code with separate tools.

1. Extract the APK: `unzip -q app.apk -d unpacked/`.
2. Locate `unpacked/lib/arm64-v8a/libapp.so` (architecture varies).
3. Use the latest installation and syntax documented by [AOTopsy](https://github.com/nicolo-ribaudo/aotopsy) (project availability/CLI changes are possible). Example commands used in this workflow:

   ```bash
   aotopsy doctor unpacked/lib/arm64-v8a/libapp.so
   aotopsy unpacked/lib/arm64-v8a/libapp.so --out ./aot-output --graph
   aotopsy _debug strings --lib unpacked/lib/arm64-v8a/libapp.so --find 'Authorization' --xref
   aotopsy _debug decompile-native --lib unpacked/lib/arm64-v8a/libapp.so --find 'OtlpHttpClient'
   ```

4. Prioritise references to `SharedPreferences`, `flutter_secure_storage`, `sqflite`, `Hive`, `Isar`, `path_provider`, database writes, `OtlpHttpClient`, tracing exporters, and authentication headers.
5. For Android ARM64 Flutter builds, consider [Blutter](https://github.com/worawit/blutter) if the app's Dart version and binary are supported.
6. Treat recovered strings as leads: validate with storage snapshots and runtime monitoring. Not all Dart/Flutter releases are supported, and iOS Mach-O binaries do not share the standard Android `libapp.so` workflow.

References: [OWASP MASVS](https://mas.owasp.org/MASVS/), [OWASP MASTG](https://mas.owasp.org/MASTG/), [Android application data storage](https://developer.android.com/training/data-storage), [Apple File System](https://developer.apple.com/documentation/foundation/filemanager), [AOTopsy](https://github.com/nicolo-ribaudo/aotopsy), [Blutter](https://github.com/worawit/blutter).

## Privacy, limitations and troubleshooting

- **Read only for analysis**, but **import** and **ADB snapshot** create evidence copies in a temporary local session. The originals aren't modified. The default GUI shows original values to the local user; it does not upload evidence to a cloud service.
- Closing the tool normally removes the session's temporary uploads. OS crashes can leave temporary copies; treat your machine as sensitive evidence storage and clean up abandoned `flutter-explorer-*` directories when safe.
- The GUI accepts files via local loopback and checks a per-session request token on mutating calls. **Do not expose port 8765 to the network or open it through a remote tunnel.**
- If **folder import doesn't work**, use Chromium/Edge folder picker or start with `--dir`; browser implementations vary.
- If SQLite appears empty, check `-wal` and `-shm` paired files and capture consistency; don't assume absence of data.
- If a `.db` cannot open, it might be encrypted or a different format; use a suitable format-specific tool.
- If `adb snapshot` fails, check `adb devices`, package name, `run-as` support and test-device root permissions.
- APK/IPA scanning does not decompile all managed/native code. AOTopsy/Blutter are separate tools; this GUI doesn't automatically execute unknown binaries.
- Inference about encryption, actual iOS file protection, Android backup eligibility, Keychain policy, or remote logging generally requires more than bytes in a copied app directory.

---

## v0.4: APK/IPA import reliability fixes

Version 0.4 changes browser uploads to stream into a temporary file instead of reading the entire archive into RAM. It also provides an **Open local file path (no upload)** input inside the **Import application / data** wizard. The local path is resolved by the Python backend on the same machine where the tool is running; the server remains bound to `127.0.0.1`.

### If Firefox reports `NetworkError when attempting to fetch resource`

1. Start the tool from a terminal: `python3 explorer.py browse` and leave it running while importing. The server now prints Python request errors, which can reveal the failure cause.
2. Open `http://127.0.0.1:8765` (not `file://`). Refresh the page after upgrading; the old page has no local-path field.
3. In the import wizard, paste the **absolute path to the APK on the same machine running the Python tool** (e.g. `/home/user/Downloads/app.apk` on Linux, `C:\Users\user\Downloads\app.apk` on Windows). Do not select a file in the browser picker when using this option. Click **Import selected evidence**.
4. Alternatively launch with `python3 explorer.py browse --apk /full/path/app.apk` and the APK will be indexed immediately.
5. If using Burp or another system proxy in Firefox, ensure localhost/127.0.0.1 bypasses that proxy. A browser extension or proxy misconfiguration can also cause failed requests.
6. Browser uploads remain capped at 300 MB per session. Larger APKs should use the local-path or `--apk` option.

**Troubleshooting:** Inspect the terminal output and Firefox Developer Tools → Network for the failing `/api/upload` or `/api/finish` request. HTTP 400/413 responses indicate validation/size errors; a request with no HTTP response suggests disconnection or a server/proxy issue. The scanner still only inspects artifacts; an APK does not contain live user-data containers.
