# apkinfo

A simple, offline command-line tool that shows key information about Android APK files.
Pure Python, **no dependencies** (standard library only) — works on Linux, macOS, Windows and Termux.

Inspired by the [Sixo Online APK Analyzer](https://www.sisik.eu/apk-tool), but runs entirely
locally in your terminal.

## Features

- Package name, `versionCode`, `versionName`
- Supported ABIs and 64-bit support check
- Minimum and target Android version (with API level)
- List of bundled native libraries (`.so`)
- Optional full report: permissions, activities, services, broadcast receivers, content providers
- Analyze multiple files, whole directories, or wildcards at once
- Works completely offline — the APK never leaves your machine

## Requirements

- Python 3.6+

No `pip install` needed.

## Usage

```
python apkinfo.py app.apk
python apkinfo.py a.apk b.apk c.apk     # multiple files
python apkinfo.py my_folder/            # all *.apk files in a directory
python apkinfo.py *.apk --full          # include permissions and components
python apkinfo.py -h                    # help
```

On Linux/macOS you can also run it directly:

```
chmod +x apkinfo.py
./apkinfo.py app.apk
```

## Example output

```
Package name
app.game

versionCode
23

versionName
1.2.1

Supported ABIs
arm64-v8a, armeabi-v7a

64 bit architecture support
YES

Minimal supported Android version
Android 8.0.0 - API level 26

Target SDK
Android 9 - API level 28

Native libraries
libc++_shared.so, libpulse.so, libvulkan_renderer.so, ...
```

## How it works

An APK is a ZIP archive. The tool:

1. Parses the binary `AndroidManifest.xml` (AXML format) with a small built-in parser to read
   package info, SDK versions, permissions and components.
2. Scans the `lib/<abi>/*.so` entries to find supported ABIs and native libraries.

## Limitations

- App name and icon are not shown (they require parsing `resources.arsc`).
- Signature / certificate information is not shown.
- Split APKs (bundles, XAPK) should be analyzed one APK at a time, e.g. `base.apk`.
- Tested on a limited number of real APK files. If something fails or looks wrong,
  please open an issue and include the error message.

## Exit codes

- `0` — all files analyzed successfully
- `2` — at least one file could not be analyzed
- `1` — no input files given

## License

MIT
