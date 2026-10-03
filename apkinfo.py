#!/usr/bin/env python3
"""apkinfo - a simple local APK analyzer (no dependencies, stdlib only).

Use:
    python apkinfo.py -h or -help          # this help
    python apkinfo.py file.apk             # single apk
    python apkinfo.py a.apk b.apk c.apk    # multiple apks
    python apkinfo.py folder/              # all apks in the folder
    python apkinfo.py *.apk --full         # + permissions, activities, services...
"""
import glob
import os
import struct
import sys
import zipfile

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_ELEMENT = 0x0102
RES_XML_RESOURCE_MAP = 0x0180

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_BOOLEAN = 0x12

ATTR_IDS = {
    0x01010003: "name",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
}

SDK_NAMES = {
    1: "Android 1.0", 2: "Android 1.1", 3: "Android 1.5", 4: "Android 1.6",
    5: "Android 2.0", 6: "Android 2.0.1", 7: "Android 2.1", 8: "Android 2.2",
    9: "Android 2.3", 10: "Android 2.3.3", 11: "Android 3.0", 12: "Android 3.1",
    13: "Android 3.2", 14: "Android 4.0", 15: "Android 4.0.3",
    16: "Android 4.1", 17: "Android 4.2", 18: "Android 4.3",
    19: "Android 4.4", 20: "Android 4.4W", 21: "Android 5.0", 22: "Android 5.1",
    23: "Android 6.0", 24: "Android 7.0", 25: "Android 7.1",
    26: "Android 8.0.0", 27: "Android 8.1", 28: "Android 9", 29: "Android 10",
    30: "Android 11", 31: "Android 12", 32: "Android 12L", 33: "Android 13",
    34: "Android 14", 35: "Android 15", 36: "Android 16", 37: "Android 17",
}


def sdk_str(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return str(v)
    return f"{SDK_NAMES.get(n, 'Android')} - API level {n}"


def parse_string_pool(data, off):
    _type, hdr, size = struct.unpack_from("<HHI", data, off)
    count, _styles, flags, strings_start, _ = struct.unpack_from("<IIIII", data, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, off + hdr)
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        if utf8:
            n = data[p]; p += 1
            if n & 0x80:
                p += 1
            n = data[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p]; p += 1
            out.append(data[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
            out.append(data[p:p + n * 2].decode("utf-16le", "replace"))
    return out, off + size


def parse_axml(data):
    t, hdr, _size = struct.unpack_from("<HHI", data, 0)
    if t != RES_XML:
        raise ValueError("This is not binary XML (AXML)")
    pos = hdr
    strings, res_ids, elements = [], [], []

    while pos + 8 <= len(data):
        ctype, chdr, csize = struct.unpack_from("<HHI", data, pos)
        if csize == 0:
            break
        if ctype == RES_STRING_POOL:
            strings, _ = parse_string_pool(data, pos)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - chdr) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", data, pos + chdr))
        elif ctype == RES_XML_START_ELEMENT:
            b = pos + 16
            _ns, name_i, attr_start, attr_size, attr_cnt = struct.unpack_from("<IIHHH", data, b)
            tag = strings[name_i] if name_i < len(strings) else f"#{name_i}"
            attrs = {}
            a = b + attr_start
            for _ in range(attr_cnt):
                _ans, aname, raw, _sz, _r0, dtype, dval = struct.unpack_from("<IIIHBBI", data, a)
                a += attr_size
                key = strings[aname] if aname < len(strings) else ""
                if not key and aname < len(res_ids):
                    key = ATTR_IDS.get(res_ids[aname], f"attr_{res_ids[aname]:08x}")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                elif dtype == TYPE_STRING and dval < len(strings):
                    val = strings[dval]
                elif dtype == TYPE_INT_DEC:
                    val = struct.unpack("<i", struct.pack("<I", dval))[0]
                elif dtype == TYPE_INT_HEX:
                    val = hex(dval)
                elif dtype == TYPE_BOOLEAN:
                    val = dval != 0
                elif dtype == TYPE_REFERENCE:
                    val = f"@0x{dval:08x}"
                else:
                    val = dval
                attrs[key] = val
            elements.append((tag, attrs))
        pos += csize
    return elements


def analyze(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        manifest = parse_axml(z.read("AndroidManifest.xml"))

        abis, libs = set(), set()
        for n in names:
            parts = n.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                abis.add(parts[1])
                libs.add(parts[2])

    info = {"abis": sorted(abis), "libs": sorted(libs),
            "permissions": [], "activities": [], "services": [],
            "receivers": [], "providers": []}
    comp = {"activity": "activities", "activity-alias": "activities",
            "service": "services", "receiver": "receivers", "provider": "providers"}

    for tag, a in manifest:
        if tag == "manifest":
            info["package"] = a.get("package")
            info["versionCode"] = a.get("versionCode")
            info["versionName"] = a.get("versionName")
        elif tag == "uses-sdk":
            info["minSdk"] = a.get("minSdkVersion")
            info["targetSdk"] = a.get("targetSdkVersion")
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            info["permissions"].append(a.get("name"))
        elif tag in comp:
            info[comp[tag]].append(a.get("name"))
    return info


def section(title, value):
    print(f"\n{title}")
    print(value if value not in (None, "") else "-")


def print_report(i, full):
    section("Package name", i.get("package"))
    section("versionCode", i.get("versionCode"))
    section("versionName", i.get("versionName"))
    if i["abis"]:
        section("Supported ABIs", ", ".join(i["abis"]))
        has64 = any("64" in a for a in i["abis"])
        section("64 bit architecture support", "YES" if has64 else "NO")
    section("Minimal supported Android version", sdk_str(i.get("minSdk", 1)))
    section("Target SDK", sdk_str(i.get("targetSdk", i.get("minSdk", 1))))
    if i["libs"]:
            section("Native libraries", ", ".join(i["libs"]))

    if full:
        for key, title in (("permissions", "Requested Permissions"),
                           ("activities", "Activities"),
                           ("services", "Services"),
                           ("receivers", "Broadcast Receivers"),
                           ("providers", "Content Providers")):
            section(f"{title} ({len(i[key])})", "\n".join(i[key]))
    print()


def collect_files(args):
    files = []
    for a in args:
        if os.path.isdir(a):
            files += sorted(glob.glob(os.path.join(a, "*.apk")))
        elif any(c in a for c in "*?["):
            files += sorted(glob.glob(a))
        else:
            files.append(a)
    return files


def main():
    if any(a in ("-h", "-help", "--help") for a in sys.argv[1:]):
            print(__doc__)
            sys.exit(0)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    full = "--full" in sys.argv
    files = collect_files(args)
    if not files:
        print(__doc__)
        sys.exit(1)

    failed = 0
    for n, path in enumerate(files):
        if len(files) > 1:
            print("=" * 70)
            print(f"[{n + 1}/{len(files)}] {path}")
            print("=" * 70)
        try:
            print_report(analyze(path), full)
        except (OSError, zipfile.BadZipFile, KeyError, ValueError, struct.error) as e:
            failed += 1
            print(f"Error: failed to analyze APK {path} ({e})\n", file=sys.stderr)

    if len(files) > 1:
        print(f"Analyzed: {len(files) - failed}/{len(files)}")
    sys.exit(2 if failed else 0)


if __name__ == "__main__":
    main()
