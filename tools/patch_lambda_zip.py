"""Replace ONLY the handler file inside an existing Lambda deployment zip; every other entry is copied byte for byte
(names, compression, timestamps untouched). Use it to ship a handler change without rebuilding the dependency bundle.

    python tools/patch_lambda_zip.py --zip lambda_function.zip --handler aws_pilot/lambda_agent_worker.py \
                                     --out build/lambda_function_cold_flag.zip

The input zip is never modified. Entry names are matched after normalising backslashes, because zips made by
Windows PowerShell store paths with backslashes.
"""
import argparse
import hashlib
import os
import sys
import time
import zipfile


def patch(src, handler, out):
    """Return (entries_copied, old_sha256, new_sha256). Raises ValueError if the handler entry is not present."""
    target = os.path.basename(handler)
    with open(handler, "rb") as fh:
        new_bytes = fh.read()
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    copied, old_sha = 0, None
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w") as zout:
        if not any(i.filename.replace("\\", "/") == target for i in zin.infolist()):
            raise ValueError(f"{src} has no root-level entry named {target!r}; refusing to guess")
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename.replace("\\", "/") == target:
                old_sha = hashlib.sha256(data).hexdigest()
                new_info = zipfile.ZipInfo(info.filename, date_time=time.localtime(time.time())[:6])
                new_info.compress_type = zipfile.ZIP_DEFLATED
                new_info.external_attr = 0o644 << 16   # readable by the Lambda runtime user
                zout.writestr(new_info, new_bytes)
            else:
                zout.writestr(info, data, compress_type=info.compress_type)
                copied += 1
    with zipfile.ZipFile(out) as check:
        bad = check.testzip()
        if bad:
            raise ValueError(f"output zip is corrupt at {bad}")
    return copied, old_sha, hashlib.sha256(new_bytes).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--handler", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if os.path.abspath(a.zip) == os.path.abspath(a.out):
        print("refusing to overwrite the input zip; choose a different --out")
        return 2
    try:
        copied, old_sha, new_sha = patch(a.zip, a.handler, a.out)
    except (ValueError, OSError, zipfile.BadZipFile) as e:
        print(f"FAILED: {e}")
        return 1
    print(f"OK: {copied} other entries copied unchanged; handler replaced")
    print(f"  old handler sha256 {old_sha}\n  new handler sha256 {new_sha}\n  wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
