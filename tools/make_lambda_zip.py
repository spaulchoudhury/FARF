"""Build a Lambda zip with FORWARD-SLASH entry names (Windows PowerShell 5.1 Compress-Archive writes backslashes).
    python tools/make_lambda_zip.py --src lambda_build_v11 --out lambda_v11_runner.zip
Every file under --src goes in at its relative path; the root must contain the handler module."""
import argparse
import os
import sys
import zipfile


def build(src, out, must_have="v11_lambda_runner.py"):
    if not os.path.exists(os.path.join(src, must_have)):
        raise SystemExit(f"{src} does not contain {must_have}")
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, src).replace(os.sep, "/"))
                n += 1
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    print(f"wrote {a.out}: {build(a.src, a.out)} files")
    sys.exit(0)
