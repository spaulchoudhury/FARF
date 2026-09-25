"""Replace pilot-account identifiers in tracked text files with placeholders.

Run ONLY after your last use of farf_run.ps1 (the runner and the task definitions need the real values), and
after teardown. Dry-run by default; pass --apply to rewrite files. Uses `git ls-files`, so untracked evidence
and ignored files are never touched. Placeholders are the AWS documentation account id and obvious all-zero ids.

    python tools/scrub_pilot_ids.py --account-id <12-digit AWS id> --project-number <GCP project number>
    python tools/scrub_pilot_ids.py --account-id ... --project-number ... --apply

The real values are passed on the command line so that this file never contains them.
"""
import argparse, re, subprocess, sys

SG = (re.compile(r"\bsg-[0-9a-f]{17}\b"), "sg-00000000000000000")
SUBNET = (re.compile(r"\bsubnet-[0-9a-f]{17}\b"), "subnet-00000000000000000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--account-id", required=True, help="your 12-digit AWS account id")
    ap.add_argument("--project-number", required=True, help="your GCP project number")
    a = ap.parse_args()
    rules = [(re.compile(r"\b" + re.escape(a.account_id) + r"\b"), "123456789012"),
             (re.compile(r"\b" + re.escape(a.project_number) + r"\b"), "000000000000"), SG, SUBNET]
    files = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    total = 0
    for f in filter(None, files):
        if f.endswith("scrub_pilot_ids.py"):
            continue
        try:
            with open(f, "rb") as fh:
                text = fh.read().decode("utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: skip
        new, n = text, 0
        for rx, rep in rules:
            new, k = rx.subn(rep, new)
            n += k
        if n:
            total += n
            print(f"{n:4d}  {f}")
            if a.apply:
                with open(f, "wb") as fh:
                    fh.write(new.encode("utf-8"))
    print(f"{total} replacement(s) {'applied' if a.apply else '(dry run; use --apply)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
