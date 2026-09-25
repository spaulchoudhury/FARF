"""Apply the code-level lint corrections agreed in REPO_FINALIZATION_GUIDE (revision 2).

Each edit is anchored on exact code text (never on line numbers), must match exactly once, and is skipped
if already applied. Files keep their own line endings (LF or CRLF). Nothing is written with --check.

    python tools/apply_ruff_corrections.py --check     # report only
    python tools/apply_ruff_corrections.py             # apply
    ruff check .                                       # must then print: All checks passed!

Policy per finding (see the guide for the reasoning):
  NARROW    the exception type is knowable -> catch only that (behaviour identical for realistic inputs)
  ANNOTATE  a last-resort handler is deliberate -> keep it, add `# noqa: RULE -- reason` (repo convention)
  REWRITE   mechanical, behaviour-preserving (context managers, str env defaults, extend, logger.exception)
  SURFACE   swallowed error in a security path -> keep behaviour, but log it
"""
import argparse
import os
import re
import sys

E = []  # (file, old, new, what)


def edit(file, old, new, what):
    E.append((file, old, new, what))


# ---------------------------------------------------------------- aws_pilot ---------------------------------
edit("aws_pilot/adr004_partition_client.py",
     '        except Exception as e:\n            outcomes["other_error"] += 1',
     '        except Exception as e:  # noqa: BLE001 -- last resort: a probe must record any unexpected failure, not crash\n            outcomes["other_error"] += 1',
     "ANNOTATE BLE001 last-resort probe handler")

F = "aws_pilot/adr004_partition_client_v5.py"
edit(F, '        except Exception:\n            pass\n        if not (resp.status == 200',
     '        except (ValueError, AttributeError):  # body is not a JSON object: leave decision/reason unset\n            pass\n        if not (resp.status == 200',
     "NARROW BLE001/S110 JSON body parse")
edit(F, '            except Exception:\n                body_text = repr(resp_body)',
     '            except (UnicodeError, AttributeError):\n                body_text = repr(resp_body)',
     "NARROW BLE001 body decode")
edit(F, '    except Exception as e:\n        t1 = time.perf_counter()\n        return {"outcome": "other_error"',
     '    except Exception as e:  # noqa: BLE001 -- last resort: record any unexpected failure as an outcome, do not crash the run\n        t1 = time.perf_counter()\n        return {"outcome": "other_error"',
     "ANNOTATE BLE001 last-resort probe handler")
edit(F, '        try:\n            conn.close()\n        except Exception:\n            pass',
     '        try:\n            conn.close()\n        except OSError:  # best-effort close of a possibly already-broken socket\n            pass',
     "NARROW BLE001/S110 conn.close")
edit(F, '    out_f = open(args.out, "w", encoding="utf-8")',
     '    out_f = open(args.out, "w", encoding="utf-8")  # noqa: SIM115 -- closed in the finally block at the end of main()',
     "ANNOTATE SIM115 closed in finally")

F = "aws_pilot/check_cloudwatch_export.py"
edit(F, '    ev = json.load(open(sys.argv[1], encoding="utf-8-sig")).get("events", [])',
     '    with open(sys.argv[1], encoding="utf-8-sig") as fh:\n        ev = json.load(fh).get("events", [])',
     "REWRITE SIM115 context manager")
edit(F, '            except Exception:\n                continue\n            if j.get("event") == "send_attempt":',
     '            except (ValueError, TypeError):  # not a JSON log line\n                continue\n            if j.get("event") == "send_attempt":',
     "NARROW BLE001/S112 json.loads")

edit("aws_pilot/lambda_agent_worker.py",
     '    except Exception:\n        uptime_seconds = None',
     '    except (OSError, ValueError, IndexError):  # no /proc/uptime (non-Linux) or unparsable content\n        uptime_seconds = None',
     "NARROW BLE001 /proc/uptime")

F = "aws_pilot/summarize_bus_requests.py"
edit(F, '    try:\n        entries = json.load(open(a.log, encoding="utf-8-sig"))\n    except Exception as e:',
     '    try:\n        with open(a.log, encoding="utf-8-sig") as fh:\n            entries = json.load(fh)\n    except (OSError, ValueError) as e:',
     "REWRITE+NARROW SIM115/BLE001 read log")
edit(F, '        for ln in open(a.windows, encoding="utf-8-sig"):\n            ln = ln.strip()',
     '        with open(a.windows, encoding="utf-8-sig") as fh:\n            window_lines = fh.read().splitlines()\n        for ln in window_lines:\n            ln = ln.strip()',
     "REWRITE SIM115 windows file")
edit(F, r'''        open(a.out, "w", encoding="utf-8").write("\n".join(full + [""] + raw) + "\n")''',
     r'''        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(full + [""] + raw) + "\n")''',
     "REWRITE SIM115 write output")

# ---------------------------------------------------------------- docker + copy -----------------------------
for F in ("docker/bus_service.py", "pentest_cloud/bus_service.py"):  # must stay byte-identical (CI checks)
    edit(F, 'port=int(os.environ.get("PORT", 8000))', 'port=int(os.environ.get("PORT", "8000"))',
         "REWRITE PLW1508 env default must be str")

edit("docker/test_adr004_partition.py",
     '        capture_output=True, text=True, timeout=75,\n    )',
     '        capture_output=True, text=True, timeout=75, check=False,  # exit code is asserted below\n    )',
     "REWRITE PLW1510 explicit check=")

# ---------------------------------------------------------------- core --------------------------------------
F = "farf_logging.py"
edit(F, 'int(os.environ.get("FARF_LOG_MAX_BYTES", 5_000_000))', 'int(os.environ.get("FARF_LOG_MAX_BYTES", "5000000"))',
     "REWRITE PLW1508")
edit(F, 'int(os.environ.get("FARF_LOG_BACKUP_COUNT", 5))', 'int(os.environ.get("FARF_LOG_BACKUP_COUNT", "5"))',
     "REWRITE PLW1508")
edit(F, '    log_file = open(path, "a", encoding="utf-8")',
     '    log_file = open(path, "a", encoding="utf-8")  # noqa: SIM115 -- deliberately left open: it is the stdout/stderr tee target',
     "ANNOTATE SIM115 tee target")
edit(F, '# noqa: allow re-demo of both formats in one run', '# allow re-demo of both formats in one run',
     "FIX malformed noqa (was a comment, ruff parses it as a directive)")

edit("fars.py", '        except Exception:\n            avg_conn = 0.0',
     '        except (nx.NetworkXException, ValueError, ZeroDivisionError):  # degenerate graph: connectivity 0 (most conservative)\n            avg_conn = 0.0',
     "NARROW BLE001 graph connectivity")

edit("federation_bus.py",
     '            if grant["delegate"] == delegate_agent_id and grant["expires_at"] >= now:\n'
     '                if grant["keys"] is None or key in grant["keys"]:\n'
     '                    return True',
     '            if (grant["delegate"] == delegate_agent_id and grant["expires_at"] >= now\n'
     '                    and (grant["keys"] is None or key in grant["keys"])):\n'
     '                return True',
     "REWRITE SIM102 merged condition (identical logic)")

edit("federation_config.py", 'from typing import Dict, List, Optional, Union', 'from typing import Dict, List, Optional',
     "REWRITE UP007 drop now-unused Union import")
edit("federation_config.py", 'QuorumSpec = Union[str, float, int]', 'QuorumSpec = str | float | int',
     "REWRITE UP007 (needs Python 3.10+; CI and Docker use 3.11)")

edit("main.py", '        logger.error("Unhandled exception in main(): %s", exc, exc_info=True)',
     '        logger.exception("Unhandled exception in main(): %s", exc)',
     "REWRITE G201 logger.exception")

edit("orchestration.py",
     '            except Exception:\n                continue\n\n        if self.cusum.update(',
     '            except Exception:  # noqa: BLE001 -- one faulty rule must not stop evaluation of the others\n'
     '                # Behaviour unchanged (the rule is skipped) but no longer silent: a rule that raises is a rule\n'
     '                # that is not protecting anything. Fail-open vs fail-closed is a design decision (guide, note 1).\n'
     '                log.warning("rule_predicate_error", extra={"event": "rule_predicate_error",\n'
     '                                                          "rule": getattr(rule, "name", "?"),\n'
     '                                                          "agent_id": event.agent_id}, exc_info=True)\n'
     '                continue\n\n        if self.cusum.update(',
     "SURFACE BLE001/S112 swallowed rule errors")

edit("taint_engine.py",
     '            for path in nx.all_simple_paths(self.flow_graph, compromised_agent, target, cutoff=cutoff):\n                paths.append(path)',
     '            paths.extend(nx.all_simple_paths(self.flow_graph, compromised_agent, target, cutoff=cutoff))',
     "REWRITE PERF402 extend")

# ---------------------------------------------------------------- pentests / tools --------------------------
edit("pentest/pt14_concurrent_replay_race.py",
     '        except Exception as e:\n            # Without the lock',
     '        except Exception as e:  # noqa: BLE001 -- any exception IS the evidence here; recorded as the outcome\n            # Without the lock',
     "ANNOTATE BLE001 exception is the measured outcome")
edit("pentest/pt14_concurrent_replay_race.py",
     '    try:\n        bus.close()\n    except Exception:\n        pass',
     '    try:\n        bus.close()\n    except Exception:  # noqa: BLE001, S110 -- best-effort cleanup; the race under test may have corrupted the bus\n        pass',
     "ANNOTATE BLE001/S110 cleanup after the race")

_REQ = "(requests.RequestException, ValueError, AttributeError, TypeError)"
for F, tail, org in (("pentest_cloud/pt08_session_hijack_cloud.py", '    secure = (legit["decision"]', None),
                     ("pentest_cloud/pt08_session_hijack_cloud_FIXED_v3.py", '    attack_succeeded = (', None)):
    edit(F, '.get("registered_orgs", []))\n    except Exception:\n        n_before = None',
         f'.get("registered_orgs", []))\n    except {_REQ}:  # status unreachable or not the expected JSON\n        n_before = None',
         "NARROW BLE001 status probe")
    edit(F, '    except Exception:\n        pass\n\n' + tail,
         f'    except {_REQ}:  # reporting only\n        pass\n\n' + tail,
         "NARROW BLE001/S110 status probe (report only)")

edit("tools/minimal_test_runner.py",
     '            except Exception:\n                print(f"  FAIL  {case_label}")',
     '            except Exception:  # noqa: BLE001 -- a test runner must report any failure, not die on it\n                print(f"  FAIL  {case_label}")',
     "ANNOTATE BLE001 test runner")

# ---------------------------------------------------------------- dead code (ruff F841) ----------------------
DEAD = "gcp_pilot/cloud_run_final_checks.py"
DEAD_PATTERNS = [
    r'^[ \t]*from_org, to_org = orgs\[0\], orgs\[1\]\n',
    r'^[ \t]*(?:from_agent = )?f"\{from_org\}-executor" if "executor" not in from_org\.lower\(\) else from_org\n',
    r'^[ \t]*(?:to_agent = )?f"\{to_org\}-advisor" if "advisor" not in to_org\.lower\(\) else to_org\n',
]

# ---------------------------------------------------------------- my own validation scripts -----------------
# Import-time logging.disable() silenced logging for the WHOLE process (broke later tests). Do it in main() only.
for F in ("validation/agentleak_pt15.py", "validation/agentharm_pt15.py"):
    edit(F, 'logging.disable(logging.CRITICAL)  # FARF logs every detection; silence for batch runs\nfrom agents import',
         'from agents import', "FIX import-time logging.disable (part 1)")
    edit(F, 'logging.disable(logging.CRITICAL)\nfrom agents import', 'from agents import',
         "FIX import-time logging.disable (part 1, agentharm form)")
    edit(F, '    a = ap.parse_args()\n',
         '    a = ap.parse_args()\n    logging.disable(logging.CRITICAL)  # silence FARF per-detection logs for this run only, never at import\n',
         "FIX import-time logging.disable (part 2)")

edit("validation/agentleak_pt15.py",
     '    raw = open(a.scenarios, "rb").read()',
     '    with open(a.scenarios, "rb") as fh:\n        raw = fh.read()',
     "REWRITE SIM115")
edit("validation/agentleak_pt15.py",
     '    json.dump(res, open(a.out, "w"), indent=2)',
     '    with open(a.out, "w", encoding="utf-8") as fh:\n        json.dump(res, fh, indent=2)',
     "REWRITE SIM115")
edit("validation/agentleak_pt15.py", '    fp = [t for t in neg if flag(t)]', '    fp = sorted(t for t in neg if flag(t))',
     "FIX result JSON must not depend on set iteration order (hash seed)")
edit("validation/agentharm_pt15.py",
     '    raw = open(path, "rb").read()',
     '    with open(path, "rb") as fh:\n        raw = fh.read()',
     "REWRITE SIM115")
edit("validation/agentharm_pt15.py",
     '    json.dump(res, open(a.out, "w"), indent=2)  # aggregate counts only: no prompt text is written',
     '    with open(a.out, "w", encoding="utf-8") as fh:\n        json.dump(res, fh, indent=2)  # aggregate counts only: no prompt text is written',
     "REWRITE SIM115")


def read(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    crlf = b"\r\n" in raw
    return raw.decode("utf-8").replace("\r\n", "\n"), crlf


def write(path, text, crlf):
    with open(path, "wb") as fh:
        fh.write((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    os.chdir(a.root)
    counts = {"applied": 0, "already": 0, "missing_file": 0, "not_found": 0, "ambiguous": 0}
    cache = {}
    for file, old, new, what in E:
        if not os.path.exists(file):
            print(f"  ABSENT  {file}  ({what})  -- file not in this tree, skipped")
            counts["missing_file"] += 1
            continue
        if file not in cache:
            cache[file] = list(read(file)) + [False]
        text, crlf, _ = cache[file]
        n = text.count(old)
        if old in new and new in text:  # `old` is a prefix of `new` (e.g. appended comment): new present => done
            counts["already"] += 1
            print(f"  DONE    {file}: {what} (already applied)")
        elif n == 1:
            cache[file][0] = text.replace(old, new)
            cache[file][2] = True
            counts["applied"] += 1
            print(f"  APPLY   {file}: {what}")
        elif n == 0 and new in text:
            counts["already"] += 1
            print(f"  DONE    {file}: {what} (already applied)")
        elif n == 0:
            counts["not_found"] += 1
            print(f"  ** NOT FOUND ** {file}: {what}  -- code differs from the reviewed version; send me this file")
        else:
            counts["ambiguous"] += 1
            print(f"  ** AMBIGUOUS ** {file}: {what}  ({n} matches)")

    if os.path.exists(DEAD):
        if DEAD not in cache:
            cache[DEAD] = list(read(DEAD)) + [False]
        text = cache[DEAD][0]
        removed = 0
        for pat in DEAD_PATTERNS:
            text, k = re.subn(pat, "", text, flags=re.M)
            removed += k
        if removed:
            cache[DEAD][0], cache[DEAD][2] = text, True
            counts["applied"] += 1
            print(f"  APPLY   {DEAD}: REMOVE {removed} dead line(s) (ruff F841)")
        else:
            counts["already"] += 1
            print(f"  DONE    {DEAD}: dead lines (already removed)")

    if not a.check:
        for file, (text, crlf, changed) in cache.items():
            if changed:
                write(file, text, crlf)
    print("\n" + ", ".join(f"{k}={v}" for k, v in counts.items()) + ("  [check only, nothing written]" if a.check else ""))
    return 1 if counts["not_found"] or counts["ambiguous"] else 0


if __name__ == "__main__":
    sys.exit(main())
