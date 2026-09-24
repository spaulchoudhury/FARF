"""
Structured logging for FARF (v7.7 hardening, v7.8 persistence)
------------------------------------------------------------------
Closes PHASE1_GAP_REPORT_v7.6.md Section 5 / THREAT_MODEL.md's "no
logging module anywhere in the codebase" finding. Previously every
module used raw print() (stdout) or print(..., file=sys.stderr) for
BOTH narration and genuine operational warnings, which made the two
visually indistinguishable and gave no way to redirect, filter, or
ship output to a real log sink without wrapping stdout externally.

This module gives every FARF component a standard `logging.Logger`
with two selectable output formats, controlled entirely by
environment variables so NO CODE CHANGE is needed to move from
laptop to cloud posture:

    FARF_LOG_LEVEL   DEBUG | INFO | WARNING | ERROR   (default INFO)
    FARF_LOG_FORMAT  text | json                       (default text)

  - "text" (default): human-readable, level-tagged single line --
    preserves the laptop-prototype console experience, just with a
    timestamp/level/component prefix instead of a bare print().
  - "json": one JSON object per line -- structured, machine-parseable,
    and directly consumable by CloudWatch Logs, Google Cloud Logging,
    Azure Monitor, or any log shipper that tails stdout/a file (the
    standard pattern for containerised workloads on all three clouds).

CURRENT WIRING STATE (accurate as of this note): `get_logger(__name__)`
is now called at import time by all ten production-path modules --
federation_bus.py, memory_store.py, agents.py (wired first),
orchestration.py, trust_protocol.py, taint_engine.py,
federation_ledger.py, adversary_model.py, fars.py and
adaptive_detection.py (wired in the same pass that added file
persistence below). Each emits structured records at its own
security-relevant decision points -- policy allow/block/quarantine,
credential verification failures, high-taint propagation and
quarantine actions, federation-ledger quorum witnessing/commit,
privilege-escalation path detection, FARS score computation, and
adaptive volume-cap calibration/trip events -- severity-mapped the
same way federation_bus.py's existing calls already were (routine =
debug, containment-adjacent = warning, active containment/escalation
= error). An earlier version of this docstring claimed all modules
were wired in while only 3 actually were; that was corrected once
actually checked, and is now genuinely accurate rather than aspirational.

v7.8 -- PERSISTENCE (this addition): previously every log record,
however well-formatted, only ever reached sys.stdout via a
StreamHandler and vanished the moment the process exited or the
terminal scrolled past it -- a real gap, given the SQLite audit trail
already gets buffer-and-retry durability (THREAT_MODEL.md Section 21)
but the parallel *log* stream got none. Two independent persistence
mechanisms are added, covering two different things that were
previously conflated as "just stdout":

  1. STRUCTURED LOG PERSISTENCE (this module, automatic): every
     `farf.*` logger record (the get_logger()-based calls above) is
     now ALSO written to a rotating file under logs/, in addition to
     stdout, using the same formatter (text or json per
     FARF_LOG_FORMAT) so nothing needs to change downstream. Governed
     by:
         FARF_LOG_TO_FILE      1 | 0            (default 1 -- on)
         FARF_LOG_DIR          path              (default: logs/ next
                                                   to this file, i.e.
                                                   <farf build dir>/logs)
         FARF_LOG_FILE         filename           (default farf.log)
         FARF_LOG_MAX_BYTES    int                (default 5_000_000)
         FARF_LOG_BACKUP_COUNT int                (default 5)
     Uses logging.handlers.RotatingFileHandler so a long-running
     process (or many repeated experiment runs) can't grow an
     unbounded log file -- old segments roll over to farf.log.1,
     farf.log.2, etc., up to FARF_LOG_BACKUP_COUNT, then the oldest is
     discarded. If the logs/ directory can't be created or opened
     (read-only filesystem, permissions), this fails OPEN for logging
     specifically -- a warning is emitted to stdout and the process
     continues with stdout-only logging, rather than crashing an
     otherwise-working security decision path over a logging problem.
     This differs from FARF's fail-CLOSED default for security
     decisions on purpose: losing log persistence is an observability
     degradation, not a security one, and should never be the reason
     a legitimate orchestration decision doesn't get made.

  2. RAW STDOUT PERSISTENCE (enable_stdout_persistence(), opt-in):
     main.py's scenario narration (the print() calls describing what
     each attack scenario is doing) is deliberately NOT routed through
     the logger -- see the scope note below, unchanged from the prior
     version of this docstring. But a full, byte-for-byte transcript
     of everything printed during a CLI run is still worth keeping,
     so `enable_stdout_persistence()` installs a tee that duplicates
     EVERYTHING written to sys.stdout (and sys.stderr) into a
     per-run timestamped file under logs/, while still printing to the
     real terminal exactly as before. This is what main.py calls at
     the top of main() so every `python main.py --scenario ...` run
     leaves behind a complete, persisted console transcript, without
     changing a single print() call anywhere in the CLI narration path.

Scope decision (unchanged, still accurate): this module's LOGGER
wiring is intended for the production call path making/recording
security-relevant decisions. It is deliberately NOT wired into:
  - main.py's scenario narration -- that's the CLI's actual
    human-facing product for a researcher running experiments, not a
    structured log stream; enable_stdout_persistence() captures it
    verbatim instead of forcing it through the logger's shape.
  - each module's own `if __name__ == "__main__":` self-test block --
    standalone developer demos, not part of any request path.
  - pentest/*.py -- narrated exploit-demonstration scripts meant to be
    read as a report when run directly.
This scoping matches how the codebase already treats "narration vs.
audit" elsewhere (e.g. print_fars() vs. the SQLite audit trail).
"""
import json
import logging
import logging.handlers
import os
import sys
import time

_RESERVED_RECORD_KEYS = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime"}


class _JsonFormatter(logging.Formatter):
    """One JSON object per line. Any structured fields passed via
    `logger.info(msg, extra={...})` ride along as top-level JSON keys,
    which is what lets a SIEM/log-aggregation query filter on e.g.
    `event == "bus_decision"` or `decision == "quarantine"` without
    regexing a free-text message string."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_KEYS:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _TextFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(fmt="[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
                          datefmt="%H:%M:%S")


_CONFIGURED = False
LOGS_DIR_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    level_name = os.environ.get("FARF_LOG_LEVEL", "INFO").upper()
    fmt_name = os.environ.get("FARF_LOG_FORMAT", "text").lower()
    level = getattr(logging, level_name, logging.INFO)
    formatter = _JsonFormatter() if fmt_name == "json" else _TextFormatter()

    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(formatter)

    root = logging.getLogger("farf")
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(stdout_handler)

    # v7.8: persist every logger record to a rotating file under logs/,
    # in addition to stdout -- see module docstring, item 1. Fails OPEN
    # (logging-only, never the caller) if the directory/file can't be
    # created, since a permissions or read-only-filesystem problem here
    # should degrade observability, not take down a working security
    # decision path.
    if os.environ.get("FARF_LOG_TO_FILE", "1") != "0":
        logs_dir = os.environ.get("FARF_LOG_DIR", LOGS_DIR_DEFAULT)
        log_file = os.environ.get("FARF_LOG_FILE", "farf.log")
        max_bytes = int(os.environ.get("FARF_LOG_MAX_BYTES", "5000000"))
        backup_count = int(os.environ.get("FARF_LOG_BACKUP_COUNT", "5"))
        try:
            os.makedirs(logs_dir, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(logs_dir, log_file),
                maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError as exc:
            print(f"[FARF logging] WARNING: could not open log file under '{logs_dir}' "
                  f"({exc}); continuing with stdout-only logging (this is a logging-"
                  f"persistence degradation, not a security-decision failure).",
                  file=sys.stderr)

    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Every production-path FARF module calls get_logger(__name__)
    once at import time. Reconfiguring FARF_LOG_LEVEL/FARF_LOG_FORMAT
    takes effect on the NEXT process start (root config happens once,
    lazily, on first call) -- this matches how every other
    environment-driven setting in the eventual cloud config works
    (see ARCHITECTURE_DECISIONS.md's runtime config section) and
    avoids reconfiguring handlers mid-run from multiple threads."""
    _configure_root()
    return logging.getLogger(f"farf.{name}")


class _StdoutTee:
    """Duplicates every write() to BOTH the original stream and a log
    file, byte for byte -- no reformatting, no filtering. Used by
    enable_stdout_persistence() below; not used by the logger path
    above (that already persists independently via the RotatingFileHandler)."""

    def __init__(self, original_stream, log_file):
        self._original = original_stream
        self._log_file = log_file

    def write(self, data):
        self._original.write(data)
        self._log_file.write(data)
        return len(data)

    def flush(self):
        self._original.flush()
        self._log_file.flush()

    def isatty(self):
        return self._original.isatty()


def enable_stdout_persistence(session_name: str | None = None, logs_dir: str | None = None) -> str:
    """v7.8: persists a full, verbatim transcript of everything written
    to sys.stdout AND sys.stderr for the remainder of the process, into
    a single timestamped file under logs/ -- see module docstring, item
    2. This is deliberately separate from the structured logger
    persistence above: it captures main.py's scenario narration
    print() calls exactly as a person watching the terminal would see
    them, without forcing that narration through the logger's
    field-structured shape (which was a documented, deliberate scope
    exclusion, not an oversight -- see the docstring's "Scope
    decision"). Call this ONCE, as early as possible in a CLI entry
    point's main(); it is idempotent-safe to call again but will open a
    second file and double-write from that point on, so entry points
    should call it exactly once, not per-scenario.

    Returns the path of the transcript file that was opened, so the
    caller can tell the user where it went.
    """
    logs_dir = logs_dir or os.environ.get("FARF_LOG_DIR", LOGS_DIR_DEFAULT)
    os.makedirs(logs_dir, exist_ok=True)
    session_name = session_name or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(logs_dir, f"session_{session_name}_stdout.log")
    log_file = open(path, "a", encoding="utf-8")  # noqa: SIM115
    sys.stdout = _StdoutTee(sys.stdout, log_file)
    sys.stderr = _StdoutTee(sys.stderr, log_file)
    return path


if __name__ == "__main__":
    demo_path = enable_stdout_persistence(session_name="farf_logging_selftest")
    print(f"--- stdout persistence demo: everything below is ALSO written to {demo_path} ---")
    for fmt in ("text", "json"):
        os.environ["FARF_LOG_FORMAT"] = fmt
        _CONFIGURED = False
        log = get_logger("demo")
        print(f"--- format={fmt} ---", file=sys.stderr)
        log.debug("this is filtered out at default INFO level")
        log.info("bus decision recorded", extra={"event": "bus_decision", "decision": "allow", "agent_id": "OrgA-advisor"})
        log.warning("audit write failed; row buffered", extra={"event": "audit_write_failed", "buffered_rows": 3})
        log.error("organisation quarantined", extra={"event": "org_quarantine", "org": "OrgA"})
    print(f"--- structured logger records ALSO persisted to {os.path.join(LOGS_DIR_DEFAULT, 'farf.log')} ---")
