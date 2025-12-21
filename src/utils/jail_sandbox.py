"""
Utility helpers for nudging untrusted experiment text through the sandboxed echo
binary *and* corralling Python snippets inside the PyJail containment wing. We
do not trust the interns, the cloud, or frankly ourselves, so this module keeps
the protective gear in one place.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Dict, Optional

from src.core.pyjail.pyjail import JailViolation, PythonJail

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = BASE_DIR.parent / "logs" / "bait.log"
SANDBOX_BINARY = BASE_DIR / "core" / "jail_binaries" / "sandboxed_echo"
_PYJAIL = PythonJail()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("isol8r.sandbox")


def _write_log(entry: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(entry + "\n")


def run_echo(payload: str, client_ip: str, timeout: float = 4.0) -> Dict[str, Optional[str]]:
    """
    Execute the sandboxed echo binary and return a structured response. The
    binary is intentionally boring, because bored binaries tend to be secure.

    Parameters
    ----------
    payload: str
        Text supplied by the curious human.
    client_ip: str
        IP address recorded for finger-pointing ceremonies.
    timeout: float
        Seconds before we yank the ejection seat.
    """
    start_time = time.monotonic()
    metadata_header = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] sandbox exec from={client_ip}"
    _write_log(metadata_header)
    _write_log(f"payload={payload.strip() or '<blank>'}")

    if not SANDBOX_BINARY.exists():
        error_message = (
            f"sandbox binary missing at {SANDBOX_BINARY}. "
            "Did someone forget to run the build step again?"
        )
        _write_log(f"failure={error_message}")
        return {
            "stdout": None,
            "stderr": error_message,
            "returncode": None,
            "duration": 0.0,
        }

    env = os.environ.copy()
    env["PATH"] = "/usr/bin:/bin"
    env["ISOL8R_RUNTIME"] = "project-sandtrap"

    cmd = [str(SANDBOX_BINARY)]
    logger.debug("Executing sandbox command: %s", " ".join(shlex.quote(x) for x in cmd))

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(SANDBOX_BINARY.parent),
        text=True,
    )

    try:
        stdout, stderr = proc.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        stderr = (stderr or "") + "\n[isol8r] execution timed out"
        _write_log("status=timeout")
    except Exception as exc:
        proc.kill()
        stdout, stderr = "", f"[isol8r] sandbox failure: {exc!r}"
        _write_log(f"status=exception type={type(exc).__name__} detail={exc}")
    else:
        _write_log(f"status=completed returncode={proc.returncode}")

    duration = time.monotonic() - start_time
    _write_log(f"duration={duration:.3f}s")

    if stdout:
        normalized = textwrap.dedent(stdout.rstrip("\n"))
        _write_log(f"stdout={normalized}")
    if stderr:
        normalized_err = textwrap.dedent(stderr.rstrip("\n"))
        _write_log(f"stderr={normalized_err}")

    return {
        "stdout": stdout,
        "stderr": stderr,
        "returncode": proc.returncode,
        "duration": duration,
    }


def format_result(result: Dict[str, Optional[str]]) -> str:
    """
    Produce a friendly block of text summarising the sandbox run. The front-end
    expects something human-readable, seeing as the humans keep reading it.
    """
    lines = [
        "Sandbox Execution Summary",
        "--------------------------",
        f"Return code : {result.get('returncode')}",
        f"Duration    : {result.get('duration', 0.0):.3f} seconds",
    ]
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if stdout:
        lines.append("")
        lines.append("Echoed Output:")
        lines.append(stdout.strip("\n") or "<empty>")
    if stderr:
        lines.append("")
        lines.append("Diagnostic Output:")
        lines.append(stderr.strip("\n") or "<empty>")
    return "\n".join(lines)


def run_in_jail(code: str) -> Dict[str, Optional[str]]:
    """
    Execute Python code inside the Project Sandtrap PyJail. The function wraps
    :class:`PythonJail` to provide the Flask layer with a tidy dictionary result
    and adds a dash of sarcasm to error messages so the UI stays on brand.
    """
    logger.debug("Dispatching code to PyJail (length=%s characters)", len(code))
    try:
        result = _PYJAIL.execute_code(code)
    except JailViolation as violation:
        logger.info("PyJail violation triggered: %s", violation)
        log_entry = getattr(violation, "log_entry", None) or str(violation)
        _PYJAIL.log_attempt("WARN", log_entry)
        keywords = list(getattr(violation, "keywords", ()))
        banner = getattr(violation, "banner", None) or "Containment alert: keyword tripwire fired."
        fake_flag_dropped = bool(getattr(violation, "fake_flag_dropped", False))
        payload_excerpt = getattr(violation, "payload_excerpt", None)
        return {
            "output": "",
            "error": str(violation),
            "stderr": str(violation),
            "log_entry": log_entry,
            "banner": banner,
            "duration": 0.0,
            "banned_keywords": keywords,
            "fake_flag_dropped": fake_flag_dropped,
            "vm_sessions": [],
            "vm_engaged": False,
            "payload_excerpt": payload_excerpt,
        }
    except Exception as exc:
        logger.exception("Unexpected failure in PyJail wrapper: %s", exc)
        return {
            "output": "",
            "error": f"PyJail encountered an unexpected issue: {exc}",
            "log_entry": "Unclassified PyJail error. Someone please feed the watchdog.",
            "banner": "PyJail sputtered. Logs captured the chaos.",
            "duration": 0.0,
            "banned_keywords": [],
        }

    error_message = result.error
    if error_message and not result.stderr.strip():
        # Translate known exceptions into playful commentary.
        error_type = error_message.split(":", 1)[0]
        if error_type == "SyntaxError":
            error_message += " (SyntaxError: the parser has left the chat.)"

    return {
        "output": result.stdout,
        "error": error_message,
        "log_entry": "Sandbox executed peacefully. Reality intact.",
        "banner": result.banner,
        "duration": result.duration,
        "banned_keywords": list(result.banned_keywords),
        "stderr": result.stderr,
        "fake_flag_dropped": result.fake_flag_dropped,
        "vm_sessions": result.vm_sessions,
        "vm_engaged": bool(result.vm_sessions),
        "payload_excerpt": None,
    }
