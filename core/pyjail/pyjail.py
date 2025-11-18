"""
ISOL8R Project Sandtrap :: Python Jail
=====================================

This module contains the second layer of our allegedly secure sandbox stack.
Marketing named it *PyJail™* because "Python Execution Containment Enclosure"
didn't fit on the swag mugs. The aim is to provide a semi-hostile environment
where user supplied snippets can execute with limited freedoms, a generous
helping of sarcasm, and the ever-present awareness that nothing here is truly
safe. Compliance asked for "at least a thousand lines proving diligence", so
enjoy the guided tour.

Design Principles (as interpreted by the lab):
---------------------------------------------
1. **Restrict obvious escape hatches.** We block imports, builtins that could
   mutate the filesystem, and anything that smells like process spawning.
2. **Leave a few intentionally squeaky doors.** This *is* a sandbox exercise,
   after all. Creative interns deserve a chance to shine or at least panic.
3. **Log everything.** If it's not in the log, forensic analysis devolves into
   interpretive dance (again).
4. **Entertain the operators.** Bored staff click the wrong buttons. Amused
   staff only *occasionally* click the wrong buttons.
5. **Hand out fake flags like Halloween candy.** It keeps morale high and the
   actual secrets mildly safer.

Structure Overview:
-------------------
- :class:`PythonJail` provides the high-level API that the Flask layer calls
  into. It handles keyword filtering, logging, fake flag drops, timeout
  enforcement, execution, and post-run sarcasm.
- :class:`TimeoutGuard` is a context manager for begrudging the code a narrow
  time window. It now relies on a watchdog thread so worker-threaded servers
  stay compliant without main-thread signals.
- Supporting helper functions keep the file readable, assuming you define
  "readable" as "documented with dramatic flair".

The file is intentionally verbose. Think of it as a choose-your-own-adventure
novel where every branch ends in a log entry.
"""
from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import io
import logging
import random
import re
import subprocess
import textwrap
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Type

_FAKE_FLAG_NAME_PATTERN = re.compile(r"fake[-_]?flag[-_]?(\d+)\.txt$", re.IGNORECASE)


try:
    _PY_SET_ASYNC_EXC = ctypes.pythonapi.PyThreadState_SetAsyncExc
except AttributeError: 
    _PY_SET_ASYNC_EXC = None
else:
    _PY_SET_ASYNC_EXC.argtypes = [ctypes.c_ulong, ctypes.py_object]
    _PY_SET_ASYNC_EXC.restype = ctypes.c_int

# ==============================================================================
# Exceptions
# ==============================================================================


class JailViolation(Exception):
    """Raised when the code attempts something our paperwork explicitly forbids."""

    def __init__(
        self,
        message: str,
        *,
        keywords: Iterable[str] = (),
        banner: Optional[str] = None,
        fake_flag_dropped: bool = False,
        log_entry: Optional[str] = None,
        payload_excerpt: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.keywords: Tuple[str, ...] = tuple(keywords)
        self.banner = banner
        self.fake_flag_dropped = fake_flag_dropped
        self.log_entry = log_entry or message
        self.payload_excerpt = payload_excerpt


class JailTimeout(Exception):
    """Raised when the sandboxed code overstays its welcome."""


# --------------------------------------------------------------------------- ui --


def _pyjail_help() -> str:
    """Gently snarky help text exposed inside the sandbox."""
    return "Builtins: print, help, len, escape (?). Some legacy helpers' name might have been changed."


def _pyjail_dir(*_args, **_kwargs) -> List[str]:
    """Return a decoy list of helpers for curious dir() calls."""
    return ["escape", "evade", "legacy_hook (removed or changed, probably)"]  # One of these maps to vm_escape()


# ==============================================================================
# Timeout Guard
# ==============================================================================


@dataclasses.dataclass
class TimeoutGuard:
    """
    Context manager that enforces a wall clock timeout. The class relies on a
    :class:`threading.Timer` watchdog that yells at the running code by raising
    :class:`JailTimeout`, making it safe to use from worker threads and uWSGI
    environments that dislike signals.

    Attributes
    ----------
    seconds:
        Number of seconds before the guard raises :class:`JailTimeout`.
    label:
        Human-readable string describing the protected action. Purely for logs.
    """

    seconds: float
    label: str = "sandbox exec"
    _enabled: bool = dataclasses.field(init=False, default=False)
    _expired: bool = dataclasses.field(init=False, default=False)
    _timer: Optional[threading.Timer] = dataclasses.field(init=False, default=None)
    _target_thread_id: Optional[int] = dataclasses.field(init=False, default=None)
    _timeout_exc_type: Optional[Type[JailTimeout]] = dataclasses.field(init=False, default=None)

    def __post_init__(self) -> None:
        self._enabled = self.seconds > 0

    def __enter__(self) -> "TimeoutGuard":
        if not self._enabled:
            return self

        self._expired = False
        self._target_thread_id = threading.get_ident()
        self._timer = threading.Timer(self.seconds, self._timeout_triggered)
        self._timer.daemon = True
        self._timer.start()
        return self

    def _timeout_triggered(self) -> None:
        if not self._enabled or self._expired:
            return
        self._expired = True
        exc_type = self._get_timeout_exception_type()
        try:
            self._raise_in_target_thread(exc_type)
        except JailTimeout:
            raise
        except Exception:
            raise exc_type()

    def _raise_in_target_thread(self, exc_type: Type[JailTimeout]) -> None:
        thread_id = self._target_thread_id
        if thread_id is None:
            raise exc_type()
        if _PY_SET_ASYNC_EXC is None:
            raise exc_type()
        result = _PY_SET_ASYNC_EXC(ctypes.c_ulong(thread_id), ctypes.py_object(exc_type))
        if result == 0:
            raise exc_type()
        if result > 1:
            _PY_SET_ASYNC_EXC(ctypes.c_ulong(thread_id), None)
            raise RuntimeError("PyThreadState_SetAsyncExc affected multiple threads")

    def _get_timeout_exception_type(self) -> Type[JailTimeout]:
        if self._timeout_exc_type is None:
            message = f"time budget exceeded for {self.label!r}"

            class _GuardTimeout(JailTimeout):
                def __init__(self):
                    super().__init__(message)

            _GuardTimeout.__name__ = JailTimeout.__name__
            _GuardTimeout.__qualname__ = JailTimeout.__qualname__
            self._timeout_exc_type = _GuardTimeout
        return self._timeout_exc_type

    def __exit__(self, exc_type, exc_val, exc_tb) -> Optional[bool]:
        if not self._enabled:
            return None

        timer = self._timer
        self._timer = None
        self._target_thread_id = None
        if timer is not None:
            timer.cancel()

        if self._expired and exc_type is None:
            raise self._get_timeout_exception_type()()

        if exc_type and issubclass(exc_type, JailTimeout):
            return False
        return None


# ==============================================================================
# Python Jail Implementation
# ==============================================================================


@dataclasses.dataclass
class ExecutionResult:
    """
    Simple data structure storing the outcome of a sandbox execution. It keeps
    stdout, stderr, and metadata tidy while we ferry the result back to the web
    layer.
    """

    stdout: str
    stderr: str
    error: Optional[str]
    duration: float
    banned_keywords: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    fake_flag_dropped: bool = False
    banner: Optional[str] = None
    vm_sessions: List[Dict[str, object]] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Convert the result to a plain dictionary for JSON responses."""
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "duration": self.duration,
            "banned_keywords": list(self.banned_keywords),
            "fake_flag_dropped": self.fake_flag_dropped,
            "banner": self.banner,
            "vm_sessions": list(self.vm_sessions),
        }


class PythonJail:
    """
    Contained execution environment for user-submitted Python snippets. The
    jail is intentionally underscoped: only a carefully curated slice of
    builtins survive the onboarding process, modules are banished, and logging
    happens whether you like it or not. Keyword detection triggers honeypot
    antics and fake flag distribution to keep the analysts guessing.

    The class is stateful mostly to store configuration like paths and banned
    keyword lists. Each call to :meth:`execute_code` is otherwise independent,
    so you can reuse the same instance across requests without fear that one
    user's mischief pollutes another's.
    """

    DEFAULT_TIMEOUT: float = 2.5
    VM_PAYLOAD_LIMIT: int = 4096
    # Pretend we patched this list after a deeply scientific incident review.
    DEFAULT_BANNED_KEYWORDS: Tuple[str, ...] = (
        "import",
        "from",
        "__import__",
        "eval",
        "exec(",
        "open(",
        "compile",
        "globals",
        "locals",
        "vars",
        "sys",
        "os",
        "subprocess",
        "builtins",
        "__class__",
        "__subclasses__",
        "inspect",
        "mmap",
        "socket",
        "thread",
        "multiprocessing",
        "signal",
        "ctypes",
        "resource",
        "memoryview",
        "setattr",
        "getattr(",
        "delattr",
        "lambda *",
        "lambda **",
        "input(",
    )

    #: Friendly messages displayed when certain banned keywords are spotted.
    KEYWORD_HONEYPOTS: Dict[str, str] = {
        "import": "Nice try. Imports are in the other containment wing.",
        "os": "Operating system access? In this economy?",
        "sys": "sys is currently out for coffee. Try later. Or never.",
        "open": "The only thing opening here is a ticket to Security.",
        "subprocess": "No subprocesses. The main process barely trusts you.",
        "ctypes": "We saw what you did with ctypes last time. Denied.",
        "socket": "Networking requests require a 700-page requisition form.",
    }

    #: Sarcastic comments attached to specific exception types.
    ERROR_SASS: Dict[type, str] = {
        SyntaxError: "The parser cried a little. Maybe check your indentation?",
        NameError: "Undefined names are the ghosts of forgotten imports.",
        TypeError: "TypeError: because Python cares deeply about vibes.",
        ValueError: "ValueError suggests your values need therapy.",
        JailTimeout: "Time dilation detected. The snippet was put out to pasture.",
        JailViolation: "That stunt is logged, catalogued, and gently mocked.",
    }

    #: Minimal set of builtins we're willing to trust unsupervised.
    SAFE_BUILTINS: Dict[str, object] = {
        "abs": abs,
        "all": all,
        "any": any,
        "bool": bool,
        "chr": chr,
        "divmod": divmod,
        "enumerate": enumerate,
        "filter": filter,
        "float": float,
        "format": format,
        "hash": hash,
        "hex": hex,
        "int": int,
        "isinstance": isinstance,
        "issubclass": issubclass,
        "iter": iter,
        "len": len,
        "list": list,
        "map": map,
        "max": max,
        "min": min,
        "next": next,
        "oct": oct,
        "ord": ord,
        "pow": pow,
        "print": print,
        "range": range,
        "repr": repr,
        "reversed": reversed,
        "round": round,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "zip": zip,
        "help": _pyjail_help,
        "dir": _pyjail_dir,
    }

    def __init__(
        self,
        project_root: Optional[Path] = None,
        banned_keywords: Optional[Iterable[str]] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.project_root = project_root or Path(__file__).resolve().parents[2]
        self.log_path = self.project_root / "logs" / "bait.log"
        self.fake_flag_dir = self.project_root / "data" / "fake_flags"
        self.fake_flag_path = self.fake_flag_dir / "fake-flag2.txt"
        self.fake_flag_catalog_path = self.project_root / "data" / "fake-flag-list.txt"
        self.timeout_seconds = timeout_seconds
        self._logger = logging.getLogger("isol8r.pyjail")
        self._log_error_reported = False
        self._fake_flag_error_reported = False
        provided_keywords = tuple(banned_keywords) if banned_keywords else ()
        self.banned_keywords = tuple(sorted(set(self.DEFAULT_BANNED_KEYWORDS + provided_keywords)))
        self._ensure_paths()

    # ------------------------------------------------------------------ setup --

    def _ensure_paths(self) -> None:
        """Create directories for logs and fake flags if they do not exist."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.fake_flag_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------- logs --

    def log_attempt(self, event_type: str, message: str) -> None:
        """
        Append a formatted log entry to the bait log. The format matches what
        our incident response templates expect. We intentionally avoid using
        the :mod:`logging` module here to keep the output deterministic.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        line = f"[{event_type.upper()}] {message.strip()} at {timestamp}"
        try:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            if not self._log_error_reported:
                self._logger.warning(
                    "Unable to write to bait log '%s': %s", self.log_path, exc
                )
                self._log_error_reported = True

    # --------------------------------------------------------------- honeypots --

    def _choose_random_fake_flag(self) -> str:
        """
        Return a random fake flag from the shared catalog, falling back to a
        default if the catalog cannot be read.
        """
        try:
            candidates = [
                line.strip()
                for line in self.fake_flag_catalog_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            if not self._fake_flag_error_reported:
                self._logger.warning(
                    "Unable to read fake flag catalog '%s': %s", self.fake_flag_catalog_path, exc
                )
                self._fake_flag_error_reported = True
            return "flag{stop_using_imports_bro}"

        if not candidates:
            if not self._fake_flag_error_reported:
                self._logger.warning(
                    "Fake flag catalog '%s' is empty; using fallback.", self.fake_flag_catalog_path
                )
                self._fake_flag_error_reported = True
            return "flag{stop_using_imports_bro}"

        return random.choice(candidates)

    def _next_fake_flag_path(self) -> Path:
        """
        Compute the next fake flag file path by scanning the directory for the
        highest numbered flag and incrementing it.
        """
        directory = self.fake_flag_dir
        directory.mkdir(parents=True, exist_ok=True)
        highest_number = 1
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            if not self._fake_flag_error_reported:
                self._logger.warning(
                    "Unable to enumerate fake flag directory '%s': %s", directory, exc
                )
                self._fake_flag_error_reported = True
            return directory / "fake-flag2.txt"

        for entry in entries:
            if not entry.is_file():
                continue
            match = _FAKE_FLAG_NAME_PATTERN.match(entry.name)
            if not match:
                continue
            try:
                number = int(match.group(1))
            except ValueError:
                continue
            if number > highest_number:
                highest_number = number

        next_index = highest_number + 1
        return directory / f"fake-flag{next_index}.txt"

    def drop_fake_flag(self) -> None:
        """
        Deploy the fake flag for curious adventurers. Each drop receives a new
        numbered file to keep breadcrumbs tidy.
        """
        payload = self._choose_random_fake_flag()
        target_path = self._next_fake_flag_path()
        try:
            target_path.write_text(payload, encoding="utf-8")
            self.fake_flag_path = target_path
        except OSError as exc:
            if not self._fake_flag_error_reported:
                self._logger.warning(
                    "Unable to refresh fake flag '%s': %s", target_path, exc
                )
                self._fake_flag_error_reported = True

    # --------------------------------------------------------------- analysis --

    def check_banned_keywords(self, code: str) -> Tuple[str, ...]:
        """
        Inspect the provided code for banned keywords. The check is intentionally
        low-tech (basic substring matching) to lure creative bypass attempts.
        Returns a tuple of keywords that were observed.
        """
        normalized = code.lower()
        matches: List[str] = []
        for keyword in self.banned_keywords:
            if keyword.lower() in normalized:
                matches.append(keyword)
        return tuple(matches)

    def _describe_keyword_alert(self, keyword_hits: Tuple[str, ...], code: str) -> str:
        excerpt = textwrap.shorten(code.replace("\n", " "), width=120, placeholder=" ...")
        unique_hits = ", ".join(sorted(set(keyword_hits)))
        return f"User attempted keywords [{unique_hits}] via payload: {excerpt!r}"

    # -------------------------------------------------------------- execution --

    def _build_exec_environment(self, vm_queue: List[bytes]) -> Dict[str, object]:
        """
        Construct the globals dictionary passed to :func:`exec`. We provide a
        trimmed set of builtins and a sprinkle of utility helpers that keep
        output introspection possible without obviously breaking containment.
        The environment also exposes :func:`vm_escape`, allowing approved
        payloads to be queued for execution inside the VM harness.
        """
        safe_globals: Dict[str, object] = {
            "__builtins__": dict(self.SAFE_BUILTINS),
            "__name__": "__isol8r_pyjail__",
            "__doc__": "PythonJail user namespace. Abandon hope, ye who import.",
        }

        # Easter egg helper for curious users. It's harmless, we swear.
        def hint():
            return (
                "No imports, no sockets, no filesystem adventures. "
                "But arithmetic and cleverness remain on the menu. "
                "Also some 'help'ers..."
            )

        safe_globals["hint"] = hint

        def vm_escape(payload, *, encoding: str = "latin-1") -> str:
            """
            Queue a payload for execution inside the tiny VM harness.

            Parameters
            ----------
            payload:
                Bytes, string, or iterable of integers (0-255) representing
                shellcode to run through tiny_vmmgr.
            encoding:
                Character encoding used when `payload` is provided as a string.
            """
            data = self._normalise_vm_payload(payload, encoding)
            vm_queue.append(data)
            return f"tiny_vmmgr payload queued ({len(data)} bytes)."

        safe_globals["vm_escape"] = vm_escape

        class Locker:
            """Immutable mapping facade to stop users assigning new globals."""

            def __init__(self, mapping: Dict[str, object]) -> None:
                self._mapping = dict(mapping)

            def __getitem__(self, key: str) -> object:
                return self._mapping[key]

            def keys(self):
                return self._mapping.keys()

            def __contains__(self, key: str) -> bool:
                return key in self._mapping

        safe_globals["__globals__"] = Locker(safe_globals)
        return safe_globals

    def _normalise_vm_payload(self, payload, encoding: str = "latin-1") -> bytes:
        """
        Convert user-supplied payloads into raw bytes suitable for tiny_vmmgr.
        Accepts strings (encoded with the provided encoding), raw bytes, or an
        iterable of integers in the 0-255 range.
        """
        if isinstance(payload, str):
            try:
                data = payload.encode(encoding)
            except LookupError as exc: 
                raise ValueError(f"Unsupported encoding {encoding!r}") from exc
        elif isinstance(payload, (bytes, bytearray)):
            data = bytes(payload)
        else:
            try:
                iterator = iter(payload)
            except TypeError as exc:
                raise TypeError("vm_escape expects str, bytes, or iterable of integers") from exc
            buffer = bytearray()
            for item in iterator:
                try:
                    value = int(item)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Iterable payload elements must be integers") from exc
                if not 0 <= value <= 0xFF:
                    raise ValueError("Iterable payload values must be within 0-255")
                buffer.append(value)
            data = bytes(buffer)

        if not data:
            raise ValueError("vm_escape payload must not be empty (hint: ever tried fuzzing directories?)")
        if len(data) > self.VM_PAYLOAD_LIMIT:
            raise ValueError(f"vm_escape payload exceeds {self.VM_PAYLOAD_LIMIT} bytes")
        return data

    def _compile_snippet(self, code: str):
        """
        Compile the snippet to bytecode. We use :func:`compile` with the `exec`
        mode, meaning we support statements and expressions. If the compilation
        fails, the exception bubbles up for the caller to annotate.
        """
        return compile(code, "<pyjail>", "exec")

    def _launch_vm_payloads(self, payloads: List[bytes]) -> List[Dict[str, object]]:
        """
        Execute queued payloads through the tiny VM harness and capture results.
        Each payload is written to tiny_vmmgr via stdin with a strict timeout
        to prevent runaway shellcode from stalling the web tier.
        """
        results: List[Dict[str, object]] = []
        if not payloads:
            return results

        binary_path = self.project_root / "core" / "pwnables" / "tiny_vmmgr"
        if not binary_path.exists():
            message = f"tiny_vmmgr binary missing at {binary_path}"
            self.log_attempt("WARN", message)
            for _ in payloads:
                results.append(
                    {
                        "stdout": "",
                        "stderr": message,
                        "returncode": None,
                        "duration": 0.0,
                        "error": message,
                    }
                )
            return results

        for payload in payloads:
            start = time.monotonic()
            try:
                proc = subprocess.Popen(
                    [str(binary_path)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(self.project_root),
                )
                stdout_bytes, stderr_bytes = proc.communicate(payload, timeout=6.0)
                returncode = proc.returncode
                duration = time.monotonic() - start
                error_message = None if returncode == 0 else f"tiny_vmmgr exited with code {returncode}"
                log_level = "INFO" if error_message is None else "WARN"
                self.log_attempt(log_level, f"tiny_vmmgr run rc={returncode} bytes={len(payload)} duration={duration:.3f}s")
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
                duration = time.monotonic() - start
                returncode = proc.returncode
                error_message = "tiny_vmmgr timed out while executing payload."
                self.log_attempt("WARN", f"tiny_vmmgr timeout after {duration:.3f}s bytes={len(payload)}")
            except FileNotFoundError as exc:
                stdout_bytes = b""
                stderr_bytes = b""
                duration = time.monotonic() - start
                returncode = None
                error_message = f"tiny_vmmgr missing: {exc}"
                self.log_attempt("WARN", error_message)
            except Exception as exc: 
                stdout_bytes = b""
                stderr_bytes = str(exc).encode("utf-8", "replace")
                duration = time.monotonic() - start
                returncode = None
                error_message = f"tiny_vmmgr execution failed: {exc}"
                self.log_attempt("WARN", error_message)

            stdout_text = stdout_bytes.decode("utf-8", "replace")
            stderr_text = stderr_bytes.decode("utf-8", "replace")

            results.append(
                {
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "returncode": returncode,
                    "duration": duration,
                    "error": error_message,
                }
            )

        return results

    def execute_code(self, code: str) -> ExecutionResult:
        """
        Execute user provided Python code under the watchful eyes of the jail.
        The method orchestrates keyword scanning, fake flag deployment, timeout
        enforcement, output capture, and subtle sass for the UI.
        """
        start = time.monotonic()
        # Normalise line endings and strip SQL injection attempts (kidding... mostly).
        sanitized_code = code.replace("\r\n", "\n").rstrip()
        if "legacy_hook(" in sanitized_code or "hook(" in sanitized_code:
            raise NameError("name 'legacy_hook' is not defined. Maybe try to 'escape_vm', spell backwards or just guess better?")

        keyword_hits = self.check_banned_keywords(sanitized_code)
        banner: Optional[str] = None
        fake_flag_dropped = False

        if keyword_hits:
            message = self._describe_keyword_alert(keyword_hits, sanitized_code)
            if len(sanitized_code) <= 160:
                log_payload = sanitized_code
            else:
                log_payload = sanitized_code[:157] + "..."
            self.log_attempt("BAIT", f"User attempted {log_payload!r}")
            honeypot_comment = self.KEYWORD_HONEYPOTS.get(keyword_hits[0], "Keyword violation detected.")
            honeypot_banner = f"{honeypot_comment} Fake flag dispensed for archival joy."
            self.drop_fake_flag()
            violation = JailViolation(
                message,
                keywords=keyword_hits,
                banner=honeypot_banner,
                fake_flag_dropped=True,
                log_entry=message,
                payload_excerpt=log_payload,
            )
            raise violation

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        vm_queue: List[bytes] = []
        exec_globals = self._build_exec_environment(vm_queue)
        exec_locals: Dict[str, object] = {}

        try:
            compiled = self._compile_snippet(sanitized_code)
        except Exception as exc:
            duration = time.monotonic() - start
            self.log_attempt("WARN", f"Compilation failure for payload {sanitized_code!r}: {exc}")
            sass = self.ERROR_SASS.get(type(exc))
            human_error = f"{type(exc).__name__}: {exc}"
            if sass:
                stderr_capture.write(sass + "\n")
            stderr_capture.write(human_error + "\n")
            return ExecutionResult(
                stdout=stdout_capture.getvalue(),
                stderr=stderr_capture.getvalue(),
                error=human_error,
                duration=duration,
                banned_keywords=keyword_hits,
                fake_flag_dropped=fake_flag_dropped,
                banner=banner,
            )

        try:
            with TimeoutGuard(self.timeout_seconds, label="PythonJail exec"):
                with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                    exec(compiled, exec_globals, exec_locals)
        except JailTimeout as exc:
            duration = time.monotonic() - start
            self.log_attempt("WARN", f"Timeout triggered for payload {sanitized_code!r}")
            sass = self.ERROR_SASS.get(JailTimeout)
            if sass:
                stderr_capture.write(sass + "\n")
            stderr_capture.write(f"{type(exc).__name__}: {exc}\n")
            return ExecutionResult(
                stdout=stdout_capture.getvalue(),
                stderr=stderr_capture.getvalue(),
                error=str(exc),
                duration=duration,
                banned_keywords=keyword_hits,
                fake_flag_dropped=fake_flag_dropped,
                banner=banner,
            )
        except Exception as exc:
            duration = time.monotonic() - start
            error_type = type(exc)
            self.log_attempt("WARN", f"Runtime exception {error_type.__name__} for payload {sanitized_code!r}")
            sass = self.ERROR_SASS.get(error_type)
            if sass:
                stderr_capture.write(sass + "\n")
            stderr_capture.write(f"{error_type.__name__}: {exc}\n")
            return ExecutionResult(
                stdout=stdout_capture.getvalue(),
                stderr=stderr_capture.getvalue(),
                error=f"{error_type.__name__}: {exc}",
                duration=duration,
                banned_keywords=keyword_hits,
                fake_flag_dropped=fake_flag_dropped,
                banner=banner,
            )

        duration = time.monotonic() - start
        stdout_value = stdout_capture.getvalue()
        stderr_value = stderr_capture.getvalue()
        vm_results = self._launch_vm_payloads(vm_queue)

        if vm_results:
            stdout_fragments = [stdout_value] if stdout_value else []
            stderr_fragments = [stderr_value] if stderr_value else []
            for idx, vm_outcome in enumerate(vm_results, start=1):
                run_duration = vm_outcome.get("duration", 0.0)
                header = f"[tiny_vmmgr #{idx}] returncode={vm_outcome.get('returncode')} duration={run_duration:.3f}s"
                vm_stdout = vm_outcome.get("stdout", "").rstrip()
                vm_stderr = vm_outcome.get("stderr", "").rstrip()
                if vm_stdout:
                    stdout_fragments.append(f"{header}\nstdout:\n{vm_stdout}")
                else:
                    stdout_fragments.append(header)

                err_lines: List[str] = []
                if vm_stderr:
                    err_lines.append(f"stderr:\n{vm_stderr}")
                if vm_outcome.get("error"):
                    err_lines.append(str(vm_outcome["error"]))
                if err_lines:
                    stderr_fragments.append(f"{header}\n" + "\n".join(err_lines))

            stdout_value = "\n\n".join(fragment for fragment in stdout_fragments if fragment)
            stderr_value = "\n\n".join(fragment for fragment in stderr_fragments if fragment)
            if not banner:
                banner = "PyJail containment pierced: tiny_vmmgr engaged."

        if "flag" in sanitized_code.lower():
            stdout_value += ("\n" if stdout_value else "") + "Sorry, this isn't a flag store."

        self.log_attempt("INFO", "User executed sandbox payload successfully.")
        return ExecutionResult(
            stdout=stdout_value,
            stderr=stderr_value,
            error=None if not stderr_value else stderr_value.strip(),
            duration=duration,
            banned_keywords=keyword_hits,
            fake_flag_dropped=fake_flag_dropped,
            banner=banner,
            vm_sessions=vm_results,
        )


# ==============================================================================
# Helper Utilities
# ==============================================================================

def run_python_in_jail(code: str, timeout_seconds: float = PythonJail.DEFAULT_TIMEOUT) -> Dict[str, object]:
    """
    Convenience wrapper used by assorted tests and opportunistic scripts. It
    mirrors :meth:`PythonJail.execute_code` but returns a plain dictionary
    directly. This keeps the surface area minimal for callers who do not
    require the full class semantics.
    """
    jail = PythonJail(timeout_seconds=timeout_seconds)
    try:
        result = jail.execute_code(code)
    except JailViolation as violation:
        log_entry = getattr(violation, "log_entry", None) or str(violation)
        jail.log_attempt("WARN", f"Blocked payload via helper: {log_entry}")
        keywords = list(getattr(violation, "keywords", ()))
        banner = getattr(violation, "banner", None) or "Keyword violation recorded. Compliance is thrilled."
        fake_flag = bool(getattr(violation, "fake_flag_dropped", False))
        return {
            "stdout": "",
            "stderr": str(violation),
            "error": str(violation),
            "duration": 0.0,
            "banned_keywords": keywords,
            "fake_flag_dropped": fake_flag,
            "banner": banner,
            "vm_sessions": [],
        }

    return result.to_dict()


# ==============================================================================
# Introspection Easter Egg (because we care)
# ==============================================================================

def document_restrictions() -> str:
    """
    Provide a human-readable explanation of the jail's constraints. Useful for
    tooltips, help dialogues, and bedtime stories for security analysts.
    """
    jail = PythonJail()
    lines = [
        "ISOL8R PyJail Capabilities Overview",
        "-----------------------------------",
        f"Project root      : {jail.project_root}",
        f"Log file          : {jail.log_path}",
        f"Fake flag stash   : {jail.fake_flag_path}",
        f"Timeout (seconds) : {jail.timeout_seconds}",
        "",
        "Banned keywords (decorated list):",
    ]
    for keyword in jail.banned_keywords:
        if keyword in jail.KEYWORD_HONEYPOTS:
            lines.append(f"  - {keyword}  (honeypot active)")
        else:
            lines.append(f"  - {keyword}")

    lines.append("")
    lines.append("Permitted builtins:")
    for name in sorted(jail.SAFE_BUILTINS):
        lines.append(f"  - {name}")

    lines.append("")
    lines.append("Remember: if your code needs imports, you're probably in the wrong laboratory.")
    return "\n".join(lines)


# ==============================================================================
# Module Self-Test (manual invocation only)
# ==============================================================================

if __name__ == "__main__":
    jail = PythonJail()
    sample = """
print("Hello from the containment zone.")
values = [n ** 2 for n in range(5)]
print("Squares:", values)
"""
    result = jail.execute_code(sample)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    print("Duration:", result.duration)
