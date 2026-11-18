#!/usr/bin/env python3
"""Private GTK prompt that gives an op read request a visible reason label."""

import argparse
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unicodedata

# This distinctive CLI help-banner text identifies the PATH-selected command because --version alone does not identify its vendor; it is a sanity check, not cryptographic proof, and can be spoofed.
OP_IDENTITY = "1password cli brings 1password to your terminal."
_CLI_NAME = "op-wrapper.py"
UNSUPPORTED_ARGUMENTS_ERROR = (
    "op-wrapper does not support extra op read arguments (for example --no-newline or --out-file); "
    f"use: {_CLI_NAME} REF [REASON]"
)
_INVALID_TIMEOUT_MESSAGE = "timeout must be a finite nonnegative number of seconds"
_FIELD = "read"
_ITEM_GET = "item-get"
_LIST_COMMANDS = {
    "item-list": ("item", "LIST ITEMS"),
    "vault-list": ("vault", "LIST VAULTS"),
    "account-list": ("account", "LIST ACCOUNTS"),
}


def select_python_runtime():
    """Return the real interpreter and its matching base Python home."""
    executable = os.path.realpath(sys.executable)
    python_home = os.path.realpath(sys.base_prefix)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise RuntimeError("cannot find the active Python interpreter")
    if not os.path.isdir(python_home):
        raise RuntimeError("cannot find the active Python base environment")
    return executable, python_home


def check_runtime():
    try:
        op_path, op_version = resolve_op()
    except RuntimeError as exc:
        print("FAIL " + str(exc))
        return 1
    print("PASS 1Password CLI: " + op_path + " (" + op_version + ")")
    try:
        executable, python_home = select_python_runtime()
    except RuntimeError as exc:
        print("FAIL " + str(exc))
        return 1
    print("PASS Python interpreter: " + executable)
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("PYTHON")
    }
    env["PYTHONHOME"] = python_home
    code = (
        "import gi; gi.require_version('Gtk', '3.0'); gi.require_version('Gdk', '3.0'); "
        "from gi.repository import Gtk, Gdk; "
        "print('PASS GTK %d.%d.%d and Gdk %s' % "
        "(Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version(), Gdk._version))"
    )
    result = subprocess.run([executable, "-c", code], env=env, check=False)
    if result.returncode:
        print("FAIL GTK 3 Python bindings (gi, Gtk, Gdk)")
        return 1
    return 0


def resolve_op(env=None, *, _context=None):
    """Find and identify the PATH-selected CLI using managed, bounded probes."""
    env = dict(os.environ if env is None else env)
    context = _context if _context is not None else _ReadContext()
    try:
        context.check()
        candidate = shutil.which("op", path=env.get("PATH", os.defpath))
        if candidate is None:
            raise RuntimeError(
                "cannot find executable 'op' on PATH; install 1Password CLI and check PATH"
            )
        path = os.path.realpath(candidate)
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            raise RuntimeError("PATH-selected 'op' is not an executable file: " + path)
        env["NO_COLOR"] = "1"
        env["OP_COLOR"] = "never"
        outputs = []
        for option in ("--version", "--help"):
            probe = None
            try:
                context.check()
                probe_deadline = time.monotonic() + 3
                probe = context.spawn(
                    [path, option], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                    start_new_session=True,
                )
                output = context.collect(probe, probe_deadline)
            except _ProbeTimeout:
                raise RuntimeError(
                    "PATH-selected 'op' timed out running " + option + ": " + path
                ) from None
            except OSError as exc:
                if not context.diagnostics:
                    raise
                raise RuntimeError(
                    "cannot run PATH-selected 'op' " + option + ": " + str(exc)
                ) from None
            finally:
                if probe is not None:
                    drained = context.cleanup(probe)
            if output is None:
                output = drained
            if probe.returncode != 0:
                raise RuntimeError(
                    "PATH-selected 'op' failed " + option + " with status "
                    + str(probe.returncode) + ": " + path
                )
            if output is None:
                raise RuntimeError("cannot collect PATH-selected 'op' " + option)
            context.check()
            outputs.append((output[0] + b"\n" + output[1]).decode("utf-8", errors="replace"))
        match = re.search(r"(?m)^\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s*$", outputs[0])
        if not match:
            raise RuntimeError("PATH-selected 'op' did not report a valid version: " + path)
        if OP_IDENTITY not in outputs[1].lower():
            raise RuntimeError(
                "PATH-selected 'op' is not identified as 1Password CLI by its help output: " + path
            )
        context.check()
        return path, match.group(1)
    finally:
        if _context is None:
            context.close()


def clean_reason(value):
    if not 1 <= len(value.encode("utf-8")) <= 128:
        raise ValueError("REASON must contain 1 to 128 bytes")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    if name in (".", ".."):
        raise ValueError("REASON must not be '.' or '..'")
    return name


def validate_reference(value):
    # op references are passed as one argv element and are never interpreted by
    # a shell. Keep validation conservative and reject control characters.
    if (
        not value.startswith("op://")
        or len(value) <= len("op://")
        or len(value) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("REF must be a valid op:// reference")


def display_label(reference, reason=None):
    # The first component is the vault; never expose it in the identity.
    path = reference[len("op://") :].partition("/")[2] or "request"
    return path + (": " + reason if reason is not None else "")


def desktop_identity(label):
    # Use the same ASCII-safe characters as the original reason-based identity.
    # Bound the combined reference and reason independently of reason validation.
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", label)[:240]
    return "request" if safe in ("", ".", "..") else safe


def gui(reference, label, op_path, *, vault=None, account=None, operation=None):
    if operation is None:
        operation = _FIELD if vault is None else _ITEM_GET
    if operation == _FIELD:
        validate_reference(reference)
        command = [op_path, "read", reference]
    else:
        _validate_json_request(operation, reference, vault, account)
        if operation == _ITEM_GET:
            command = [op_path, "item", "get", reference]
        else:
            command = [op_path, _LIST_COMMANDS[operation][0], "list"]
        if vault is not None:
            command += ["--vault", vault]
        command += ["--format", "json"]
        if account is not None:
            command += ["--account", account]

    try:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk, GLib
    except (ImportError, ValueError) as exc:
        print("cannot load GTK 3 bindings: " + str(exc), file=sys.stderr)
        return 69

    if not Gtk.init_check()[0]:
        print("cannot connect to graphical session", file=sys.stderr)
        return 2
    identity = label
    GLib.set_prgname(identity)
    Gdk.set_program_class(identity)
    window = Gtk.Window(title=label)
    Gtk.Widget.set_opacity(window, 0.0)
    window.set_decorated(False)
    try:
        from gi.repository import GdkX11

        if isinstance(Gdk.Display.get_default(), GdkX11.X11Display):
            window.set_wmclass(identity, identity)
    except (ImportError, AttributeError, TypeError):
        pass
    window.add(Gtk.Label(label="opread 1Password CLI request window"))
    # Deliberately avoid set_resizable(False): it was observed to make 1Password
    # show footclient instead of the overridden request identity.
    # Request a 1x1 window; compositor rules control floating and minimum size.
    window.set_size_request(1, 1)
    window.set_default_size(1, 1)
    window.realize()
    display = window.get_display()
    surface = window.get_window()
    try:
        from gi.repository import GdkWayland

        if isinstance(display, GdkWayland.WaylandDisplay) and isinstance(
            surface, GdkWayland.WaylandWindow
        ):
            GdkWayland.WaylandWindow.set_application_id(surface, identity)
    except (ImportError, AttributeError, TypeError):
        pass

    state = {"proc": None, "status": 1, "spawn_id": 0}

    def poll_op():
        proc = state["proc"]
        code = proc.poll()
        if code is None:
            return GLib.SOURCE_CONTINUE
        state["status"] = code if code >= 0 else 128 - code
        Gtk.main_quit()
        return GLib.SOURCE_REMOVE

    def run_op():
        state["spawn_id"] = 0
        if state["proc"] is not None:
            return GLib.SOURCE_REMOVE
        try:
            state["proc"] = subprocess.Popen(command)
        except OSError as exc:
            print("cannot start op: " + str(exc), file=sys.stderr)
            state["status"] = 127
            Gtk.main_quit()
            return GLib.SOURCE_REMOVE

        def close_window():
            window.destroy()
            return GLib.SOURCE_REMOVE

        # Keep the window mapped briefly so 1Password can identify the request.
        # Closing it immediately made the prompt fall back to the calling client.
        # Depending on the system, the number might need to be increased.
        # TODO: Make the window auto-close delay configurable.
        GLib.timeout_add(300, close_window)
        GLib.timeout_add(50, poll_op)
        return GLib.SOURCE_REMOVE

    def mapped(_window):
        state["spawn_id"] = GLib.timeout_add(300, run_op)

    def closing(_window, _event):
        if state["spawn_id"]:
            GLib.source_remove(state["spawn_id"])
        proc = state["proc"]
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            except OSError:
                pass
        state["status"] = 1
        Gtk.main_quit()
        return True

    def interrupted(_signum, _frame):
        closing(None, None)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)

    state["mapped"] = False

    def mapped_once(_window):
        if not state["mapped"]:
            state["mapped"] = True
            mapped(_window)

    window.connect("map", mapped_once)
    window.connect("delete-event", closing)
    window.show_all()
    Gtk.main()
    return state["status"]


def terminate_process_group(child, *, deadline=None):
    """Stop a detached group, including descendants of an exited leader."""
    if deadline is None:
        deadline = time.monotonic() + 5
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except OSError:
            pass
        remaining = max(0, deadline - time.monotonic())
        if remaining:
            try:
                child.wait(timeout=min(0.2, remaining))
            except (subprocess.TimeoutExpired, OSError):
                pass


class OpreadError(Exception):
    """A credential read failed; returncode is the CLI-compatible status."""

    def __init__(self, returncode):
        self.returncode = returncode
        super().__init__("opread failed with status " + str(returncode))


class OpreadTimeoutError(OpreadError):
    """The call's total timeout expired."""

    def __init__(self):
        super().__init__(124)


class OpreadCancelledError(OpreadError):
    """The caller requested cooperative cancellation."""

    def __init__(self):
        super().__init__(130)


class _ProbeTimeout(Exception):
    pass


class _InvalidTimeout(ValueError):
    pass


class _ReadContext:
    """Per-call control and ownership; no process-global environment or handlers."""

    def __init__(self, timeout=None, cancel=None, pending=None, *, diagnostics=True):
        started = time.monotonic()
        self.deadline = None
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
                raise _InvalidTimeout()
            try:
                deadline = started + timeout
            except OverflowError:
                raise _InvalidTimeout() from None
            if not math.isfinite(deadline):
                raise _InvalidTimeout()
            self.deadline = deadline
        self.cancel = cancel
        self.pending = pending
        self.diagnostics = diagnostics
        self.children = []
        self.cleanup_remaining = 5.0
        self.cleanup_failed = False

    def check(self):
        if self.pending is not None and self.pending["signal"] is not None:
            raise OpreadError(128 + self.pending["signal"])
        if self.cancel is not None and self.cancel.is_set():
            raise OpreadCancelledError()
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise OpreadTimeoutError()

    def spawn(self, *args, **kwargs):
        self.check()
        child = subprocess.Popen(*args, **kwargs)
        # Publish ownership before observing cancellation acquired during Popen.
        self.children.append(child)
        self.check()
        return child

    def collect(self, child, probe_deadline=None):
        while True:
            self.check()
            now = time.monotonic()
            if probe_deadline is not None and now >= probe_deadline:
                raise _ProbeTimeout()
            interval = 0.05
            for deadline in (self.deadline, probe_deadline):
                if deadline is not None:
                    interval = min(interval, max(0, deadline - now))
            try:
                return child.communicate(timeout=interval)
            except subprocess.TimeoutExpired:
                # EOF can lag leader exit indefinitely (including escaped holders).
                # Hand ownership to bounded cleanup rather than waiting for EOF.
                if child.poll() is not None:
                    return None

    def cleanup(self, child):
        started = time.monotonic()
        deadline = started + self.cleanup_remaining
        output = None
        try:
            terminate_process_group(child, deadline=deadline)
            remaining = max(0, deadline - time.monotonic())
            if remaining:
                try:
                    output = child.communicate(timeout=min(0.5, remaining))
                except (subprocess.TimeoutExpired, OSError, ValueError):
                    pass
        except Exception:
            self.cleanup_failed = True
        finally:
            for name in ("stdout", "stderr"):
                stream = getattr(child, name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        self.cleanup_failed = True
            self.children.remove(child)
            self.cleanup_remaining = max(0, self.cleanup_remaining - (time.monotonic() - started))
        return output

    def close(self):
        for child in self.children[:]:
            self.cleanup(child)


def neutralize_stdout():
    """Prevent a failed buffered stream from being flushed again at shutdown."""
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(fd, sys.stdout.fileno())
        finally:
            os.close(fd)
    except (OSError, ValueError, AttributeError):
        pass


class _CommandParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, _message):
        self.print_usage(sys.stderr)
        self.exit(2, "op-wrapper: invalid or unsupported arguments\n")


def _parse_cli_command(arguments):
    parser = _CommandParser(prog=_CLI_NAME)
    families = parser.add_subparsers(dest="family", required=True)
    for family in ("item", "vault", "account"):
        actions = families.add_parser(family).add_subparsers(dest="action", required=True)
        for action in (("get", "list") if family == "item" else ("list",)):
            command = actions.add_parser(action)
            if action == "get":
                command.add_argument("item", metavar="ITEM")
                command.usage = "%(prog)s ITEM --vault VAULT [--account ACCOUNT] [--reason REASON]"
            if family == "item":
                command.add_argument("--vault", metavar="VAULT", required=action == "get")
            if family != "account":
                command.add_argument("--account", metavar="ACCOUNT")
            command.add_argument("--reason", metavar="REASON")
            command.set_defaults(item=None, vault=None, account=None)
    return parser.parse_args(arguments)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--check-runtime":
        return check_runtime()
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(f"usage: {_CLI_NAME} REF [REASON]\n"
              f"       {_CLI_NAME} item get ITEM --vault VAULT [--account ACCOUNT] [--reason REASON]\n"
              f"       {_CLI_NAME} item list [--vault VAULT] [--account ACCOUNT] [--reason REASON]\n"
              f"       {_CLI_NAME} vault list [--account ACCOUNT] [--reason REASON]\n"
              f"       {_CLI_NAME} account list [--reason REASON]\n\n"
              "Show a labeled 1Password CLI read prompt.")
        return 0
    if len(sys.argv) == 7 and sys.argv[1] == "--gui-item-child":
        try:
            return gui(sys.argv[2], sys.argv[3], sys.argv[4],
                       vault=sys.argv[5], account=sys.argv[6] or None, operation=_ITEM_GET)
        except Exception:
            print("opread item prompt failed", file=sys.stderr)
            return 70
    if len(sys.argv) == 7 and sys.argv[1] == "--gui-list-child":
        operation, label, op_path, vault, account = sys.argv[2:]
        try:
            if operation not in _LIST_COMMANDS:
                raise ValueError("invalid list operation")
            return gui(None, label, op_path, vault=vault or None,
                       account=account or None, operation=operation)
        except Exception:
            print("opread list prompt failed", file=sys.stderr)
            return 70
    if len(sys.argv) == 5 and sys.argv[1] == "--gui-child":
        try:
            return gui(sys.argv[2], sys.argv[3], sys.argv[4])
        except Exception as exc:
            print("opread prompt failed: " + str(exc), file=sys.stderr)
            return 70
    arguments = sys.argv[1:]
    try:
        if arguments and arguments[0] in ("item", "vault", "account"):
            try:
                command = _parse_cli_command(arguments)
            except SystemExit as exc:
                return exc.code
            output = _cli_read(command.item, command.reason, vault=command.vault,
                               account=command.account, operation=command.family + "-" + command.action)
        else:
            if len(arguments) > 2 or any(argument.startswith("-") for argument in arguments):
                print(UNSUPPORTED_ARGUMENTS_ERROR, file=sys.stderr)
                return 2
            if len(arguments) not in (1, 2):
                print(f"usage: {_CLI_NAME} REF [REASON]", file=sys.stderr)
                return 2
            reference = arguments[0]
            reason = arguments[1] if len(arguments) == 2 else None
            output = _cli_read(reference, reason)
    except OpreadError as exc:
        return exc.returncode
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        neutralize_stdout()
        return 141
    except OSError:
        neutralize_stdout()
        print("opread: cannot write output", file=sys.stderr)
        return 1
    return 0


def read(reference, reason=None, *, env=None, timeout=None, cancel=None):
    """Return exact credential bytes with optional timeout and cooperative cancellation."""
    return _library_read(reference, reason, env, timeout, cancel)


def get_item(item, reason=None, *, vault, account=None, env=None, timeout=None, cancel=None):
    """Return a whole item as a parsed dict; suppress item diagnostics."""
    return _library_read(item, reason, env, timeout, cancel,
                         vault=vault, account=account, operation=_ITEM_GET)


def list_items(reason=None, *, vault=None, account=None, env=None, timeout=None, cancel=None):
    """Return item summaries as a list of dicts."""
    return _library_read(None, reason, env, timeout, cancel,
                         vault=vault, account=account, operation="item-list")


def list_vaults(reason=None, *, account=None, env=None, timeout=None, cancel=None):
    """Return vault summaries as a list of dicts."""
    return _library_read(None, reason, env, timeout, cancel, account=account, operation="vault-list")


def list_accounts(reason=None, *, env=None, timeout=None, cancel=None):
    """Return configured accounts as a list of dicts."""
    return _library_read(None, reason, env, timeout, cancel, operation="account-list")


def _library_read(reference, reason, env, timeout, cancel, *,
                  vault=None, account=None, operation=_FIELD):
    context = None
    try:
        context = _ReadContext(timeout, cancel, diagnostics=False)
        snapshot = dict(os.environ if env is None else env)
        return _read(reference, reason, snapshot, context,
                     vault=vault, account=account, operation=operation)
    except Exception as exc:
        kind = type(exc)
        if context is None and kind is _InvalidTimeout:
            failure = ValueError(_INVALID_TIMEOUT_MESSAGE)
        elif kind is OpreadTimeoutError:
            failure = OpreadTimeoutError()
        elif kind is OpreadCancelledError:
            failure = OpreadCancelledError()
        else:
            status = getattr(exc, "returncode", None) if kind is OpreadError else None
            failure = OpreadError(status if type(status) is int and 1 <= status <= 255 else 69)

    try:
        raise failure from None
    except (OpreadError, ValueError):
        # Python can attach an exception already being handled by the caller.
        failure.__context__ = None
        raise


def _cli_read(reference, reason=None, *, vault=None, account=None, operation=_FIELD):
    pending = {"signal": None}
    context = _ReadContext(pending=pending)
    old_handlers = {}

    def interrupted(signum, _frame):
        if pending["signal"] is None:
            pending["signal"] = signum

    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, interrupted)
        return _read(reference, reason, dict(os.environ), context,
                     vault=vault, account=account, operation=operation)
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def _validate_selector(value, name):
    if (not isinstance(value, str) or not value or value.startswith("-")
            or len(value.encode("utf-8")) > 4096
            or any(unicodedata.category(c) == "Cc" for c in value)):
        raise ValueError(name + " must be a nonempty, option-safe name or ID (at most 4096 UTF-8 bytes)")


def _validate_json_request(operation, reference, vault, account):
    # get_item must reject a missing/invalid vault, rather than becoming a field read.
    if operation == _ITEM_GET:
        _validate_selector(reference, "ITEM")
        _validate_selector(vault, "VAULT")
    elif operation not in _LIST_COMMANDS or reference is not None:
        raise ValueError("invalid JSON read operation")
    elif vault is not None:
        if operation != "item-list":
            raise ValueError("this operation does not accept a vault")
        _validate_selector(vault, "VAULT")
    if account is not None:
        if operation == "account-list":
            raise ValueError("this operation does not accept an account")
        _validate_selector(account, "ACCOUNT")


def _parse_json(output):
    def reject_constant(_value):
        raise ValueError("invalid JSON constant")
    return json.loads(output.decode("utf-8"), parse_constant=reject_constant)


def _parse_item_json(output):
    value = _parse_json(output)
    if not isinstance(value, dict):
        raise ValueError("item JSON must be an object")
    return value


def _parse_list_json(output):
    value = _parse_json(output)
    if not isinstance(value, list) or any(not isinstance(entry, dict) for entry in value):
        raise ValueError("list JSON must be an array of objects")
    return value


def _read(reference, reason, env, context, *, vault=None, account=None, operation=_FIELD):
    is_field = operation == _FIELD
    tempdir = executable = child = None
    output = None
    failure = None
    try:
        context.check()
        try:
            if is_field:
                if reference.startswith("-") or (reason is not None and reason.startswith("-")):
                    raise ValueError(UNSUPPORTED_ARGUMENTS_ERROR)
                validate_reference(reference)
            else:
                _validate_json_request(operation, reference, vault, account)
                if account is not None:
                    env["OP_ACCOUNT"] = account
            if reason is not None:
                if reason.startswith("-"):
                    raise ValueError(UNSUPPORTED_ARGUMENTS_ERROR)
                clean_reason(reason)
            if is_field:
                label = display_label(reference, reason)
            else:
                label = "WHOLE ITEM: " + reference if operation == _ITEM_GET else _LIST_COMMANDS[operation][1]
                if reason is not None:
                    label += ": " + reason
            identity = desktop_identity(label)
        except (ValueError, UnicodeError, TypeError, AttributeError) as exc:
            if context.diagnostics:
                print(str(exc) if is_field else "op-wrapper: invalid request arguments", file=sys.stderr)
            raise OpreadError(2) from None

        incompatible = ("OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SESSION")
        manual_session = any(
            name.startswith("OP_SESSION_") and name != "OP_SESSION_DELEGATION_ENABLED" and value
            for name, value in env.items()
        )
        if (any(env.get(name) for name in incompatible) or manual_session
                or env.get("OP_BIOMETRIC_UNLOCK_ENABLED", "").lower() == "false"):
            if context.diagnostics:
                print("op-wrapper requires interactive desktop authentication; a non-interactive 1Password backend is configured",
                      file=sys.stderr)
            raise OpreadError(2)

        op_path, _op_version = resolve_op(env, _context=context)
        context.check()
        tempdir = tempfile.mkdtemp(prefix="opread-python-")
        context.check()
        os.chmod(tempdir, 0o700)
        executable = os.path.join(tempdir, identity)
        try:
            source_python, python_home = select_python_runtime()
        except RuntimeError as exc:
            if context.diagnostics:
                print(str(exc) if is_field else "opread: cannot find Python runtime", file=sys.stderr)
            raise OpreadError(69) from None
        context.check()
        shutil.copyfile(source_python, executable)
        context.check()
        os.chmod(executable, 0o700)
        child_env = {k: v for k, v in env.items() if not k.startswith("PYTHON")}
        child_env["PYTHONHOME"] = python_home
        child_env["OP_BIOMETRIC_UNLOCK_ENABLED"] = "true"
        args = [executable, os.path.abspath(__file__)]
        stderr = None if context.diagnostics else subprocess.DEVNULL
        if is_field:
            args += ["--gui-child", reference, label, op_path]
        elif operation == _ITEM_GET:
            args += ["--gui-item-child", reference, label, op_path, vault, account or ""]
        else:
            args += ["--gui-list-child", operation, label, op_path, vault or "", account or ""]
        if not is_field:
            stderr = subprocess.PIPE
        child = context.spawn(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=stderr, start_new_session=True, env=child_env)
        collected = context.collect(child)
        status = child.returncode
        status = status if status >= 0 else 128 - status
        drained = context.cleanup(child)
        if collected is None:
            collected = drained
        if status:
            raise OpreadError(status)
        if collected is None:
            raise RuntimeError("cannot collect complete output")
        output = collected[0]
        context.check()
        if not is_field:
            parsed = _parse_item_json(output) if operation == _ITEM_GET else _parse_list_json(output)
            if context.pending is None:
                output = parsed
        context.check()
    except OpreadError as exc:
        failure = exc
    except Exception as exc:
        if not context.diagnostics:
            raise
        if not is_field:
            diagnostic = "opread: cannot complete JSON request"
        elif isinstance(exc, OSError):
            diagnostic = "cannot prepare opread prompt: " + str(exc)
        else:
            diagnostic = "opread: " + str(exc)
        print(diagnostic, file=sys.stderr)
        failure = OpreadError(69)
    finally:
        try:
            context.close()
        except Exception:
            context.cleanup_failed = True
        finally:
            if executable is not None:
                try:
                    os.unlink(executable)
                except OSError:
                    pass
                except Exception:
                    context.cleanup_failed = True
            if tempdir is not None:
                try:
                    os.rmdir(tempdir)
                except OSError:
                    pass
                except Exception:
                    context.cleanup_failed = True
    if failure is None and context.cleanup_failed:
        if context.diagnostics:
            print("opread: cannot finish cleanup", file=sys.stderr)
        failure = OpreadError(69)
    # CLI signals retain their historical precedence over child failures.
    # Library calls have no pending signal state and keep failure-first semantics.
    if context.pending is not None:
        context.check()
    if failure is not None:
        raise failure from None
    # Cancellation takes precedence over deadline when both become observable.
    context.check()
    return output


if __name__ == "__main__":
    raise SystemExit(main())
