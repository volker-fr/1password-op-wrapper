#!/usr/bin/env python3
"""Private GTK prompt that gives an op read request a visible reason label."""

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile

# This distinctive CLI help-banner text identifies the PATH-selected command because --version alone does not identify its vendor; it is a sanity check, not cryptographic proof, and can be spoofed.
OP_IDENTITY = "1password cli brings 1password to your terminal."
UNSUPPORTED_ARGUMENTS_ERROR = (
    "opread does not support extra op read arguments (for example --no-newline or --out-file); "
    "use: opread REF [REASON]"
)


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


def resolve_op(env=None):
    """Find and identify the PATH-selected 1Password CLI without authenticating."""
    env = dict(os.environ if env is None else env)
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
        try:
            result = subprocess.run(
                [path, option],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                "PATH-selected 'op' timed out running " + option + ": " + path
            )
        except OSError as exc:
            raise RuntimeError(
                "cannot run PATH-selected 'op' " + option + ": " + str(exc)
            )
        if result.returncode != 0:
            raise RuntimeError(
                "PATH-selected 'op' failed "
                + option
                + " with status "
                + str(result.returncode)
                + ": "
                + path
            )
        outputs.append((result.stdout or "") + "\n" + (result.stderr or ""))
    match = re.search(r"(?m)^\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s*$", outputs[0])
    if not match:
        raise RuntimeError("PATH-selected 'op' did not report a valid version: " + path)
    if OP_IDENTITY not in outputs[1].lower():
        raise RuntimeError(
            "PATH-selected 'op' is not identified as 1Password CLI by its help output: "
            + path
        )
    return path, match.group(1)


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


def gui(reference, label, op_path):
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
            state["proc"] = subprocess.Popen([op_path, "read", reference])
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


def terminate_process_group(child):
    """Stop the detached GUI group and reap its interpreter process."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    # The leader may already be gone while an op descendant ignores SIGTERM.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


class OpreadError(Exception):
    """A credential read failed; returncode is the CLI-compatible status."""

    def __init__(self, returncode):
        self.returncode = returncode
        super().__init__("opread failed with status " + str(returncode))


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


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--check-runtime":
        return check_runtime()
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print("usage: opread REF [REASON]\n\nShow a labeled 1Password CLI read prompt.")
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "--gui-child":
        try:
            return gui(sys.argv[2], sys.argv[3], sys.argv[4])
        except Exception as exc:
            print("opread prompt failed: " + str(exc), file=sys.stderr)
            return 70
    arguments = sys.argv[1:]
    if len(arguments) > 2 or any(argument.startswith("-") for argument in arguments):
        print(UNSUPPORTED_ARGUMENTS_ERROR, file=sys.stderr)
        return 2
    if len(arguments) not in (1, 2):
        print("usage: opread REF [REASON]", file=sys.stderr)
        return 2
    reference = arguments[0]
    reason = arguments[1] if len(arguments) == 2 else None
    try:
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


def read(reference, reason=None, *, env=None):
    """Return exact credential bytes using a snapshot of the supplied environment."""
    snapshot = dict(os.environ if env is None else env)
    return _read(reference, reason, snapshot, {"signal": None})


def _cli_read(reference, reason=None):
    pending = {"signal": None}
    old_handlers = {}

    def interrupted(signum, _frame):
        if pending["signal"] is None:
            pending["signal"] = signum

    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, interrupted)
        return _read(reference, reason, dict(os.environ), pending)
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def _read(reference, reason, env, pending):
    if reference.startswith("-") or (reason is not None and reason.startswith("-")):
        print(UNSUPPORTED_ARGUMENTS_ERROR, file=sys.stderr)
        raise OpreadError(2)
    try:
        validate_reference(reference)
        if reason is not None:
            clean_reason(reason)
        label = display_label(reference, reason)
        identity = desktop_identity(label)
    except (ValueError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise OpreadError(2) from None

    incompatible = (
        "OP_SERVICE_ACCOUNT_TOKEN",
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
        "OP_SESSION",
    )
    manual_session = any(
        name.startswith("OP_SESSION_")
        and name != "OP_SESSION_DELEGATION_ENABLED"
        and value
        for name, value in env.items()
    )
    if (
        any(env.get(name) for name in incompatible)
        or manual_session
        or env.get("OP_BIOMETRIC_UNLOCK_ENABLED", "").lower() == "false"
    ):
        print(
            "opread requires interactive desktop authentication; a non-interactive 1Password backend is configured",
            file=sys.stderr,
        )
        raise OpreadError(2)

    # The compositor derives the prompt identity from the executable basename.
    # Run a private copy of the system interpreter under that basename.
    tempdir = None
    executable = None
    child = None
    status = 69
    output = None
    try:
        op_path = None
        try:
            op_path, _op_version = resolve_op(env)
        except RuntimeError as exc:
            print("opread: " + str(exc), file=sys.stderr)
        if pending["signal"] is None and op_path is not None:
            tempdir = tempfile.mkdtemp(prefix="opread-python-")
            os.chmod(tempdir, 0o700)
            executable = os.path.join(tempdir, identity)
        try:
            source_python, python_home = select_python_runtime()
        except RuntimeError as exc:
            source_python = None
            print(str(exc), file=sys.stderr)
        if pending["signal"] is None and (source_python is None or op_path is None):
            pass
        elif pending["signal"] is None and op_path is not None:
            shutil.copyfile(source_python, executable)
            if pending["signal"] is None:
                os.chmod(executable, 0o700)
                child_env = {k: v for k, v in env.items() if not k.startswith("PYTHON")}
                child_env["PYTHONHOME"] = python_home
                child_env["OP_BIOMETRIC_UNLOCK_ENABLED"] = "true"
                if pending["signal"] is None:
                    child = subprocess.Popen(
                        [
                            executable,
                            os.path.abspath(__file__),
                            "--gui-child",
                            reference,
                            label,
                            op_path,
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        start_new_session=True,
                        env=child_env,
                    )
                    while pending["signal"] is None:
                        try:
                            output, _ = child.communicate(timeout=0.1)
                            code = child.returncode
                            status = code if code >= 0 else 128 - code
                            break
                        except subprocess.TimeoutExpired:
                            code = child.poll()
                            if code is not None:
                                status = code if code >= 0 else 128 - code
                                break
    except OSError as exc:
        print("cannot prepare opread prompt: " + str(exc), file=sys.stderr)
        status = 69
    finally:
        if child is not None:
            terminate_process_group(child)
            if output is None:
                try:
                    output, _ = child.communicate(timeout=1)
                except (subprocess.TimeoutExpired, OSError):
                    if status == 0 and pending["signal"] is None:
                        print("opread: cannot collect complete output", file=sys.stderr)
                        status = 69
            if child.stdout is not None:
                child.stdout.close()
        if executable is not None:
            try:
                os.unlink(executable)
            except OSError:
                pass
        if tempdir is not None:
            try:
                os.rmdir(tempdir)
            except OSError:
                pass
    if pending["signal"] is not None:
        status = {signal.SIGINT: 130, signal.SIGTERM: 143, signal.SIGHUP: 129}[
            pending["signal"]
        ]
    if status:
        raise OpreadError(status) from None
    return output


if __name__ == "__main__":
    raise SystemExit(main())
