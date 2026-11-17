import contextlib
import importlib.util
import io
import os
import tempfile
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "opread.py"
spec = importlib.util.spec_from_file_location("opread_under_test", SCRIPT.parent / "lib" / "opread.py")
opread = importlib.util.module_from_spec(spec)
spec.loader.exec_module(opread)
REAL_RESOLVE_OP = opread.resolve_op


class Child:
    pid = 987654

    def __init__(self, status):
        self.status = status
        self.returncode = status
        self.stdout = io.BytesIO()

    def communicate(self, timeout=None):
        return b"", None

    def wait(self, timeout=None):
        return self.status

    def poll(self):
        return self.status


class OpreadTests(unittest.TestCase):
    def setUp(self):
        self.op_resolver = mock.patch.object(opread, "resolve_op", return_value=("/validated/bin/op", "2.41.1"))
        self.op_resolver.start()
        self.addCleanup(self.op_resolver.stop)

    def make_fake_op(self, directory, version="2.41.1", help_text="1Password CLI brings 1Password to your terminal."):
        executable = Path(directory) / "op"
        executable.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            f"  --version) printf '%s\\n' {version!r} ;;\n"
            f"  --help) printf '%s\\n' {help_text!r} ;;\n"
            "  *) exit 9 ;;\n"
            "esac\n"
        )
        executable.chmod(0o700)
        return executable

    def test_resolver_finds_and_validates_path_selected_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_fake_op(directory)
            with mock.patch.dict(opread.os.environ, {"PATH": directory}, clear=False):
                self.assertEqual(REAL_RESOLVE_OP(), (str(executable.resolve()), "2.41.1"))

    def test_resolver_rejects_impostor_with_plausible_version(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_fake_op(directory, help_text="A generic command line tool.")
            with mock.patch.dict(opread.os.environ, {"PATH": directory}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "not identified as 1Password"):
                    REAL_RESOLVE_OP()

    def test_resolver_reports_missing_cli(self):
        with mock.patch.dict(opread.os.environ, {"PATH": ""}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "cannot find executable 'op'"):
                REAL_RESOLVE_OP()

    def test_resolver_reports_probe_failure_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_fake_op(directory)
            failed = Child(7)
            with mock.patch.object(opread.subprocess, "Popen", return_value=failed), \
                 mock.patch.object(opread, "terminate_process_group"):
                with self.assertRaisesRegex(RuntimeError, "failed --version with status 7"):
                    REAL_RESOLVE_OP({"PATH": directory})
            hung = Child(None)
            with mock.patch.object(opread.subprocess, "Popen", return_value=hung), \
                 mock.patch.object(opread._ReadContext, "collect", side_effect=opread._ProbeTimeout), \
                 mock.patch.object(opread, "terminate_process_group"):
                with self.assertRaisesRegex(RuntimeError, "timed out running --version"):
                    REAL_RESOLVE_OP({"PATH": directory})
            self.assertTrue(hung.stdout.closed)

    def test_normal_failure_happens_before_temp_or_gui_child(self):
        self.op_resolver.stop()
        self.addCleanup(self.op_resolver.start)
        with mock.patch.object(opread, "resolve_op", side_effect=RuntimeError("wrong program")), \
             mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
             mock.patch.object(opread.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(opread.subprocess, "Popen") as popen, \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(opread.main(), 69)
        self.assertIn("wrong program", errors.getvalue())
        mkdtemp.assert_not_called()
        popen.assert_not_called()

    def test_runtime_selection_uses_real_interpreter_and_base_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base"
            base.mkdir()
            target = base / "python3.12"
            target.write_text("interpreter")
            target.chmod(0o700)
            link = Path(directory) / "python"
            link.symlink_to(target)
            with mock.patch.object(opread.sys, "executable", str(link)), \
                 mock.patch.object(opread.sys, "base_prefix", str(base)):
                self.assertEqual(opread.select_python_runtime(), (str(target), str(base)))

    def test_runtime_check_uses_selected_interpreter_and_pythonhome(self):
        with mock.patch.object(opread, "resolve_op", return_value=("/validated/bin/op", "2.41.1")), \
             mock.patch.object(opread, "select_python_runtime", return_value=("/base/bin/python3", "/base")), \
             mock.patch.object(opread.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(opread.check_runtime(), 0)
        self.assertEqual(run.call_args.args[0][0], "/base/bin/python3")
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONHOME"], "/base")

    def test_rejects_option_like_and_non_op_references(self):
        for reference in ("--help", "vault/item", "op://vault/item\n--help"):
            with self.subTest(reference=reference):
                with self.assertRaises(ValueError):
                    opread.validate_reference(reference)

    def test_missing_reference_fails_before_probe(self):
        with mock.patch.object(opread.sys, "argv", ["opread"]), \
             mock.patch.object(opread, "resolve_op") as resolve_op, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(opread.main(), 2)
        resolve_op.assert_not_called()

    def test_label_omits_vault_and_preserves_reason(self):
        ref = "op://Private/fooo/section/API_TOKEN_READ_ONLY"
        self.assertEqual(opread.display_label(ref), "fooo/section/API_TOKEN_READ_ONLY")
        self.assertEqual(opread.display_label(ref, "Fastmail / résumé"),
                         "fooo/section/API_TOKEN_READ_ONLY: Fastmail / résumé")
        self.assertEqual(opread.desktop_identity(opread.display_label(ref, "Fastmail")),
                         "fooo_section_API_TOKEN_READ_ONLY__Fastmail")

    def test_desktop_identity_is_safe_and_bounded(self):
        self.assertEqual(opread.desktop_identity("../a\nb"), ".._a_b")
        self.assertEqual(opread.desktop_identity(".."), "request")
        identity = opread.desktop_identity("é" * 300)
        self.assertLessEqual(len(identity.encode("utf-8")), 240)
        self.assertNotIn("/", identity)

    def test_explicit_reason_validation_before_probe(self):
        for reason in ("", ".", "..", "é" * 65):
            with self.subTest(reason=reason), \
                 mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item/field", reason]), \
                 mock.patch.object(opread, "resolve_op") as resolve_op, \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(opread.main(), 2)
                resolve_op.assert_not_called()

    def test_help_does_not_start_gui_or_require_bindings(self):
        with mock.patch.object(opread.sys, "argv", ["opread", "--help"]):
            self.assertEqual(opread.main(), 0)

    def test_unsupported_op_arguments_fail_before_probe_or_gui(self):
        cases = (
            ["opread", "--no-newline", "op://vault/item", "Finance"],
            ["opread", "op://vault/item", "Finance", "--out-file", "file"],
            ["opread", "op://vault/item", "--no-newline"],
            ["opread", "op://vault/item", "-n"],
        )
        for argv in cases:
            with self.subTest(argv=argv), \
                 mock.patch.object(opread.sys, "argv", argv), \
                 mock.patch.object(opread, "resolve_op") as resolve_op, \
                 mock.patch.object(opread.tempfile, "mkdtemp") as mkdtemp, \
                 mock.patch.object(opread.subprocess, "Popen") as popen, \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(opread.main(), 2)
                self.assertEqual(errors.getvalue().strip(), opread.UNSUPPORTED_ARGUMENTS_ERROR)
                resolve_op.assert_not_called()
                mkdtemp.assert_not_called()
                popen.assert_not_called()

    def test_read_returns_exact_bytes_and_suppresses_failures(self):
        for data in (b"", b"newline\n\n", b"nul\0\xff", b"x" * 200000):
            child = Child(0)
            child.communicate = mock.Mock(return_value=(data, None))
            with self.subTest(length=len(data)), \
                 mock.patch.object(opread.subprocess, "Popen", return_value=child) as popen, \
                 mock.patch.object(opread, "terminate_process_group"):
                self.assertEqual(opread.read("op://vault/item", "Finance"), data)
            self.assertEqual(popen.call_args.kwargs["stdout"], opread.subprocess.PIPE)
            self.assertNotIn("stderr", popen.call_args.kwargs)
        child = Child(7)
        child.communicate = mock.Mock(return_value=(b"secret", None))
        with mock.patch.object(opread.subprocess, "Popen", return_value=child), \
             mock.patch.object(opread, "terminate_process_group"), \
             self.assertRaises(opread.OpreadError) as error:
            opread.read("op://vault/item")
        self.assertEqual(error.exception.returncode, 7)
        self.assertNotIn("secret", str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    def test_read_rejects_option_like_arguments_before_probe(self):
        for reference, reason in (("-ref", None), ("op://vault/item", "-reason")):
            with self.subTest(reference=reference, reason=reason), \
                 mock.patch.object(opread, "resolve_op") as resolve_op, \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(opread.OpreadError) as error:
                    opread.read(reference, reason)
                self.assertEqual(error.exception.returncode, 2)
                self.assertEqual(errors.getvalue().strip(), opread.UNSUPPORTED_ARGUMENTS_ERROR)
                resolve_op.assert_not_called()

    def test_root_entry_point_forwards_to_library_main(self):
        import runpy
        with mock.patch("lib.opread.main", return_value=7) as main:
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(result.exception.code, 7)
        main.assert_called_once_with()

    def test_child_status_is_forwarded_and_tempdir_removed(self):
        with tempfile.TemporaryDirectory() as parent:
            created = []

            def mkdtemp(**kwargs):
                path = os.path.join(parent, "private")
                os.mkdir(path, 0o700)
                created.append(path)
                return path

            child = Child(7)
            with mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance approval"]), \
                 mock.patch.object(opread.tempfile, "mkdtemp", side_effect=mkdtemp), \
                 mock.patch.object(opread.subprocess, "Popen", return_value=child) as popen, \
                 mock.patch.object(opread, "terminate_process_group") as cleanup:
                self.assertEqual(opread.main(), 7)
            cleanup.assert_called_once_with(child, deadline=mock.ANY)
            argv = popen.call_args.args[0]
            self.assertEqual(argv[-4:], ["--gui-child", "op://vault/item", "item: Finance approval", "/validated/bin/op"])
            self.assertEqual(popen.call_args.kwargs["env"]["OP_BIOMETRIC_UNLOCK_ENABLED"], "true")
            self.assertEqual(popen.call_args.kwargs["env"]["PYTHONHOME"], opread.select_python_runtime()[1])
            self.assertFalse(os.path.exists(created[0]))

    @contextlib.contextmanager
    def fake_gui(self):
        window = mock.Mock()
        gtk = mock.Mock()
        gtk.init_check.return_value = (True, [])
        gtk.Window.return_value = window
        gdk = mock.Mock()
        glib = mock.Mock(SOURCE_CONTINUE=True, SOURCE_REMOVE=False)
        handlers, timers = {}, {}

        def timeout_add(delay, callback):
            source_id = len(timers) + 1
            timers[source_id] = (delay, callback)
            return source_id

        window.connect.side_effect = lambda event, callback: handlers.__setitem__(event, callback)
        window.show_all.side_effect = lambda: handlers["map"](window)
        glib.timeout_add.side_effect = timeout_add
        gi = types.ModuleType("gi")
        gi.require_version = mock.Mock()
        repository = types.ModuleType("gi.repository")
        x11 = types.ModuleType("gi.repository.GdkX11")
        x11.X11Display = type("X11Display", (), {})
        wayland = types.ModuleType("gi.repository.GdkWayland")
        wayland.WaylandDisplay = type("WaylandDisplay", (), {})
        wayland.WaylandWindow = type("WaylandWindow", (), {"set_application_id": mock.Mock()})
        display, surface = wayland.WaylandDisplay(), wayland.WaylandWindow()
        gdk.Display.get_default.return_value = display
        window.get_display.return_value = display
        window.get_window.return_value = surface
        repository.Gtk, repository.Gdk, repository.GLib = gtk, gdk, glib
        repository.GdkX11, repository.GdkWayland = x11, wayland
        modules = {"gi": gi, "gi.repository": repository,
                   "gi.repository.GdkX11": x11, "gi.repository.GdkWayland": wayland}
        with mock.patch.dict(opread.sys.modules, modules), \
             mock.patch.object(opread.signal, "signal"), \
             mock.patch.object(opread.subprocess, "Popen") as popen:
            yield types.SimpleNamespace(window=window, gtk=gtk, gdk=gdk, glib=glib,
                                        wayland=wayland, surface=surface, handlers=handlers,
                                        timers=timers, popen=popen)

    def test_gui_keeps_transparent_labeled_identity_window_resizable(self):
        with self.fake_gui() as gui:
            self.assertEqual(opread.gui("op://Private/fooo/field", "fooo/field: Fastmail", "/op"), 1)
        gui.gtk.Window.assert_called_once_with(title="fooo/field: Fastmail")
        gui.glib.set_prgname.assert_called_once_with("fooo/field: Fastmail")
        gui.gdk.set_program_class.assert_called_once_with("fooo/field: Fastmail")
        gui.wayland.WaylandWindow.set_application_id.assert_called_once_with(
            gui.surface, "fooo/field: Fastmail")
        gui.gtk.Widget.set_opacity.assert_called_once_with(gui.window, 0.0)
        gui.gtk.Label.assert_called_once_with(label="opread 1Password CLI request window")
        gui.window.add.assert_called_once_with(gui.gtk.Label.return_value)
        # Disabling resizing was observed to lose the request identity.
        self.assertNotIn(mock.call(False), gui.window.set_resizable.call_args_list)
        gui.window.set_default_size.assert_called_once_with(1, 1)
        gui.window.set_size_request.assert_called_once_with(1, 1)
        gui.popen.assert_not_called()

    def test_gui_closes_window_while_polling_until_child_status(self):
        for returncode, expected in ((7, 7), (-15, 143)):
            with self.subTest(returncode=returncode), self.fake_gui() as gui:
                proc = gui.popen.return_value
                proc.poll.side_effect = [None, None, returncode]

                def main_loop():
                    # Repeated map notifications must not schedule another spawn.
                    gui.handlers["map"](gui.window)
                    self.assertEqual(len(gui.timers), 1)
                    delay, spawn = gui.timers[1]
                    self.assertEqual(delay, 300)
                    gui.popen.assert_not_called()
                    self.assertIs(spawn(), gui.glib.SOURCE_REMOVE)
                    self.assertIs(spawn(), gui.glib.SOURCE_REMOVE)
                    gui.popen.assert_called_once_with(["/validated/bin/op", "read", "op://Private/fooo/field"])
                    self.assertEqual(len(gui.timers), 3)
                    close_delay, close_window = gui.timers[2]
                    poll_delay, poll_op = gui.timers[3]
                    self.assertEqual((close_delay, poll_delay), (300, 50))
                    self.assertIs(poll_op(), gui.glib.SOURCE_CONTINUE)
                    self.assertIs(close_window(), gui.glib.SOURCE_REMOVE)
                    gui.window.destroy.assert_called_once_with()
                    proc.terminate.assert_not_called()
                    proc.wait.assert_not_called()
                    gui.gtk.main_quit.assert_not_called()
                    # The op child can remain alive after its window disappears.
                    self.assertIs(poll_op(), gui.glib.SOURCE_CONTINUE)
                    gui.gtk.main_quit.assert_not_called()
                    self.assertIs(poll_op(), gui.glib.SOURCE_REMOVE)
                    gui.gtk.main_quit.assert_called_once_with()

                gui.gtk.main.side_effect = main_loop
                self.assertEqual(opread.gui("op://Private/fooo/field", "fooo/field: Fastmail",
                                           "/validated/bin/op"), expected)

    def test_gui_spawn_failure_reports_status_without_polling(self):
        with self.fake_gui() as gui, contextlib.redirect_stderr(io.StringIO()) as errors:
            gui.popen.side_effect = OSError("cannot execute")

            def main_loop():
                self.assertIs(gui.timers[1][1](), gui.glib.SOURCE_REMOVE)
                self.assertEqual(len(gui.timers), 1)
                gui.gtk.main_quit.assert_called_once_with()

            gui.gtk.main.side_effect = main_loop
            self.assertEqual(opread.gui("op://Private/fooo/field", "fooo/field", "/op"), 127)
        self.assertIn("cannot start op: cannot execute", errors.getvalue())

    def test_optional_reason_reaches_child_with_item_path(self):
        child = Child(0)
        with mock.patch.object(opread.sys, "argv", ["opread", "op://Private/fooo/API_TOKEN_READ_ONLY"]), \
             mock.patch.object(opread.subprocess, "Popen", return_value=child) as popen, \
             mock.patch.object(opread, "terminate_process_group"):
            self.assertEqual(opread.main(), 0)
        argv = popen.call_args.args[0]
        self.assertEqual(os.path.basename(argv[0]), "fooo_API_TOKEN_READ_ONLY")
        self.assertEqual(argv[-4:], ["--gui-child", "op://Private/fooo/API_TOKEN_READ_ONLY",
                                     "fooo/API_TOKEN_READ_ONLY", "/validated/bin/op"])

    def test_sigterm_after_interpreter_copy_cleans_tempdir_before_spawn(self):
        with tempfile.TemporaryDirectory() as parent:
            path = os.path.join(parent, "private")
            real_copyfile = opread.shutil.copyfile

            def make_tempdir(**_kwargs):
                os.mkdir(path, 0o700)
                return path

            def copy_then_signal(source, destination):
                result = real_copyfile(source, destination)
                os.kill(os.getpid(), opread.signal.SIGTERM)
                return result

            with mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
                 mock.patch.object(opread.tempfile, "mkdtemp", side_effect=make_tempdir), \
                 mock.patch.object(opread.shutil, "copyfile", side_effect=copy_then_signal), \
                 mock.patch.object(opread.subprocess, "Popen") as popen:
                self.assertEqual(opread.main(), 143)
            popen.assert_not_called()
            self.assertFalse(os.path.exists(path))

    def test_sigterm_immediately_after_mkdtemp_removes_empty_private_dir(self):
        with tempfile.TemporaryDirectory() as parent:
            path = os.path.join(parent, "private")

            def make_tempdir(**_kwargs):
                os.mkdir(path, 0o700)
                os.kill(os.getpid(), opread.signal.SIGTERM)
                return path

            with mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
                 mock.patch.object(opread.tempfile, "mkdtemp", side_effect=make_tempdir), \
                 mock.patch.object(opread.subprocess, "Popen") as popen:
                self.assertEqual(opread.main(), 143)
            popen.assert_not_called()
            self.assertFalse(os.path.exists(path))

    def test_sigterm_during_popen_publication_cleans_published_child(self):
        with tempfile.TemporaryDirectory() as parent:
            path = os.path.join(parent, "private")
            child = Child(0)

            def make_tempdir(**_kwargs):
                os.mkdir(path, 0o700)
                return path

            def publish_then_signal(*_args, **_kwargs):
                os.kill(os.getpid(), opread.signal.SIGTERM)
                return child

            with mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
                 mock.patch.object(opread.tempfile, "mkdtemp", side_effect=make_tempdir), \
                 mock.patch.object(opread.subprocess, "Popen", side_effect=publish_then_signal), \
                 mock.patch.object(opread, "terminate_process_group") as cleanup:
                self.assertEqual(opread.main(), 143)
            cleanup.assert_called_once_with(child, deadline=mock.ANY)
            self.assertFalse(os.path.exists(path))

    @unittest.skipUnless(os.name == "posix" and Path("/proc").exists(), "requires Linux process groups")
    def test_group_cleanup_kills_descendant_after_group_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "descendant.pid"
            descendant = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
            leader_code = (
                "import subprocess,sys,time; "
                f"p=subprocess.Popen([sys.executable,'-c',{descendant!r}]); "
                f"open({str(pidfile)!r},'w').write(str(p.pid)); time.sleep(.1)"
            )
            leader = __import__("subprocess").Popen(
                [opread.sys.executable, "-c", leader_code], start_new_session=True,
                stdin=__import__("subprocess").DEVNULL,
                stdout=__import__("subprocess").DEVNULL,
                stderr=__import__("subprocess").DEVNULL,
            )
            self.assertEqual(leader.wait(timeout=3), 0)
            descendant_pid = int(pidfile.read_text())
            opread.terminate_process_group(leader)
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                try:
                    state = Path(f"/proc/{descendant_pid}/stat").read_text().split()[2]
                except FileNotFoundError:
                    break
                if state in ("Z", "X"):
                    break
                time.sleep(0.02)
            else:
                self.fail("SIGTERM-resistant descendant survived process-group cleanup")

    def test_cli_output_write_and_flush_failures(self):
        for where, error, expected in (("write", BrokenPipeError(), 141),
                                        ("flush", BrokenPipeError(), 141),
                                        ("write", OSError(), 1), ("flush", OSError(), 1)):
            stream = mock.Mock()
            getattr(stream.buffer, where).side_effect = error
            with self.subTest(where=where, expected=expected), \
                 mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item"]), \
                 mock.patch.object(opread.sys, "stdout", stream), \
                 mock.patch.object(opread, "neutralize_stdout") as neutralize, \
                 mock.patch.object(opread, "_cli_read", return_value=b"data"), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(opread.main(), expected)
            neutralize.assert_called_once()
            self.assertEqual(errors.getvalue(), "opread: cannot write output\n" if expected == 1 else "")

    def test_cli_real_broken_pipe_has_no_shutdown_override(self):
        import subprocess
        for size in (1, 200000):
            code = ("import sys; from lib import opread; "
                    f"opread._cli_read=lambda *a,**k: b'x'*{size}; "
                    "sys.argv=['opread','op://vault/item']; "
                    "raise SystemExit(opread.main())")
            with self.subTest(size=size):
                proc = subprocess.Popen([sys.executable, "-c", code], cwd=SCRIPT.parent,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.stdout.close()
                proc.stdout = None
                try:
                    _, errors = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.fail("broken-pipe fixture exceeded deadline")
                self.assertEqual(proc.returncode, 141)
                self.assertNotIn(b"Traceback", errors)
                self.assertNotIn(b"Exception ignored", errors)
                proc.stderr.close()

    def test_real_child_drains_phased_output_and_inherits_stderr(self):
        import subprocess
        for status in (0, 7):
            child_code = ("import os,time; "
                          "os.write(2,b'child diagnostic\\n'); "
                          "[(os.write(1,bytes([65+i])*100000),time.sleep(.16)) for i in range(3)]; "
                          f"raise SystemExit({status})")
            harness = ("import subprocess,sys; from unittest import mock; from lib import opread; "
                       "real=subprocess.Popen; "
                       f"code={child_code!r}; "
                       "spawn=lambda *a,**k: real([sys.executable,'-c',code],stdout=subprocess.PIPE,start_new_session=True); "
                       "opread.resolve_op=lambda *a,**k: ('/fake/op','1'); "
                       "p=mock.patch.object(opread.subprocess,'Popen',side_effect=spawn); p.start(); "
                       "\ntry:\n data=opread.read('op://vault/item'); sys.stdout.buffer.write(data)\n"
                       "except opread.OpreadError as e:\n sys.exit(e.returncode)\n")
            with self.subTest(status=status):
                result = subprocess.run([sys.executable, "-c", harness], cwd=SCRIPT.parent,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, b"" if status else
                                 b"A" * 100000 + b"B" * 100000 + b"C" * 100000)
                self.assertEqual(result.stderr, b"child diagnostic\n")

    @unittest.skipUnless(os.name == "posix", "requires process groups")
    def test_real_pipe_holder_is_cleaned_or_bounded(self):
        import subprocess
        for escaped, exitcode in ((False, 0), (True, 0), (True, 7)):
            with self.subTest(escaped=escaped, exitcode=exitcode), tempfile.TemporaryDirectory() as directory:
                pidfile = Path(directory) / "holder.pid"
                leaderfile = Path(directory) / "leader.pid"
                holder = f"import os,time; open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(30)"
                leader = ("import os,subprocess,sys,time; "
                          f"p=subprocess.Popen([sys.executable,'-c',{holder!r}], start_new_session={escaped!r}, stderr=subprocess.DEVNULL); "
                          f"path={str(pidfile)!r}; "
                          "\nwhile not os.path.exists(path): time.sleep(.01)\n"
                          f"os.write(1,b'credential'); sys.exit({exitcode})")
                harness = ("import subprocess,sys; from unittest import mock; from lib import opread; "
                           "real=subprocess.Popen; "
                           f"code={leader!r}; path={str(leaderfile)!r}; "
                           "\ndef spawn(*a,**k):\n p=real([sys.executable,'-c',code],stdout=subprocess.PIPE,start_new_session=True); open(path,'w').write(str(p.pid)); return p\n"
                           "opread.resolve_op=lambda *a,**k: ('/fake/op','1')\n"
                           "with mock.patch.object(opread.subprocess,'Popen',side_effect=spawn):\n"
                           " try: sys.stdout.buffer.write(opread.read('op://vault/item'))\n"
                           " except opread.OpreadError as e: sys.exit(e.returncode)\n")
                proc = subprocess.Popen([sys.executable, "-c", harness], cwd=SCRIPT.parent,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                started = time.monotonic()
                try:
                    try:
                        output, errors = proc.communicate(timeout=6)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        self.fail("pipe-holder fixture exceeded deadline")
                    self.assertLess(time.monotonic() - started, 6)
                    self.assertEqual(proc.returncode, 69 if escaped and exitcode == 0 else exitcode)
                    self.assertEqual(output, b"" if escaped else b"credential")
                    self.assertEqual(bool(errors), escaped and exitcode == 0)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    for path, group in ((leaderfile, True), (pidfile, False)):
                        if path.exists():
                            try:
                                (os.killpg if group else os.kill)(int(path.read_text()), opread.signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    proc.communicate(timeout=2)

    def test_worker_reads_concurrently_with_isolated_replacement_environments(self):
        from concurrent.futures import ThreadPoolExecutor
        import subprocess
        self.op_resolver.stop()
        self.addCleanup(self.op_resolver.start)
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_fake_op(directory)
            original = dict(os.environ)
            envs = [{"PATH": directory, "OP_ACCOUNT": account, "OP_CONFIG_DIR": account,
                     "PYTHONPATH": "must-be-removed"} for account in ("one", "two")]
            saved = [dict(env) for env in envs]
            real_popen = subprocess.Popen
            code = ("import os,sys; os.write(2,b'worker diagnostic\\n'); "
                    "os.write(1,(os.environ['OP_ACCOUNT']+':'+os.environ['OP_CONFIG_DIR']).encode()); "
                    "sys.exit(7 if os.environ['OP_ACCOUNT']=='two' else 0)")
            def spawn(args, **kwargs):
                if args[0] == str(executable.resolve()):
                    return real_popen(args, **kwargs)
                self.assertNotIn("PYTHONPATH", kwargs["env"])
                self.assertEqual(kwargs["env"]["OP_BIOMETRIC_UNLOCK_ENABLED"], "true")
                return real_popen([sys.executable, "-c", code], **kwargs)
            def worker(env):
                try:
                    return opread.read("op://vault/item", env=env)
                except opread.OpreadError as exc:
                    return exc.returncode
            handlers = {sig: opread.signal.getsignal(sig) for sig in
                        (opread.signal.SIGINT, opread.signal.SIGTERM, opread.signal.SIGHUP)}
            with mock.patch.object(opread.subprocess, "Popen", side_effect=spawn), \
                 mock.patch.object(opread.signal, "signal", side_effect=AssertionError("signal handler changed")):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(worker, envs))
            self.assertEqual(results, [b"one:one", 7])
            self.assertEqual(envs, saved)
            self.assertEqual(dict(os.environ), original)
            self.assertEqual(handlers, {sig: opread.signal.getsignal(sig) for sig in handlers})

    def test_resolver_and_backend_use_replacement_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_fake_op(directory)
            with mock.patch.dict(os.environ, {"PATH": "/nonexistent", "OP_CONNECT_TOKEN": "ignored"}), \
                 mock.patch.object(opread.subprocess, "Popen", wraps=opread.subprocess.Popen) as run:
                self.assertEqual(REAL_RESOLVE_OP({"PATH": directory, "OP_ACCOUNT": "isolated"})[0], str(executable))
            for call in run.call_args_list:
                self.assertEqual(call.kwargs["env"]["OP_ACCOUNT"], "isolated")
                self.assertNotIn("OP_CONNECT_TOKEN", call.kwargs["env"])
            with mock.patch.object(opread.shutil, "which", return_value=None) as which:
                with self.assertRaises(RuntimeError):
                    REAL_RESOLVE_OP({})
                which.assert_called_once_with("op", path=os.defpath)
            with mock.patch.object(opread, "resolve_op", side_effect=RuntimeError("reached resolver")), \
                 mock.patch.dict(os.environ, {"OP_CONNECT_TOKEN": "ignored"}), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(opread.OpreadError) as caught:
                    opread.read("op://vault/item", env={})
                self.assertEqual(caught.exception.returncode, 69)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(opread.OpreadError) as caught:
                    opread.read("op://vault/item", env={"OP_CONNECT_TOKEN": "rejected"})
                self.assertEqual(caught.exception.returncode, 2)

    def test_cli_restores_handlers_for_all_interrupt_signals(self):
        for sig, status in ((opread.signal.SIGINT, 130), (opread.signal.SIGTERM, 143),
                            (opread.signal.SIGHUP, 129)):
            before = {s: opread.signal.getsignal(s) for s in
                      (opread.signal.SIGINT, opread.signal.SIGTERM, opread.signal.SIGHUP)}
            def interrupt(*args, **kwargs):
                os.kill(os.getpid(), sig)
                return ("/validated/bin/op", "1")
            with self.subTest(sig=sig), mock.patch.object(opread, "resolve_op", side_effect=interrupt):
                with self.assertRaises(opread.OpreadError) as caught:
                    opread._cli_read("op://vault/item")
                self.assertEqual(caught.exception.returncode, status)
                self.assertEqual(before, {s: opread.signal.getsignal(s) for s in before})

    def test_backend_conflict_is_reported_without_echoing_value(self):
        with mock.patch.dict(opread.os.environ, {"OP_CONNECT_TOKEN": "secret-token"}, clear=False), \
             mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
             mock.patch.object(opread.tempfile, "mkdtemp") as mkdtemp, \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(opread.main(), 2)
        self.assertIn("non-interactive", errors.getvalue())
        self.assertNotIn("secret-token", errors.getvalue())
        mkdtemp.assert_not_called()

    def test_manual_session_token_is_rejected_without_echoing_value(self):
        with mock.patch.dict(opread.os.environ, {"OP_SESSION_WORK": "secret-token"}, clear=False), \
             mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item", "Finance"]), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(opread.main(), 2)
        self.assertNotIn("secret-token", errors.getvalue())

    def fake_payload(self, payload, status=0):
        child = Child(status)
        child.communicate = mock.Mock(return_value=(payload, b"secret diagnostic"))
        child.stderr = io.BytesIO()
        return child

    def test_whole_item_parses_once_returns_same_dict_and_preserves_selection_and_label(self):
        data = b' {"id":"abc","fields":[{"value":"secret"}]}\n\n'
        child = self.fake_payload(data)
        env = {"OP_ACCOUNT": "ambient-account", "PATH": "/fake"}
        parsed = []
        real_loads = opread.json.loads
        def parse(*args, **kwargs):
            value = real_loads(*args, **kwargs)
            parsed.append(value)
            return value
        with mock.patch.object(opread.subprocess, "Popen", return_value=child) as spawn, \
             mock.patch.object(opread, "terminate_process_group"), \
             mock.patch.object(opread.json, "loads", side_effect=parse) as loads:
            result = opread.get_item("item name", "backup", vault="private-vault",
                                     account="chosen-account", env=env)
        loads.assert_called_once_with(data.decode("utf-8"), parse_constant=mock.ANY)
        self.assertIs(result, parsed[0])
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {"id": "abc", "fields": [{"value": "secret"}]})
        args = spawn.call_args.args[0]
        self.assertEqual(args[2:], ["--gui-item-child", "item name", "WHOLE ITEM: item name: backup",
                                    "/validated/bin/op", "private-vault", "chosen-account"])
        self.assertTrue(os.path.basename(args[0]).startswith("WHOLE_ITEM_"))
        self.assertNotIn("private-vault", args[4])
        self.assertNotIn("chosen-account", args[4])
        self.assertEqual(spawn.call_args.kwargs["stderr"], opread.subprocess.PIPE)
        self.assertEqual(spawn.call_args.kwargs["env"]["OP_ACCOUNT"], "chosen-account")
        self.assertEqual(env["OP_ACCOUNT"], "ambient-account")
        self.assertTrue(child.stderr.closed)

    def test_whole_item_gui_uses_fixed_command_and_optional_account(self):
        for account in (None, "chosen"):
            with self.subTest(account=account), self.fake_gui() as gui:
                gui.gtk.main.side_effect = lambda: gui.timers[1][1]()
                opread.gui("item name", "WHOLE ITEM: item name", "/op", vault="vault", account=account)
                expected = ["/op", "item", "get", "item name", "--vault", "vault", "--format", "json"]
                if account is not None:
                    expected += ["--account", account]
                gui.popen.assert_called_once_with(expected)

    def test_whole_item_rejects_unsafe_selectors_before_probe(self):
        for value in (None, "", "--format=json", "line\nbreak", "x\0y", "x\x85y", "é" * 2049):
            for field in ("item", "vault", "account"):
                if field == "account" and value is None:
                    continue
                values = dict(item="item", vault="vault", account="account")
                values[field] = value
                with self.subTest(field=field, value=str(value)[:30]), \
                     mock.patch.object(opread, "resolve_op") as resolve, \
                     contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(opread.OpreadError) as error:
                        opread.get_item(**values)
                    self.assertEqual(error.exception.returncode, 2)
                    resolve.assert_not_called()

    def test_whole_item_strict_json_and_all_failures_sanitized(self):
        invalid = (b"secret", b"\xffsecret", b'["secret"]', b'"secret"', b"null",
                   b'{"secret":NaN}', b'{"secret":Infinity}', b'{"secret":-Infinity}',
                   b'{"secret":1} trailing', b'\xef\xbb\xbf{"secret":1}', b"")
        for payload, status in [(data, 0) for data in invalid] + [(b'{"secret":1}', 7)]:
            child = self.fake_payload(payload, status)
            with self.subTest(payload=payload), \
                 mock.patch.object(opread.subprocess, "Popen", return_value=child), \
                 mock.patch.object(opread, "terminate_process_group"), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(opread.OpreadError) as error:
                    opread.get_item("item", vault="vault")
            self.assertEqual(error.exception.returncode, status or 69)
            self.assertNotIn("secret", str(error.exception))
            self.assertNotIn("secret", errors.getvalue())
            self.assertIsNone(error.exception.__cause__)
            self.assertIsNone(error.exception.__context__)
        for operation in ("resolve_op", "select_python_runtime"):
            with self.subTest(operation=operation), \
                 mock.patch.object(opread, operation, side_effect=RuntimeError("secret")), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(opread.OpreadError) as error:
                    opread.get_item("item", vault="vault")
            self.assertEqual(error.exception.returncode, 69)
            self.assertNotIn("secret", errors.getvalue())
        for exception in (OSError("secret"), ValueError("secret"),
                          opread.subprocess.SubprocessError("secret")):
            with mock.patch.object(opread.subprocess, "Popen", side_effect=exception), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(opread.OpreadError) as error:
                    opread.get_item("item", vault="vault")
            self.assertEqual(error.exception.returncode, 69)
            self.assertNotIn("secret", errors.getvalue())

    def test_timeout_validation_and_immediate_control_before_acquisition(self):
        import threading
        for value in (-1, float("nan"), float("inf"), "1", True):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                opread.read("op://vault/item", timeout=value)
        cancelled = threading.Event()
        cancelled.set()
        for kwargs, kind, status in (({"timeout": 0}, opread.OpreadTimeoutError, 124),
                                     ({"cancel": cancelled}, opread.OpreadCancelledError, 130),
                                     ({"timeout": 0, "cancel": cancelled}, opread.OpreadCancelledError, 130)):
            with self.subTest(kwargs=kwargs), mock.patch.object(opread, "resolve_op") as resolve:
                with self.assertRaises(kind) as error:
                    opread.read("op://vault/item", **kwargs)
                self.assertEqual(error.exception.returncode, status)
                resolve.assert_not_called()

    def test_cancel_and_deadline_cover_setup_and_publication_races(self):
        import threading
        for phase in ("resolve", "mkdtemp", "copy", "spawn"):
            for timed in (False, True):
                cancel = threading.Event()
                clock = [10.0]
                paths = []
                child = Child(0)
                real_mkdtemp, real_copy = opread.tempfile.mkdtemp, opread.shutil.copyfile
                def trigger():
                    if timed:
                        clock[0] = 12.0
                    else:
                        cancel.set()
                def resolve(*a, **k):
                    if phase == "resolve": trigger()
                    return ("/fake/op", "1")
                def make(**k):
                    result = real_mkdtemp(**k)
                    paths.append(result)
                    if phase == "mkdtemp": trigger()
                    return result
                def copy(*a):
                    result = real_copy(*a)
                    if phase == "copy": trigger()
                    return result
                def spawn(*a, **k):
                    trigger()
                    return child
                with self.subTest(phase=phase, timed=timed), \
                     mock.patch.object(opread.time, "monotonic", side_effect=lambda: clock[0]), \
                     mock.patch.object(opread, "resolve_op", side_effect=resolve), \
                     mock.patch.object(opread.tempfile, "mkdtemp", side_effect=make), \
                     mock.patch.object(opread.shutil, "copyfile", side_effect=copy), \
                     mock.patch.object(opread.subprocess, "Popen", side_effect=spawn) as popen, \
                     mock.patch.object(opread, "terminate_process_group") as cleanup:
                    kind = opread.OpreadTimeoutError if timed else opread.OpreadCancelledError
                    with self.assertRaises(kind):
                        opread.read("op://vault/item", timeout=1 if timed else None, cancel=cancel)
                self.assertTrue(all(not os.path.exists(path) for path in paths))
                if phase == "spawn":
                    cleanup.assert_called_once_with(child, deadline=mock.ANY)
                    self.assertTrue(child.stdout.closed)
                else:
                    popen.assert_not_called()

    def test_control_rechecked_after_item_parsing_and_cleanup(self):
        import threading
        for phase in ("parse", "cleanup"):
            for timed in (False, True):
                event = threading.Event()
                clock = [20.0]
                child = self.fake_payload(b'{"id":"item"}')
                def trigger(*a, **k):
                    if timed: clock[0] = 22.0
                    else: event.set()
                with self.subTest(phase=phase, timed=timed), \
                     mock.patch.object(opread.time, "monotonic", side_effect=lambda: clock[0]), \
                     mock.patch.object(opread.subprocess, "Popen", return_value=child), \
                     mock.patch.object(opread, "terminate_process_group", side_effect=trigger if phase == "cleanup" else None), \
                     mock.patch.object(opread, "_parse_item_json", side_effect=trigger if phase == "parse" else None):
                    kind = opread.OpreadTimeoutError if timed else opread.OpreadCancelledError
                    with self.assertRaises(kind):
                        opread.get_item("item", vault="vault", timeout=1 if timed else None, cancel=event)

    def test_cli_signal_during_failed_child_cleanup_overrides_failure(self):
        signals = (opread.signal.SIGINT, opread.signal.SIGTERM, opread.signal.SIGHUP)
        for sig, status in zip(signals, (130, 143, 129)):
            before = {value: opread.signal.getsignal(value) for value in signals}
            def interrupt(*args, **kwargs):
                os.kill(os.getpid(), sig)
            child = self.fake_payload(b"failed credential", 7)
            with self.subTest(signal=sig), \
                 mock.patch.object(opread.sys, "argv", ["opread", "op://vault/item"]), \
                 mock.patch.object(opread.subprocess, "Popen", return_value=child), \
                 mock.patch.object(opread, "terminate_process_group", side_effect=interrupt), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(opread.main(), status)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(before, {value: opread.signal.getsignal(value) for value in signals})

    def test_original_failure_preserved_when_cancel_arrives_during_cleanup(self):
        import threading
        event = threading.Event()
        with mock.patch.object(opread.subprocess, "Popen", return_value=self.fake_payload(b"secret", 7)), \
             mock.patch.object(opread, "terminate_process_group", side_effect=lambda *a, **k: event.set()):
            with self.assertRaises(opread.OpreadError) as error:
                opread.get_item("item", vault="vault", cancel=event)
        self.assertEqual(error.exception.returncode, 7)

    def test_shared_cleanup_allowance_and_close_abandoned_pipes(self):
        clock = [0.0]
        context = opread._ReadContext()
        children = [self.fake_payload(b"secret") for _ in range(3)]
        deadlines = []
        def cleanup(child, *, deadline):
            deadlines.append(deadline)
            clock[0] += min(3.0, max(0, deadline - clock[0]))
        with mock.patch.object(opread.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(opread, "terminate_process_group", side_effect=cleanup):
            context.children.extend(children)
            context.close()
        self.assertEqual(clock[0], 5.0)
        self.assertEqual(deadlines, [5.0, 5.0, 5.0])
        self.assertEqual(context.cleanup_remaining, 0)
        self.assertTrue(all(child.stdout.closed and child.stderr.closed for child in children))

    def test_field_setup_and_runtime_diagnostics_preserve_existing_text(self):
        cases = ((opread.tempfile, "mkdtemp", OSError("private setup failure"),
                  "cannot prepare opread prompt: private setup failure\n"),
                 (opread.shutil, "copyfile", OSError("private copy failure"),
                  "cannot prepare opread prompt: private copy failure\n"),
                 (opread.subprocess, "Popen", OSError("private spawn failure"),
                  "cannot prepare opread prompt: private spawn failure\n"),
                 (opread, "select_python_runtime", RuntimeError("private runtime failure"),
                  "private runtime failure\n"))
        for owner, operation, exception, expected in cases:
            for item in (False, True):
                with self.subTest(operation=operation, item=item), \
                     mock.patch.object(owner, operation, side_effect=exception), \
                     contextlib.redirect_stderr(io.StringIO()) as errors:
                    with self.assertRaises(opread.OpreadError) as error:
                        if item:
                            opread.get_item("item", vault="vault")
                        else:
                            opread.read("op://vault/item")
                self.assertEqual(error.exception.returncode, 69)
                self.assertEqual(errors.getvalue(), "opread: item read failed\n" if item else expected)

    def test_cleanup_exception_is_sanitized_and_cannot_return_payload(self):
        with mock.patch.object(opread.subprocess, "Popen", return_value=self.fake_payload(b'{"secret":1}')), \
             mock.patch.object(opread, "terminate_process_group", side_effect=RuntimeError("secret")), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(opread.OpreadError) as error:
                opread.get_item("item", vault="vault")
        self.assertEqual(error.exception.returncode, 69)
        self.assertNotIn("secret", errors.getvalue())

    def run_real_read(self, code, *, item=False, **controls):
        import subprocess
        real = subprocess.Popen
        def spawn(args, **kwargs):
            return real([sys.executable, "-S", "-c", code], **kwargs)
        with mock.patch.object(opread.subprocess, "Popen", side_effect=spawn):
            if item:
                return opread.get_item("item", vault="vault", **controls)
            return opread.read("op://vault/item", **controls)

    def test_real_item_stderr_saturation_drains_and_is_suppressed(self):
        for status in (0, 7):
            code = ("import os; "
                    "[(os.write(2,b'secret'*20000),os.write(1,b' ')) for _ in range(10)]; "
                    "os.write(1,b'{\"id\":\"value\"}'); "
                    f"raise SystemExit({status})")
            with self.subTest(status=status), contextlib.redirect_stderr(io.StringIO()) as errors:
                if status:
                    with self.assertRaises(opread.OpreadError) as error:
                        self.run_real_read(code, item=True, timeout=3)
                    self.assertEqual(error.exception.returncode, 7)
                else:
                    self.assertEqual(self.run_real_read(code, item=True, timeout=3), {"id": "value"})
            self.assertEqual(errors.getvalue(), "")

    def test_real_running_read_timeout_and_cancel_suppress_partial_payload(self):
        import threading
        for timed in (False, True):
            event = threading.Event()
            timer = None
            if not timed:
                timer = threading.Timer(.15, event.set)
                timer.start()
            started = time.monotonic()
            try:
                kind = opread.OpreadTimeoutError if timed else opread.OpreadCancelledError
                with self.assertRaises(kind):
                    self.run_real_read("import os,time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                                       "os.write(1,b'partial secret'); time.sleep(30)",
                                       timeout=.15 if timed else None, cancel=event)
                self.assertLess(time.monotonic() - started, 2)
            finally:
                if timer: timer.join()

    def test_real_probes_cancel_timeout_and_publication_cleanup(self):
        import threading
        import subprocess
        self.op_resolver.stop()
        self.addCleanup(self.op_resolver.start)
        for timed in (False, True):
            for option in ("--version", "--help"):
                with self.subTest(timed=timed, option=option), tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory) / "op"
                    fake.write_text(f"#!{sys.executable} -S\nimport sys,time,signal\n"
                                    "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                                    f"if sys.argv[1]=={option!r}: time.sleep(30)\n"
                                    "print('2.41.1' if sys.argv[1]=='--version' else '1Password CLI brings 1Password to your terminal.')\n")
                    fake.chmod(0o700)
                    event = threading.Event()
                    timer = threading.Timer(.25, event.set)
                    if not timed: timer.start()
                    children = []
                    real = subprocess.Popen
                    def spawn(*args, **kwargs):
                        child = real(*args, **kwargs)
                        children.append(child)
                        return child
                    try:
                        started = time.monotonic()
                        with mock.patch.object(opread.subprocess, "Popen", side_effect=spawn):
                            kind = opread.OpreadTimeoutError if timed else opread.OpreadCancelledError
                            with self.assertRaises(kind):
                                opread.read("op://vault/item", env={"PATH": directory},
                                            timeout=.25 if timed else None, cancel=event)
                        self.assertLess(time.monotonic() - started, 2)
                        self.assertEqual(len(children), 1 if option == "--version" else 2)
                        self.assertTrue(all(child.poll() is not None for child in children))
                        self.assertTrue(all(child.stdout.closed and child.stderr.closed for child in children))
                    finally:
                        if not timed: timer.join()

    def test_probe_budget_is_three_seconds_and_capped_by_total_deadline(self):
        for total, expected in ((None, 3.0), (1.0, 1.0)):
            clock = [0.0]
            context = opread._ReadContext(timeout=total)
            context.deadline = None if total is None else total
            child = Child(None)
            def communicate(timeout):
                clock[0] += timeout
                raise opread.subprocess.TimeoutExpired("probe", timeout)
            child.communicate = communicate
            with mock.patch.object(opread.time, "monotonic", side_effect=lambda: clock[0]):
                with self.assertRaises(opread._ProbeTimeout if total is None else opread.OpreadTimeoutError):
                    context.collect(child, 3.0)
            self.assertAlmostEqual(clock[0], expected)

    def test_threaded_cancel_isolation_for_whole_items(self):
        from concurrent.futures import ThreadPoolExecutor
        import subprocess
        import threading
        first, second = threading.Event(), threading.Event()
        first.set()
        real = subprocess.Popen
        environments = [{"OP_ACCOUNT": name} for name in ("one", "two")]
        original = dict(os.environ)
        def spawn(args, **kwargs):
            return real([sys.executable, "-c", "import os,json; print(json.dumps({'account':os.environ['OP_ACCOUNT']}))"], **kwargs)
        def worker(pair):
            env, event = pair
            try:
                return opread.get_item("item", vault="vault", env=env, cancel=event)
            except opread.OpreadError as error:
                return error.returncode
        with mock.patch.object(opread.subprocess, "Popen", side_effect=spawn), \
             mock.patch.object(opread.signal, "signal", side_effect=AssertionError("global handler mutation")):
            with ThreadPoolExecutor(2) as pool:
                results = list(pool.map(worker, zip(environments, (first, second))))
        self.assertEqual(results, [130, {"account": "two"}])
        self.assertEqual(environments, [{"OP_ACCOUNT": "one"}, {"OP_ACCOUNT": "two"}])
        self.assertEqual(dict(os.environ), original)


    def test_probe_spawn_publication_cancellation_reaps_acquired_process(self):
        import subprocess
        import threading
        self.op_resolver.stop()
        self.addCleanup(self.op_resolver.start)
        with tempfile.TemporaryDirectory() as directory:
            self.make_fake_op(directory)
            event = threading.Event()
            children = []
            real = subprocess.Popen
            def spawn(*args, **kwargs):
                child = real(*args, **kwargs)
                children.append(child)
                event.set()
                return child
            with mock.patch.object(opread.subprocess, "Popen", side_effect=spawn):
                with self.assertRaises(opread.OpreadCancelledError):
                    opread.read("op://vault/item", env={"PATH": directory}, cancel=event)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)

    def test_real_cancel_kills_ready_term_resistant_descendant(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "ready"
            descendant = ("import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                          f"open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(30)")
            leader = ("import subprocess,sys,time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                      f"subprocess.Popen([sys.executable,'-S','-c',{descendant!r}]); time.sleep(30)")
            event, finished = threading.Event(), threading.Event()
            def cancel_when_ready():
                deadline = time.monotonic() + 3
                while not finished.wait(.01) and time.monotonic() < deadline:
                    if pidfile.exists():
                        event.set()
                        return
                event.set()
            watcher = threading.Thread(target=cancel_when_ready)
            watcher.start()
            try:
                with self.assertRaises(opread.OpreadCancelledError):
                    self.run_real_read(leader, cancel=event)
                self.assertTrue(pidfile.exists(), "descendant never published readiness")
                pid = int(pidfile.read_text())
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    try:
                        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
                    except FileNotFoundError:
                        break
                    if state in ("Z", "X"):
                        break
                    time.sleep(.01)
                else:
                    self.fail("ready TERM-resistant descendant survived cleanup")
            finally:
                finished.set()
                watcher.join()
                if pidfile.exists():
                    try: os.kill(int(pidfile.read_text()), opread.signal.SIGKILL)
                    except ProcessLookupError: pass


if __name__ == "__main__":
    unittest.main()
