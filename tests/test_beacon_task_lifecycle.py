"""P0: a task timeout must be a REAL timeout, and must not corrupt the beacon.

Manus's sharpest finding was that the watchdog allocated the task state on
the stack, handed the worker a raw pointer, and called ``detach()`` when the
budget ran out. The detached worker then wrote into a stack frame that had
already returned — a use-after-free that could kill the implant mid-session.
The same code also "timed out" a command without ever stopping it: the child
process (and its grandchildren) kept running on the target with no watchdog.

These tests pin both halves:

* the C++ lifecycle is compiled and RUN (tests/test_beacon_task_lifecycle.cpp),
  which is the only way to prove a detached worker no longer touches freed
  memory — a source assertion cannot demonstrate the absence of a crash;
* the source invariants that a Windows-only runner cannot execute (the POSIX
  process-group branch, the shutdown drain) are asserted textually, and the
  CI Linux job compiles that branch for real.

Run the executable part only where a compiler exists; the rest always runs.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "phantom" / "payloads" / "beacon" / "src"
_MAIN = _SRC / "main.cpp"
_LIFECYCLE = _SRC / "task_lifecycle.h"
_CPP_TEST = _ROOT / "tests" / "test_beacon_task_lifecycle.cpp"


def _compiler():
    """A C++ compiler, or None. The lifecycle test is skipped, not failed,
    on a runner without a toolchain — the textual invariants still run."""
    for name in ("g++", "clang++", "cl"):
        found = shutil.which(name)
        if found:
            return found
    return None


class TestTheUafIsGone(unittest.TestCase):
    """The regression itself: no stack-allocated run state, no raw pointer
    handed to a worker that can outlive the frame."""

    def setUp(self):
        self.src = _MAIN.read_text(encoding="utf-8")

    def test_the_old_stack_taskrun_is_gone(self):
        # `TaskRun tr;` + `_task_worker(TaskRun* tr, ...)` was the exact shape
        # that made the detached write land in a dead frame.
        self.assertNotIn("TaskRun tr;", self.src)
        self.assertNotIn("struct TaskRun", self.src)
        self.assertNotIn("_task_worker", self.src)

    def test_the_run_is_shared_owned(self):
        header = _LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn("std::make_shared<task::Run>", self.src)
        # The registry holds the same strong references the worker does, so
        # the storage cannot die while either side still points at it.
        self.assertIn("std::vector<std::shared_ptr<Run>>", header)

    def test_a_late_worker_drops_its_result(self):
        # publish() must refuse after a cancel: that is what stops the
        # detached worker from writing at all.
        self.assertIn("bool publish(const std::string& out)", _LIFECYCLE
                      .read_text(encoding="utf-8"))
        self.assertIn("cancel_.load", _LIFECYCLE.read_text(encoding="utf-8"))

    def test_detaching_is_conditional_on_the_cap(self):
        # An unconditional detach() is the old bug with extra steps: the cap
        # check is what makes a wedged beacon stop spawning threads.
        self.assertIn("kMaxDetached", _LIFECYCLE.read_text(encoding="utf-8"))
        self.assertIn("Registry::instance().admit(run)", self.src)

    def test_shutdown_drains_stranded_workers(self):
        self.assertIn("task::Registry::instance().drain()", self.src)


class TestTheWatchdogNeverWaitsForABlockedWorker(unittest.TestCase):
    """F1/F2/F3: every defect here shows up only when the work is STUCK.

    The original suite used workers that always finish, so all three were
    invisible: a join() that waits for a blocked thread, a reference captured
    into a block-scoped vector, and a cap that a cancelled state erased.
    """

    def setUp(self):
        self.src = _MAIN.read_text(encoding="utf-8")
        start = self.src.index("static std::string run_task_with_timeout(")
        end = self.src.index("// \u2500\u2500 Command Dispatcher", start)
        self.fn = self.src[start:end]

    def test_the_timeout_path_detaches_and_never_joins(self):
        tail = self.fn[self.fn.index(
            "run->request_cancel(task::State::kTimedOut);"):]
        self.assertIn("worker.detach()", tail)
        self.assertNotIn(
            "worker.join()", tail,
            "join() waits for the THREAD, and this branch is only reached "
            "when the thread is blocked: it wedges the beacon for ever")

    def test_the_cap_is_checked_before_the_thread_is_spawned(self):
        self.assertLess(
            self.fn.index("kMaxDetached"), self.fn.index("std::thread worker("),
            "a cap checked after the spawn cannot prevent a spawn")

    def test_the_refusal_creates_no_thread_at_all(self):
        head = self.fn[:self.fn.index("std::thread worker(")]
        self.assertIn("TASK_REFUSED", head)

    def test_the_command_and_config_outlive_the_worker(self):
        self.assertIn("[cmd, cfg_owner]()", self.fn)
        self.assertNotIn("[&cmd", self.fn)
        self.assertNotIn("[&cfg", self.fn)
        self.assertIn("auto cfg_owner = std::make_shared<net::C2Config>();",
                      self.src)
        # every call site hands over the shared owner, never a bare reference
        self.assertNotIn("run_task_with_timeout(task.command, cfg,", self.src)
        self.assertNotIn("run_task_with_timeout(piped, cfg)", self.src)

    def test_the_worker_announces_its_own_exit_before_releasing(self):
        body = self.fn
        self.assertIn("run->mark_worker_exited();", body)
        self.assertLess(body.index("run->mark_worker_exited();"),
                        body.index("release(run.get())"))

    def test_the_cap_counts_threads_not_terminal_states(self):
        header = _LIFECYCLE.read_text(encoding="utf-8")
        reap = header[header.index("    void reap() {"):]
        reap = reap[:reap.index("\n    }")]
        self.assertIn("worker_exited()", reap)
        self.assertNotIn("finished()", reap)

    def test_shutdown_reports_the_workers_it_abandoned(self):
        header = _LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn("size_t drain()", header)
        self.assertIn("abandoned", header)
        self.assertIn("abandoned", self.src)


class TestOrphanPrevention(unittest.TestCase):
    """A timeout that leaves the command running is not a timeout."""

    def setUp(self):
        self.src = _MAIN.read_text(encoding="utf-8")

    def _fn(self):
        """The body of run_shell_command_bounded, so the branch split below is
        THIS function's and not the include block at the top of the file."""
        start = self.src.index("static std::string run_shell_command_bounded")
        end = self.src.index("std::string run_shell_command(const std::string&",
                             start)
        return self.src[start:end]

    def _branch(self, marker, other):
        body = self._fn()
        start = body.index(marker)
        end = body.index(other, start)
        return body[start:end]

    def _win(self):
        return self._branch("#ifdef _WIN32", "#else")

    def _posix(self):
        return self._branch("#else", "#endif")

    def test_windows_assigns_every_child_to_a_kill_on_close_job(self):
        win = self._win()
        self.assertIn("CreateJobObjectA", win)
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", win)
        self.assertIn("AssignProcessToJobObject", win)
        # Created suspended, or the child can spawn before the assignment and
        # escape the job entirely.
        self.assertIn("CREATE_SUSPENDED", win)
        self.assertIn("ResumeThread", win)
        self.assertIn("CREATE_NEW_PROCESS_GROUP", win)

    def test_windows_kills_the_tree_not_just_the_shell(self):
        win = self._win()
        self.assertIn("TerminateJobObject", win)
        self.assertIn("TerminateProcess", win)

    def test_windows_reads_are_non_blocking_and_bounded(self):
        win = self._win()
        # The old unbounded ReadFile loop is what let a hung pipe wedge the
        # loop; PeekNamedPipe + a deadline is the fix.
        self.assertIn("PeekNamedPipe", win)
        self.assertIn("GetTickCount() > deadline", win)
        self.assertNotIn("WaitForSingleObject(pi.hProcess, 5000)", win)

    def test_posix_kills_the_process_group(self):
        posix = self._posix()
        self.assertIn("setpgid", posix)
        self.assertIn("kill(-pid, SIGKILL)", posix)

    def test_posix_reaps_so_no_zombie_survives(self):
        posix = self._posix()
        self.assertIn("WNOHANG", posix)
        self.assertIn("select(", posix)
        self.assertIn("std::chrono::steady_clock::now() > deadline", posix)

    def test_output_is_capped(self):
        self.assertIn("kMaxTaskOutput", self.src)
        self.assertIn("static const size_t kMaxTaskOutput", self.src)


class TestPendingResultsAreNotHeadOfLineBlocked(unittest.TestCase):
    """1.1: one undeliverable result must not stall the results behind it.

    The loop that retried unacknowledged results used ``else break;``, so the
    FIRST failure stopped the whole drain and every result produced afterwards
    stayed queued behind it (``pending_results`` only ever grew). The policy
    now lives in ``task::drain_pending_results`` — compiled and RUN by
    ``TestLifecycleExecutable`` above; these pin that ``main.cpp`` actually
    calls it instead of re-growing the broken loop.
    """

    def setUp(self):
        self.src = _MAIN.read_text(encoding="utf-8")

    def test_main_drains_pending_results_through_the_helper(self):
        self.assertIn("task::drain_pending_results(", self.src)

    def test_the_old_break_on_first_failure_is_gone(self):
        start = self.src.index(
            "std::vector<std::pair<std::string, std::string>> pending_results;")
        head = self.src[start:]
        self.assertNotIn(
            "for (auto it = pending_results.begin()", head,
            "the old iterator loop that break-ed on the first failure is back")


class TestLifecycleExecutable(unittest.TestCase):
    """Compile and run the C++ lifecycle test.

    This is the part that actually proves the fix: the C++ program runs the
    timeout path with a worker that finishes late and would have written into
    a dead frame.
    """

    def test_the_cpp_lifecycle_test_passes(self):
        compiler = _compiler()
        if compiler is None:
            self.skipTest("no C++ compiler on this runner")
        with tempfile.TemporaryDirectory() as tmp:
            exe = os.path.join(tmp, "task_lifecycle_test")
            argv = [compiler, "-std=c++20", "-O1", "-pthread", "-o", exe,
                    str(_CPP_TEST)]
            build = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=600)
            self.assertEqual(build.returncode, 0,
                             f"lifecycle test failed to build:\n"
                             f"{build.stdout}\n{build.stderr}")
            run = subprocess.run([exe], capture_output=True, text=True,
                                 timeout=300)
            self.assertEqual(
                run.returncode, 0,
                "task lifecycle invariants violated:\n"
                f"{run.stdout}\n{run.stderr}")
            # A passing run must actually have exercised the cases, otherwise
            # a compiler that silently skipped main() would look green.
            self.assertIn("all task-lifecycle checks passed", run.stdout)


class TestTheKeyloggerStopsCooperatively(unittest.TestCase):
    """G9: the keylogger hook thread must stop cooperatively.

    TerminateThread() on the hook thread while hook_proc holds key_lock (it
    takes the spinlock on every keystroke) abandons the lock forever: the
    buffer can never be dumped again and the beacon looks alive while it is
    not. The stop path must set a flag the hook loop observes, post WM_QUIT
    and wait a bounded time — never force the thread to die.
    """

    def setUp(self):
        self.src = (_SRC / "keylogger.h").read_text(encoding="utf-8")

    def test_terminate_thread_is_gone(self):
        # Comment lines may NAME TerminateThread to explain why it is gone;
        # what must not survive is a CALL to it in the code.
        code = "\n".join(
            line for line in self.src.splitlines()
            if not line.strip().startswith("//"))
        self.assertNotIn("TerminateThread", code)

    def test_hook_loop_observes_the_stop_flag(self):
        start = self.src.index("inline DWORD WINAPI hook_thread")
        end = self.src.index("// \u2500\u2500 Public API", start)
        loop = self.src[start:end]
        self.assertIn("g_stop.load()", loop)
        # A blocking GetMessageW would never observe the flag on an idle
        # desktop: the loop must poll with a bounded wait instead.
        self.assertNotIn("while (GetMessageW", self.src)
        self.assertIn("MsgWaitForMultipleObjects", loop)

    def test_stop_flag_is_reset_before_the_thread_is_spawned(self):
        spawn = self.src.index("CreateThread(NULL, 0, hook_thread")
        self.assertIn("g_stop.store(false)", self.src[:spawn])

    def test_stop_posts_wm_quit_then_waits_bounded(self):
        start = self.src.index("inline std::string stop()")
        body = self.src[start:]
        self.assertIn("g_stop.store(true)", body)
        self.assertIn("PostThreadMessageW", body)
        self.assertLess(body.index("PostThreadMessageW"),
                        body.index("WaitForSingleObject"))
        self.assertIn("WaitForSingleObject(g_hook_thread, 5000)", body)


if __name__ == "__main__":
    unittest.main()
