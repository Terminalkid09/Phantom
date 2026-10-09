// Compile-and-run test for the beacon task lifecycle.
//
// The bug this pins: the watchdog used to allocate TaskRun on the stack and
// detach() the worker on timeout, so a worker that woke up after the
// watchdog returned wrote into a dead stack frame (use-after-free). These
// cases assert the properties that make that impossible:
//
//   1. a run's storage stays alive while a worker still references it,
//      even after the watchdog has given up (shared ownership);
//   2. a worker cancelled mid-flight DROPS its result instead of publishing;
//   3. every task reaches an explicit, named terminal state;
//   4. the detached-worker cap is enforced (no unbounded thread growth),
//      and it counts THREADS, not terminal states — a cancelled run whose
//      worker is still blocked keeps its slot;
//   5. drain() at shutdown RETURNS even when a worker is genuinely blocked
//      (it reports how many it gave up on instead of waiting for ever).
//
// The three defects these last cases pin were all invisible to the original
// suite because it only ever used workers that finish: a lifecycle is only
// real when the work is actually STUCK.
//
// Build (MinGW-w64), run by tests/test_beacon_task_lifecycle.py:
//   g++ -std=c++20 -O1 -pthread -o t.exe test_beacon_task_lifecycle.cpp

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../phantom/payloads/beacon/src/task_lifecycle.h"

using task::Run;
using task::State;

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("  [FAIL] %s\n", (msg));                               \
            ++g_failures;                                                      \
        } else {                                                               \
            std::printf("  [ok]   %s\n", (msg));                               \
        }                                                                      \
    } while (0)

namespace {

void nap(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// 1. Normal completion: the watchdog's thread joins, output survives.
void test_completed() {
    std::printf("[1] normal completion\n");
    auto run = std::make_shared<Run>([] { return std::string("whoami output"); });
    run->mark_running();
    std::thread worker([run] { run->publish(run->work()()); });
    for (int i = 0; i < 200 && !run->finished(); ++i) nap(5);
    worker.join();
    CHECK(run->state() == State::kCompleted, "reaches kCompleted");
    CHECK(run->output() == "whoami output", "output published");
    CHECK(run->finished(), "finished() is true once terminal");
}

// 2. A task that reports an error is `failed`, not `completed`: the C2
//    operator must be able to tell the two apart.
void test_failed() {
    std::printf("[2] failure is a distinct state\n");
    auto run = std::make_shared<Run>([] { return std::string("Error: nope"); });
    run->mark_running();
    run->publish_failure(run->work()());
    CHECK(run->state() == State::kFailed, "reaches kFailed");
    CHECK(run->state_name() == std::string("failed"), "named 'failed'");
}

// 3. The core of the UAF fix: a worker that finishes AFTER cancellation must
//    not publish. Before the fix this was the exact line that wrote into the
//    dead stack frame.
void test_late_worker_does_not_publish() {
    std::printf("[3] late worker after cancel\n");
    std::atomic<bool> release{false};
    auto run = std::make_shared<Run>([] { return std::string("late result"); });
    run->mark_running();

    std::thread worker([run, &release] {
        while (!release.load()) nap(1);   // still "stuck" when the watchdog gives up
        run->publish(run->work()());     // <-- would have been the UAF write
    });

    nap(20);
    bool cancelled = run->request_cancel(State::kTimedOut);
    release.store(true);
    worker.join();                        // storage alive throughout, on purpose

    CHECK(cancelled, "request_cancel() claims the transition");
    CHECK(!run->publish("second attempt"), "publish() refuses after cancel");
    CHECK(run->state() == State::kTimedOut, "state stays kTimedOut");
    CHECK(run->output().empty(), "no output published for a killed task");
    CHECK(run->state_name() == std::string("timed_out"), "named 'timed_out'");
}

// 4. Storage outlives the watchdog: keep only a weak_ptr and prove the object
//    is still reachable because the worker holds a strong reference.
void test_storage_outlives_watchdog() {
    std::printf("[4] storage outlives the watchdog frame\n");
    std::atomic<bool> release{false};
    std::weak_ptr<Run> weak;
    std::shared_ptr<Run> run = std::make_shared<Run>([] { return std::string("x"); });
    weak = run;
    run->mark_running();
    std::thread worker([run, &release] {
        while (!release.load()) nap(1);
        run->publish(run->work()());
    });
    // The watchdog drops its reference here, exactly as returning from
    // run_task_with_timeout() would; the worker still holds its own.
    run.reset();
    nap(20);
    CHECK(!weak.expired(), "run is still alive after the watchdog let go");
    release.store(true);
    worker.join();
    for (int i = 0; i < 300 && !weak.expired(); ++i) nap(5);
    CHECK(weak.expired(), "run is freed once the worker also lets go");
}

// 5. The cap: admitting more detached workers than kMaxDetached is refused.
void test_detached_cap() {
    std::printf("[5] detached worker cap\n");
    auto& reg = task::Registry::instance();
    reg.drain();
    CHECK(reg.live() == 0, "registry empty to begin with");

    std::vector<std::shared_ptr<Run>> admitted;
    for (int i = 0; i < task::kMaxDetached; ++i) {
        auto run = std::make_shared<Run>([] { return std::string("stuck"); });
        run->mark_running();
        if (reg.admit(run)) admitted.push_back(run);
        else CHECK(false, "admit() refused below the cap");
    }
    CHECK(reg.live() == static_cast<size_t>(task::kMaxDetached),
          "cap reached with kMaxDetached live runs");

    auto extra = std::make_shared<Run>([] { return std::string("one too many"); });
    CHECK(!reg.admit(extra), "admit() refuses the one past the cap");

    // The stranded runs never finish; drain() must still return promptly.
    auto t0 = std::chrono::steady_clock::now();
    reg.drain();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    CHECK(reg.live() == 0, "drain() empties the registry");
    CHECK(ms < 2000, "drain() returns without hanging on stuck work");
}

// 6. Registry bookkeeping: a run whose worker has exited is reaped, not
//    leaked. Note what "reapable" means now: the THREAD is gone, not merely
//    the state.
void test_reap() {
    std::printf("[6] reap runs whose worker exited\n");
    auto& reg = task::Registry::instance();
    reg.drain();
    auto run = std::make_shared<Run>([] { return std::string("done"); });
    run->mark_running();
    CHECK(reg.admit(run), "admitted");
    CHECK(reg.live() == 1, "one live");
    run->publish(run->work()());
    reg.reap();
    CHECK(reg.live() == 1,
          "not reaped while the worker may still be inside work()");
    run->mark_worker_exited();
    reg.reap();
    CHECK(reg.live() == 0, "reaped once the worker exited");
}

// 7. The cap must count a run whose worker is STILL RUNNING even after the
//    run was cancelled. request_cancel() makes the state terminal at once,
//    so a state-keyed reap dropped the bookkeeping immediately and the cap
//    could never fill — which is why the beacon never refused anything.
void test_the_cap_counts_a_running_worker() {
    std::printf("[7] the cap counts threads, not terminal states\n");
    auto& reg = task::Registry::instance();
    reg.drain();
    auto run = std::make_shared<Run>([] { return std::string("late"); });
    run->mark_running();
    CHECK(reg.admit(run), "admitted");
    run->request_cancel(State::kTimedOut);
    CHECK(run->finished(), "the STATE is terminal immediately on cancel");
    CHECK(!run->worker_exited(), "but the WORKER has not exited");
    reg.reap();
    CHECK(reg.live() == 1,
          "reap() keeps a run whose worker is still running");
    run->mark_worker_exited();
    reg.reap();
    CHECK(reg.live() == 0, "reap() drops it once the worker exited");
}

// 8. drain() with a genuinely blocked worker: it must RETURN, cancel the
//    run, and report that it gave up on one worker — never wait for a thread
//    that cannot move.
void test_drain_returns_with_a_blocked_worker() {
    std::printf("[8] drain() with a genuinely blocked worker\n");
    auto& reg = task::Registry::instance();
    reg.drain();
    std::atomic<bool> release{false};
    auto run = std::make_shared<Run>([&release] {
        while (!release.load()) nap(1);   // work() does not return
        return std::string("late result");
    });
    run->mark_running();
    CHECK(reg.admit(run), "the stuck worker is registered");
    std::thread worker([run] {
        const std::string out = run->work()();
        run->publish(out);
        run->mark_worker_exited();
        task::Registry::instance().release(run.get());
    });
    nap(20);

    auto t0 = std::chrono::steady_clock::now();
    size_t abandoned = reg.drain();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 1000, "drain() returns while the worker is still blocked");
    CHECK(abandoned == 1, "drain() reports the worker it could not wait for");
    CHECK(run->state() == State::kCancelled, "the run was cancelled");
    CHECK(reg.live() == 0, "drain() empties the registry");

    release.store(true);          // let the worker go so it can be joined
    worker.join();
    CHECK(run->worker_exited(), "the worker signalled its own exit");
}

// 9. Head-of-line blocking: a send that fails for ONE task_id must not stop
//    the results behind it. The old loop `break`-ed on the first failure, so
//    everything queued after the bad entry stayed undelivered for ever.
void test_one_bad_result_does_not_block_the_rest() {
    std::printf("[9] one failing result does not block the rest\n");
    std::vector<std::pair<std::string, std::string>> pending = {
        {"t1", "out1"}, {"t2", "out2"}, {"t3", "out3"}};
    std::vector<std::string> attempted;
    size_t delivered = task::drain_pending_results(
        pending, [&attempted](const std::string& id, const std::string&) {
            attempted.push_back(id);
            return id != "t2";            // ONLY t2 is undeliverable
        });
    CHECK(delivered == 2, "the two healthy results were delivered");
    CHECK(attempted.size() == 3, "every result was attempted once");
    CHECK(attempted.size() == 3 && attempted[0] == "t1" &&
          attempted[1] == "t2" && attempted[2] == "t3",
          "attempted in queue order");
    CHECK(pending.size() == 1 && pending[0].first == "t2",
          "only the failed result stays queued");
}

// 10. The opposite failure mode: when EVERY send fails the round must end
//     (bounded work — no infinite retry) and the backlog must survive in
//     order for the next check-in.
void test_an_all_failing_send_terminates() {
    std::printf("[10] an always-failing send terminates the round\n");
    std::vector<std::pair<std::string, std::string>> pending = {
        {"a", "1"}, {"b", "2"}, {"c", "3"}};
    size_t calls = 0;
    size_t delivered = task::drain_pending_results(
        pending, [&calls](const std::string&, const std::string&) {
            ++calls;
            return false;                 // the link is down for sends
        });
    CHECK(delivered == 0, "nothing delivered when every send fails");
    CHECK(calls == 3, "each queued result attempted exactly once");
    CHECK(pending.size() == 3, "the whole backlog is retained");
    CHECK(pending.size() == 3 && pending[0].first == "a" &&
          pending[2].first == "c", "order preserved for the next round");
}

}  // namespace

int main() {
    std::printf("=== beacon task lifecycle ===\n");
    test_completed();
    test_failed();
    test_late_worker_does_not_publish();
    test_storage_outlives_watchdog();
    test_detached_cap();
    test_reap();
    test_the_cap_counts_a_running_worker();
    test_drain_returns_with_a_blocked_worker();
    test_one_bad_result_does_not_block_the_rest();
    test_an_all_failing_send_terminates();
    if (g_failures == 0) {
        std::printf("=== all task-lifecycle checks passed ===\n");
        return 0;
    }
    std::printf("=== %d check(s) failed ===\n", g_failures);
    return 1;
}