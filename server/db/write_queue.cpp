// server/db/write_queue.cpp - bounded write-behind buffer (see write_queue.h).
#include "core/win_headers.h"
#include "db/write_queue.h"

#include <chrono>

namespace {

// How many coalesced writes one transaction takes. Small enough that a
// commit never monopolizes the database for long, large enough to amortize
// the transaction cost during a burst.
const size_t kBatchSize = 64;

// Normal busy timeout of the connections (matches db_open/arpa_open). The
// flusher temporarily drops it to zero so a locked database is detected
// immediately instead of stalling this thread for seconds.
const int kNormalBusyMs = 5000;

const int kIdleWaitMs = 100;
const int kRetryWaitMs = 100;

// Shell for the shutdown path and the flusher registry. The queues live for
// the whole process; the registry only exists so the console handler can
// drain them without knowing which modules created them.
std::mutex g_registry_mutex;
std::vector<WriteQueue*> g_registry;

}  // namespace

WriteQueue::~WriteQueue() {
    stop();
}

void WriteQueue::setup(sqlite3* db, std::mutex* db_mutex, CommitFn on_committed,
                       size_t max_pending) {
    db_ = db;
    db_mutex_ = db_mutex;
    on_committed_ = std::move(on_committed);
    max_pending_ = max_pending == 0 ? 1 : max_pending;
}

void WriteQueue::start(const std::string& name) {
    if (db_ == NULL || db_mutex_ == NULL) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) return;
        name_ = name;
        running_ = true;
        stopping_ = false;
    }

    {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        g_registry.push_back(this);
    }

    thread_ = std::thread([this] { thread_main(); });
}

void WriteQueue::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_ && !thread_.joinable()) return;
        stopping_ = true;
    }
    cv_.notify_all();

    if (thread_.joinable()) {
        thread_.join();
    }

    // Drain what the flusher left behind (bounded: an externally locked
    // database cannot hold shutdown forever).
    flush_now();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
        stopping_ = false;
        cv_.notify_all();
    }
}

void WriteQueue::enqueue(const std::string& key, Task task) {
    if (!task || db_ == NULL || db_mutex_ == NULL) return;

    std::unique_lock<std::mutex> lock(mutex_);

    // Not started (early startup, unit tests) or stopped: keep the old
    // synchronous durability.
    if (!running_) {
        lock.unlock();
        std::lock_guard<std::mutex> db_lock(*db_mutex_);
        sqlite3_busy_timeout(db_, kNormalBusyMs);
        if (task() && on_committed_) {
            on_committed_(key);
        }
        return;
    }

    if (pending_.size() + inflight_ >= max_pending_) {
        if (!warned_full_) {
            warned_full_ = true;
            std::cerr << name_ << ": write buffer full (" << pending_.size()
                      << " pending); producers wait for the database" << std::endl;
        }
        // Bounded memory: the request path waits until the flusher makes
        // room instead of piling writes up without limit.
        while (running_ && pending_.size() + inflight_ >= max_pending_) {
            cv_.wait_for(lock, std::chrono::milliseconds(50));
        }
        if (pending_.size() < max_pending_ / 2) {
            warned_full_ = false;
        }
        if (!running_) {
            lock.unlock();
            std::lock_guard<std::mutex> db_lock(*db_mutex_);
            sqlite3_busy_timeout(db_, kNormalBusyMs);
            if (task() && on_committed_) {
                on_committed_(key);
            }
            return;
        }
    }

    // One entry per key: the newest intent wins, so a burst of updates for
    // the same identity costs one row write, not one per request.
    pending_[key] = std::move(task);
    ++generation_[key];
    cv_.notify_one();
}

void WriteQueue::flush_now() {
    if (db_ == NULL || db_mutex_ == NULL) return;

    // Waits for the flusher's in-flight batch as well as for the queue to
    // drain, so the caller can trust that everything is on disk when this
    // returns. Bounded: an externally locked database must not hang
    // shutdown forever.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (pending_.empty() && inflight_ == 0) return;
            cv_.wait_for(lock, std::chrono::milliseconds(10));
            if (pending_.empty() && inflight_ == 0) return;
        }
        if (std::chrono::steady_clock::now() >= deadline) return;
        // Help the flusher when the database is free; an in-flight batch is
        // completed by its owner (the wait above wakes on that commit).
        flush_batch(false);
    }
}

// Takes a batch out of the in-memory queue and commits it in one
// transaction. When `blocking` is false the database mutex is only taken
// when free - that is the "database is idle" gate of the normal path.
bool WriteQueue::flush_batch(bool blocking) {
    std::vector<Entry> batch;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_.begin();
        while (it != pending_.end() && batch.size() < kBatchSize) {
            batch.push_back(Entry{it->first, std::move(it->second), generation_[it->first]});
            it = pending_.erase(it);
        }
        inflight_ += batch.size();
    }
    if (batch.empty()) return true;

    std::unique_lock<std::mutex> db_lock(*db_mutex_, std::defer_lock);
    if (blocking) {
        db_lock.lock();
    } else if (!db_lock.try_lock()) {
        // Somebody is using the database right now (read or write). Leave
        // the batch queued; the next wake-up retries.
        requeue(std::move(batch));
        return false;
    }

    // Zero busy timeout: an externally locked file must not stall this
    // thread (and, through it, the queue) for seconds.
    sqlite3_busy_timeout(db_, blocking ? kNormalBusyMs : 0);

    bool began = (sqlite3_exec(db_, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    if (!began) {
        int code = sqlite3_errcode(db_) & 0xff;
        if (code != SQLITE_BUSY && code != SQLITE_LOCKED) {
            std::cerr << name_ << ": write transaction could not start: "
                      << sqlite3_errmsg(db_) << std::endl;
        }
    }
    bool all_ok = began;
    if (began) {
        for (auto& entry : batch) {
            if (!entry.task || !entry.task()) {
                all_ok = false;
                break;
            }
        }
    }

    bool committed = false;
    if (began) {
        if (all_ok && sqlite3_exec(db_, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) {
            committed = true;
        } else {
            sqlite3_exec(db_, "ROLLBACK", NULL, NULL, NULL);
        }
    }

    sqlite3_busy_timeout(db_, kNormalBusyMs);

    if (committed) {
        // Still under the database mutex: owners drop their in-memory copy
        // only now, after the rows are really on disk. Skip entries whose
        // generation was superseded by a newer enqueue while this batch was
        // in flight - the newer task will write the newest state on its own
        // flush, so erasing the old in-memory copy here would lose it.
        std::vector<std::string> to_commit;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& entry : batch) {
                auto gen = generation_.find(entry.key);
                if (gen != generation_.end() && gen->second == entry.generation) {
                    to_commit.push_back(entry.key);
                }
            }
            written_ += batch.size();
            inflight_ -= batch.size();
            cv_.notify_all();
        }
        for (const auto& key : to_commit) {
            if (on_committed_) on_committed_(key);
        }
    } else {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            retried_ += batch.size();
        }
        requeue(std::move(batch));
    }
    return committed;
}

// Put entries back without overwriting anything newer that arrived while
// the batch was in flight (the newer task writes the newest state anyway).
void WriteQueue::requeue(std::vector<Entry>&& batch) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& entry : batch) {
            pending_.emplace(entry.key, std::move(entry.task));
        }
        inflight_ -= batch.size();
    }
    cv_.notify_one();
}

void WriteQueue::thread_main() {
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (stopping_) break;
            if (pending_.empty()) {
                cv_.wait_for(lock, std::chrono::milliseconds(kIdleWaitMs));
                continue;
            }
        }

        if (!flush_batch(false)) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(kRetryWaitMs));
        }
    }
}

size_t WriteQueue::pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.size();
}

uint64_t WriteQueue::written() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return written_;
}

uint64_t WriteQueue::retried() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return retried_;
}

std::string WriteQueue::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return "pending " + std::to_string(pending_.size()) + "/" +
           std::to_string(max_pending_) + ", written " + std::to_string(written_) +
           ", retried " + std::to_string(retried_);
}

void flush_all_databases() {
    std::vector<WriteQueue*> queues;
    {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        queues = g_registry;
    }
    for (WriteQueue* queue : queues) {
        if (queue) queue->flush_now();
    }
}
