// server/db/write_queue.h
//
// Write-behind buffer for SQLite.
//
// The server's hot path produces writes (an address claim per client
// connection, name registrations, settings). Committing every one of them
// synchronously means a disk flush - and the database mutex - inside the
// request path, which is what turns a burst of clients into stall.
//
// This unit keeps the pending writes in memory (one entry per key, so
// repeated updates of the same identity/domain coalesce into a single row
// write) and a background thread commits them when the database is free:
//   * the flusher only enters while the database mutex can be acquired
//     without blocking, so readers are never pushed aside;
//   * it opens its transaction with BEGIN IMMEDIATE and a zero busy
//     timeout, so an externally locked database is simply retried later;
//   * the queue is bounded. When it fills up, producers wait for space
//     instead of growing without limit (natural backpressure).
//
// Callers attach the queue to their database handle and mutex; until the
// flusher is started, writes are executed synchronously so early startup
// (schema repair, unit tests) keeps the old durable behavior.
#ifndef ROOTLAYER_SERVER_DB_WRITE_QUEUE_H
#define ROOTLAYER_SERVER_DB_WRITE_QUEUE_H

#include "core/win_headers.h"

#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

class WriteQueue {
public:
    // Executed while the database mutex is held. Returns false when the
    // write could not be applied because the database is busy/locked (the
    // entry is retried later); internal conflicts that were resolved are
    // reported as true.
    using Task = std::function<bool()>;

    // Called with the queue's key after a COMMIT, still under the database
    // mutex. Owners use it to drop the in-memory copy of the committed row.
    using CommitFn = std::function<void(const std::string& key)>;

    WriteQueue() = default;
    ~WriteQueue();

    WriteQueue(const WriteQueue&) = delete;
    WriteQueue& operator=(const WriteQueue&) = delete;

    // Attach to a database handle and the mutex that guards it. Must be
    // called before the first enqueue().
    void setup(sqlite3* db, std::mutex* db_mutex, CommitFn on_committed,
               size_t max_pending = 4096);

    // Start the background flusher. Until this point enqueue() writes
    // synchronously. `name` only appears in console diagnostics.
    void start(const std::string& name);

    // Stop the flusher and drain everything still pending (best effort).
    void stop();

    // Insert or replace the write for `key`. Replacing means "the newest
    // state wins", so a burst of updates for one identity costs one row
    // write. May block when the bounded queue is full.
    void enqueue(const std::string& key, Task task);

    // Synchronous drain for shutdown. Returns when the queue is empty or the
    // database stayed locked for the whole attempt window.
    void flush_now();

    size_t pending() const;
    uint64_t written() const;
    uint64_t retried() const;

    // One-line diagnostics for the console: "pending 3/4096, written 1200,
    // retried 4".
    std::string stats() const;

private:
    struct Entry {
        std::string key;
        Task task;
        size_t generation = 0;  // enqueue-time generation of this intent
    };

    void thread_main();
    bool flush_batch(bool blocking);
    void requeue(std::vector<Entry>&& batch);

    sqlite3* db_ = nullptr;
    std::mutex* db_mutex_ = nullptr;
    CommitFn on_committed_;
    std::string name_ = "database";

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, Task> pending_;
    std::map<std::string, size_t> generation_;  // latest enqueue generation per key
    size_t inflight_ = 0;  // entries taken out of pending_ by a flush
    size_t max_pending_ = 4096;
    bool running_ = false;
    bool stopping_ = false;
    bool warned_full_ = false;
    std::thread thread_;

    uint64_t written_ = 0;
    uint64_t retried_ = 0;
    uint64_t dropped_ = 0;
};

// Registered queues, used by the console handler at shutdown.
void flush_all_databases();

#endif  // ROOTLAYER_SERVER_DB_WRITE_QUEUE_H
