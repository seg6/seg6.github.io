---
title: "concurrent device registration without redis"
description: "race conditions, row-level locks, and why your isolation level matters."
date: 2026-06-01
toc: true
mermaid: true
---

A user installs the desktop app on a new machine, signs in, and the backend has to decide: do they have a free seat, or have they hit their device limit? Issue a key or send them packing.

The constraint sounds trivial when you say it out loud. For any user with a maximum device count `L` and an active count `A`, make sure `A <= L` holds. That's it. That's the whole feature.

Then you ship it, two of the user's machines hit "register" within the same millisecond, and your invariant goes out the window.

This is the story of how I got it back, without bringing in any new infrastructure to do it.

# the constraints

Half the interesting decisions here come from things I *couldn't* do.

The MySQL database is nearly as old as I am. Tables that were designed for one purpose a long time ago, picked up extra columns over the years, and are now load bearing for things they were never meant to do. The legacy backend that's still serving production traffic reads them in ways that aren't fully documented and aren't well tested. The rewrite was rolling out incrementally, and the two backends would run side by side for months.

So:

- **no schema rewrites** to existing tables. Auditing every legacy query wasn't on the table.
- **no new infrastructure.** No Redis, no etcd. One more service to operate and monitor, might not be worth it.
- **no broad locking.** Whatever I introduced couldn't stall unrelated queries. The DB has to keep doing its day job.
- **multiple backend instances behind a load balancer.** Anything relying on shared in-process state is dead on arrival.

That last one is the one that kills most of the obvious approaches.

A quick map of the tables that come up:

- `users`: the main user table. **MyISAM**, never migrated to InnoDB. Hold that thought, it matters.
- `features`: per-user plan info, including `devices` (the seat limit `L`). No unique constraint on `user_id`. A user might have zero rows, exactly one, or, for some reason, multiple.
- `registrations`: one row per registered device.

# iteration 0: the naive handler

```go
// POST /registration { username, password, device_name }
func createRegistration() {
    // We actually have a middleware for this, do not worry.
    user := GetUserByCredentials(username, password)
    if user == nil {
        return http.StatusUnauthorized
    }

    seatLimit := GetSeatLimit(user)
    activeSeats := GetActiveSeatCount(user)

    if activeSeats >= seatLimit {
        return http.StatusConflict
    }

    return CreateSeatRegistration(user, deviceName)
}
```

Read, compare, insert. Looks fine.

It isn't.

```text
Time    Request 1              Request 2              DB State
----    ---------------------  ---------------------  ---------
t0      START                                         A=1, L=2
        auth ok

t1      get_limit  -> 2        START                  A=1, L=2
        get_count  -> 1        auth ok

t2      check (1 < 2): ok      get_limit  -> 2        A=1, L=2
                               get_count  -> 1

t3                             check (1 < 2): ok      A=1, L=2
                               create

t4      create                                        A=2, L=2

t5      DONE                                          A=3, L=2  *broken*
```

Two requests for the same user both read `A=1`. Both decide there's room. Both insert. The user now has three devices registered against a two device limit.

Classic time-of-check to time-of-use. The check ("is there room?") and the use ("create the registration") aren't atomic, so anything that changes between the two, like the other request inserting its row, invalidates the check. The fix is some flavour of synchronization. The interesting question is *where* it lives.

# iteration 1: a global mutex

The dumbest possible synchronization primitive is a `sync.Mutex` at the top of the handler:

```go
var registrationMu sync.Mutex

func createRegistration() {
    registrationMu.Lock()
    defer registrationMu.Unlock()
    // ...
}
```

This works, in the technical sense. It also means that two completely unrelated users (different accounts, different plans, different continents) can't register devices at the same time. One of them waits. For nothing.

We can't ship that. Throughput collapses the moment traffic shows up. The lock proposed here is too coarse. We only need to serialize requests for the *same* user.

# iteration 2: per-user mutexes

A `sync.Map` of mutexes, keyed by user ID. Each request grabs the mutex for *its* user.

```go
var userLocks sync.Map

func lockFor(userID int) *sync.Mutex {
    mu, _ := userLocks.LoadOrStore(userID, &sync.Mutex{})
    return mu.(*sync.Mutex)
}
```

Different users register in parallel, same user requests serialize. The throughput is fine, correctness is fine, life is good. In a single process world, this could be the answer.

We do not live in a single-process world.

<pre class="mermaid">
flowchart LR
    lb[load balancer]
    subgraph instances[backend instances]
        i1[instance 1<br/>userLocks map]
        i2[instance 2<br/>userLocks map]
        i3[instance 3<br/>userLocks map]
    end
    db[(MySQL)]

    r1[request A<br/>user 42] --> lb
    r2[request B<br/>user 42] --> lb
    lb --> i1
    lb --> i3
    i1 --> db
    i3 --> db
</pre>

The backend runs as multiple replicas. Each one has its own process memory, its own `userLocks` map, its own copy of "the user 42 mutex". Two requests for user `42` hit two different instances, each one cheerfully locks its local mutex, neither waits for anything, both race against the database in parallel. We're back where we started, except now we feel clever about it!

What we actually need is a lock that lives somewhere all the instances can see. The usual menu (Redis, etcd, a Redlock implementation if you're feeling brave) all violate the "no new infrastructure" constraint.

But here's the thing: every instance already shares one piece of durable, network accessible state. They all talk to the same MySQL database. Databases are, fundamentally, distributed coordination services with extremely good durability guarantees bolted on. Locking is something they're explicitly built to do.

So I made the database lock for me.

# iteration 3: let the database lock for us

InnoDB supports row-level locking. `SELECT ... FOR UPDATE` inside a transaction takes an exclusive lock on each matching row. Other transactions that try to lock or modify that row block until the holder commits or rolls back. Different rows? They don't contend at all!

That's exactly the granularity we want. Same user requests serialize on the same row, different users don't even know about each other.

The shape:

1. begin a transaction
2. `SELECT ... FOR UPDATE` on a row tied to this user
3. read count and limit
4. insert if there's room
5. commit (or rollback)

Two requests for the same user race for the lock. One wins, does its check, inserts, commits, and only at that point does the lock release. The other request, which has been blocked at step 2 the whole time, now unblocks, runs *its* check against the new state of the world, and bails out. Two requests for *different* users don't contend at all.

So which row do we lock?

This is where I spent more time than I'd like to admit, because the natural answers all turned out to be wrong.

**`users`?** This is the most tempting one, since every user has exactly one. But `users` is a MyISAM table. MyISAM has no row-level locking. No transactions. None of the primitives this approach depends on. `SELECT ... FOR UPDATE` against a MyISAM table is a silent no-op: the syntax parses, the query runs, no lock is taken. You don't get an error, nor a warning. You instead get a race condition wearing a confident smile!

**`features`?** That's where the seat limit lives, so it felt right. Right up until I realized there's no unique constraint on `user_id`, and some users might have no row in `features` at all. `SELECT ... FOR UPDATE` only locks rows that *exist*. No row, no lock, no protection. The patch ("if it's missing, insert a default and then lock it") has its own race: two requests both observe no row, both insert, now there are two `features` rows for the same user. We've traded a race condition for another one, terrible trade.

So neither existing row works. What I actually wanted was a row whose only purpose was *being a stable lock target*, with proper uniqueness, that nothing else in the system touched.

## a table that exists only to be locked

```sql
CREATE TABLE registration_lock (
    user_id    INT       NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB;
```

That's the whole table. No business data. The `created_at` is there because empty tables feel weird, nothing reads it. The point is the primary key on `user_id`, which gives me uniqueness guarantees and a stable target for `SELECT ... FOR UPDATE`.

The flow becomes:

1. `INSERT ... ON DUPLICATE KEY UPDATE`: guarantees the row exists, atomically
2. `SELECT ... FOR UPDATE`: takes the lock
3. read count and limit
4. insert if there's room
5. commit

Step 1 is the move. `INSERT ... ON DUPLICATE KEY UPDATE` is a single atomic statement: it either inserts a new row, or runs the `UPDATE` clause against the existing one. Two concurrent calls cannot both decide "the row doesn't exist, I'll create it".

```go
func (s *Store) AcquireRegistrationLock(ctx context.Context, userID int) error {
    _, err := s.db(ctx).ExecContext(ctx, `
        INSERT INTO registration_lock (user_id)
        VALUES (?)
        ON DUPLICATE KEY UPDATE created_at = created_at`,
        userID,
    )
    if err != nil {
        return fmt.Errorf("ensure lock row: %w", err)
    }

    var exists int
    return s.db(ctx).GetContext(ctx, &exists, `
        SELECT 1 FROM registration_lock
        WHERE user_id = ? FOR UPDATE`,
        userID,
    )
}

func (s *RegistrationService) CreateRegistration(
    ctx context.Context, username, password, deviceName string,
) (*Registration, error) {
    user, err := s.store.GetUserByCredentials(ctx, username, password)
    if err != nil {
        return nil, err
    }

    return s.store.WithTx(ctx,
        &sql.TxOptions{Isolation: sql.LevelReadCommitted},
        func(ctx context.Context) (*Registration, error) {
            if err := s.store.AcquireRegistrationLock(ctx, user.ID); err != nil {
                return nil, err
            }
            if exceeded := s.checkRegistrationLimit(ctx, user.ID); exceeded {
                return nil, ErrNoSeatsAvailable
            }
            return s.store.CreateRegistration(ctx, user.ID, deviceName)
        },
    )
}
```

The whole thing runs in one transaction. That part matters: InnoDB releases row locks at transaction end. If the lock and the insert weren't in the same transaction, the lock would drop the moment `AcquireRegistrationLock` returned and the limit check after it would run completely unprotected.

And that `sql.LevelReadCommitted` on the transaction options? That isn't decorative at all! That one bit me harder than anything else in this whole project.

# the second wrinkle: isolation levels

The first time I wrote this, I left the isolation level at the MySQL default, `REPEATABLE READ`, the one every example online uses, because I didn't have a specific reason to change it. The unit tests passed. I felt good. I wrote a stress test that fired off ten concurrent registrations against a one seat user. And two of them succeeded.

The lock was working. I checked the slow query log: R2 was definitely waiting for R1 to commit. So the requests were serialized correctly. And R2 was *still* coming back saying there was room.

That's where I had to actually understand what isolation levels are doing.

InnoDB uses MVCC: multi-version concurrency control. Instead of having writers block readers, the engine keeps multiple versions of each row and shows each transaction a "view" of the database. The rules for that view depend on isolation level.

## repeatable read

The MySQL default. On the transaction's first read, InnoDB takes a snapshot of which row versions are committed at that moment. Every subsequent non-locking read in that transaction is served from that same snapshot, regardless of what other transactions commit while you're working.

This is wonderful for reports, where you don't want totals shifting under you mid query. It's the wrong tool here though. The whole *reason* I'm waiting on a lock is that another transaction is changing the data, if I then read from a snapshot taken before those changes, the wait was pointless theatre.

There's a mean little wrinkle: `SELECT ... FOR UPDATE` is a *locking* read, and locking reads see the latest committed data even under `REPEATABLE READ`. But `SELECT COUNT(*) FROM registrations` is a regular read, and that one happily uses the stale snapshot. So in the same transaction, two queries can show you two different versions of reality. This is the kind of thing you find out about by being burned by it.

## serializable

Every transaction runs as if it were the only one in the world. Correct, but it's basically the global mutex pushed into the database. We already rejected that solution; no reason to come back to it now wearing different hats.

## read committed

Each statement sees the latest committed state at the moment that statement runs. No long-lived snapshot, after the transaction wakes up from waiting on the lock, the next read sees what *just happened*. This is what we want. The lock serializes the critical section, `READ COMMITTED` makes sure we see fresh data inside it.

## the difference, side by side

Same scenario, two isolation levels. Under `READ COMMITTED`:

```text
Time    R1                              R2                              DB State
----    ------------------------------  ------------------------------  ---------
t0      BEGIN                           BEGIN                           A=1, L=2

t1      SELECT FOR UPDATE               wait for lock                   A=1, L=2
        lock acquired

t2      read count -> 1                 (still waiting)                 A=1, L=2
        read limit -> 2
        check (1 < 2): ok

t3      INSERT registration             (still waiting)                 A=2, L=2

t4      COMMIT                          lock acquired                   A=2, L=2

t5                                      read count -> 2                 A=2, L=2
                                        read limit -> 2
                                        check (2 >= 2): full

t6                                      ROLLBACK                        A=2, L=2
```

R2 wakes up after R1 commits, reads the new count, sees the limit is full, gives up. Our invariant holds!

But under `REPEATABLE READ`:

```text
Time    R1                              R2                              DB State
----    ------------------------------  ------------------------------  ---------
t0      BEGIN                           BEGIN                           A=1, L=2
        snapshot taken                  snapshot taken

t1      SELECT FOR UPDATE               wait for lock                   A=1, L=2
        lock acquired

t2      read count -> 1                 (still waiting)                 A=1, L=2
        read limit -> 2
        check (1 < 2): ok

t3      INSERT registration             (still waiting)                 A=2, L=2

t4      COMMIT                          lock acquired                   A=2, L=2

t5                                      read count -> 1  (!)            A=2, L=2
                                        read limit -> 2
                                        check (1 < 2): ok  (!)

t6                                      INSERT registration             A=3, L=2  *broken*
                                        COMMIT
```

R2 acquires the lock, perfectly. R2 reads the count, and gets `A=1`, the value from R2's snapshot taken back at `t0`, before R1 had even started its insert. The lock serialized the *execution*. The snapshot meant R2 was making its decision against a view of the world that no longer existed.

Locking and isolation are orthogonal. Locks control *when* transactions run. Isolation controls *what they see* once they're running. If we get the locking right and the isolation wrong, we get a system that serializes flawlessly while quietly producing wrong answers.

# testing it

The test that surfaced the bug parks a pile of goroutines at a barrier and releases them all at the exact same instant, smashing them into the same single seat:

```go
func TestConcurrentRegistration(t *testing.T) {
    ts := testutil.NewTestSetup(t)
    user := ts.SeedUser(t, "testuser", "testpass", "test@example.com")
    ts.SeedFeatures(t, user.ID, 1) // one seat

    attempts := 10
    responses := make([]response, attempts)
    var ready, done sync.WaitGroup
    start := make(chan struct{})

    for i := 0; i < attempts; i++ {
        ready.Add(1)
        done.Add(1)
        go func(idx int) {
            defer done.Done()
            ready.Done()
            <-start  // barrier

            responses[idx] = executeRequest(handler, registrationRequest{
                Username:   "testuser",
                Password:   "testpass",
                DeviceName: fmt.Sprintf("device-%d", idx),
            })
        }(i)
    }

    ready.Wait()    // every goroutine is parked
    close(start)    // released all at once
    done.Wait()

    require.Equal(t, 1, successCount(responses))
    require.Equal(t, 9, conflictCount(responses))
}
```

`ready` makes sure every goroutine has reached the barrier before any of them is allowed to fire. `close(start)` releases them all in the same instant. The point is to push the contention window down to almost nothing: ten goroutines fighting over a single seat in roughly the same nanosecond. Without the barrier, they'd stagger, and the race would be too small to consistently trigger.

Under `REPEATABLE READ`, this test fails. Sometimes two registrations succeed, sometimes three. Under `READ COMMITTED`, exactly one succeeds, exactly nine fail with a conflict, every single run.

# wrapping up

We added one new table, a transaction wrapper, and a one line isolation level change while no extra service to operate or monitor. The database was already a distributed coordination service, we just had to ask it for the right lock and read at the right level.

The general lesson here is that, if there is one: when you're tempted to reach for an external coordination primitive, check first whether the durable store you're already running is willing to do the job. Most of the time, it is. The trick is knowing what to ask for.
