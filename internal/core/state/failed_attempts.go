package state

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/trypando/pando/internal/errs"
)

// FailedAttempts counts wrong guesses at something secret, for the limits on
// guessing: a passcode, per app and client address (R-075a), and a password at
// sign-in, per username and per client address (R-404). A key says which.
//
// In the database rather than in memory (issue #72): with N replicas behind a
// load balancer, a count kept per process gave an attacker N times the
// attempts, and one more set every time a replica restarted.
type FailedAttempts struct{ db *DB }

func NewFailedAttempts(db *DB) *FailedAttempts { return &FailedAttempts{db: db} }

// maxKeyUsername bounds what a client can put in a row it causes.
const maxKeyUsername = 256

// SignInUsernameKey is the key wrong passwords for username are counted
// under (R-404): as typed, whether or not the account exists.
func SignInUsernameKey(username string) string {
	if len(username) > maxKeyUsername {
		username = username[:maxKeyUsername]
	}
	return "signin|user|" + username
}

// SignInAddrKey is the key wrong passwords from a client address are counted
// under (R-404).
func SignInAddrKey(addr string) string { return "signin|addr|" + addr }

// SignInCodeKey is the key wrong two-factor codes for an account are counted
// under (R-405). By account ID: the password was right, so it is known.
func SignInCodeKey(userID string) string { return "signin|code|" + userID }

// AttemptLimit is how many failures a key may have within a window before
// another attempt is refused without being checked.
type AttemptLimit struct {
	Key    string
	Max    int
	Window time.Duration
}

// HeldAttempt is one failure Reserve counted ahead of the check: its key and
// the time it was counted at, which is how Release finds it again.
type HeldAttempt struct {
	Key string
	At  time.Time
}

// Reservation is what Reserve decided. Over a limit, Over is that limit's
// index and Wait how long until it lets another attempt through, never zero,
// and nothing was counted. Otherwise Over is -1 and Held is the failure
// counted against each limit, which stands unless it is released.
type Reservation struct {
	Held []HeldAttempt
	Over int
	Wait time.Duration
}

// Refused reports whether a limit was reached and the attempt is not to be
// checked.
func (r Reservation) Refused() bool { return r.Over >= 0 }

// Reserve counts one failure against every limit before the guess is checked,
// unless one is already reached (R-075a, R-404, R-405). Counting first and in
// one transaction under each key's lock is what holds a burst of concurrent
// attempts to the limit: reading the count and recording the failure after
// the check let every request in the burst see the same count. The caller
// releases the reservation when the guess was right, or when it was not a
// guess at all.
func (p *FailedAttempts) Reserve(ctx context.Context, limits ...AttemptLimit) (Reservation, error) {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return Reservation{}, errs.Wrap(errs.Internal, "Could not count failed attempts.", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	res, err := reserveIn(ctx, tx, limits)
	if err != nil {
		return Reservation{}, errs.Wrap(errs.Internal, "Could not count failed attempts.", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Reservation{}, errs.Wrap(errs.Internal, "Could not count failed attempts.", err)
	}
	return res, nil
}

// reserveIn is Reserve inside its transaction.
func reserveIn(ctx context.Context, tx pgx.Tx, limits []AttemptLimit) (Reservation, error) {
	// Locked in one order whatever order the limits come in, so two
	// attempts holding the same keys cannot each wait for the other. Each
	// lock is its own statement, so the counts after it see what the last
	// holder committed.
	keys := make([]string, 0, len(limits))
	for _, l := range limits {
		keys = append(keys, l.Key)
	}
	slices.Sort(keys)
	for _, key := range slices.Compact(keys) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			failedAttemptsLockKey+key); err != nil {
			return Reservation{}, err
		}
	}
	for i, l := range limits {
		var n int
		var secs float64
		if err := tx.QueryRow(ctx, `
			SELECT count(*),
			       coalesce(extract(epoch FROM min(failed_at) + make_interval(secs => $2) - clock_timestamp()), 0)::float8
			FROM failed_attempts
			WHERE key = $1 AND failed_at > clock_timestamp() - make_interval(secs => $2)`,
			l.Key, l.Window.Seconds()).Scan(&n, &secs); err != nil {
			return Reservation{}, err
		}
		if n >= l.Max {
			// Never zero once over, so a caller can tell the two apart.
			return Reservation{Over: i, Wait: max(time.Duration(secs*float64(time.Second)), time.Second)}, nil
		}
	}
	res := Reservation{Over: -1}
	for _, l := range limits {
		var at time.Time
		if err := tx.QueryRow(ctx, `
			INSERT INTO failed_attempts (key, failed_at) VALUES ($1, clock_timestamp()) RETURNING failed_at`,
			l.Key).Scan(&at); err != nil {
			return Reservation{}, err
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM failed_attempts WHERE key = $1 AND failed_at <= clock_timestamp() - make_interval(secs => $2)`,
			l.Key, l.Window.Seconds()); err != nil {
			return Reservation{}, err
		}
		res.Held = append(res.Held, HeldAttempt{Key: l.Key, At: at})
	}
	return res, nil
}

// failedAttemptsLockKey prefixes a key for its advisory lock, so it cannot
// share one with another use of advisory locks.
const failedAttemptsLockKey = "failed_attempts|"

// Release takes back the failures a reservation counted: the guess was right,
// or it was never checked. One row per held failure, matched by key and time.
func (p *FailedAttempts) Release(ctx context.Context, res Reservation) error {
	var failed error
	for _, h := range res.Held {
		_, err := p.db.Exec(ctx, `
			DELETE FROM failed_attempts WHERE ctid = (
				SELECT ctid FROM failed_attempts WHERE key = $1 AND failed_at = $2 LIMIT 1)`,
			h.Key, h.At)
		failed = errors.Join(failed, err)
	}
	if failed != nil {
		return errs.Wrap(errs.Internal, "Could not release a counted attempt.", failed)
	}
	return nil
}

// Recent counts failures for key within window.
func (p *FailedAttempts) Recent(ctx context.Context, key string, window time.Duration) (int, error) {
	var n int
	err := p.db.QueryRow(ctx, `
		SELECT count(*) FROM failed_attempts
		WHERE key = $1 AND failed_at > now() - make_interval(secs => $2)`,
		key, window.Seconds()).Scan(&n)
	if err != nil {
		return 0, errs.Wrap(errs.Internal, "Could not read recent failed attempts.", err)
	}
	return n, nil
}

// Wait is how long until the oldest failure for key within window leaves it,
// which is when one more attempt is allowed once a limit is reached. Zero when
// there is none. Measured by the database's clock, which recorded them.
func (p *FailedAttempts) Wait(ctx context.Context, key string, window time.Duration) (time.Duration, error) {
	var secs float64
	err := p.db.QueryRow(ctx, `
		SELECT coalesce(extract(epoch FROM min(failed_at) + make_interval(secs => $2) - now()), 0)::float8
		FROM failed_attempts
		WHERE key = $1 AND failed_at > now() - make_interval(secs => $2)`,
		key, window.Seconds()).Scan(&secs)
	if err != nil {
		return 0, errs.Wrap(errs.Internal, "Could not read recent failed attempts.", err)
	}
	return max(time.Duration(secs*float64(time.Second)), 0), nil
}

// Record counts one failure for key, and forgets failures older than window
// for it, which nothing will count again.
func (p *FailedAttempts) Record(ctx context.Context, key string, window time.Duration) error {
	if _, err := p.db.Exec(ctx, `INSERT INTO failed_attempts (key) VALUES ($1)`, key); err != nil {
		return errs.Wrap(errs.Internal, "Could not record a failed attempt.", err)
	}
	if _, err := p.db.Exec(ctx, `
		DELETE FROM failed_attempts WHERE key = $1 AND failed_at <= now() - make_interval(secs => $2)`,
		key, window.Seconds()); err != nil {
		return errs.Wrap(errs.Internal, "Could not record a failed attempt.", err)
	}
	return nil
}

// Clear forgets key's failures, after a right guess.
func (p *FailedAttempts) Clear(ctx context.Context, key string) error {
	if _, err := p.db.Exec(ctx, `DELETE FROM failed_attempts WHERE key = $1`, key); err != nil {
		return errs.Wrap(errs.Internal, "Could not clear failed attempts.", err)
	}
	return nil
}

// Prune forgets every failure older than window: keys nobody tried again.
func (p *FailedAttempts) Prune(ctx context.Context, window time.Duration) error {
	if _, err := p.db.Exec(ctx, `
		DELETE FROM failed_attempts WHERE failed_at <= now() - make_interval(secs => $1)`,
		window.Seconds()); err != nil {
		return errs.Wrap(errs.Internal, "Could not prune failed attempts.", err)
	}
	return nil
}
