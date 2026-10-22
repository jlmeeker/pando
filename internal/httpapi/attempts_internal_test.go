package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trypando/pando/internal/clientaddr"
	"github.com/trypando/pando/internal/core/state"
	"github.com/trypando/pando/internal/errs"
)

// TestR404_TheInMemoryCountLimitsAndSaysWhen asserts the count a Server uses
// when no shared store is wired: a reservation counts before the check, the
// limit refuses once reached and says how long until the oldest failure leaves
// the window, a release takes a reservation back, Clear forgets, and the count
// is one per Server so that two in one process do not share a count.
func TestR404_TheInMemoryCountLimitsAndSaysWhen(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	f := s.failedAttempts()
	require.Same(t, f, s.failedAttempts(), "one count per Server")
	require.NotSame(t, f, (&Server{}).failedAttempts(), "and not one per process")

	limit := state.AttemptLimit{Key: "signin|user|dana", Max: 3, Window: time.Minute}
	for range 3 {
		res, err := f.Reserve(ctx, limit)
		require.NoError(t, err)
		require.False(t, res.Refused())
		require.Len(t, res.Held, 1)
	}
	over, err := f.Reserve(ctx, limit)
	require.NoError(t, err)
	require.True(t, over.Refused())
	require.Zero(t, over.Over)
	require.Empty(t, over.Held, "a refused attempt counts nothing")
	require.Greater(t, over.Wait, 55*time.Second)
	require.LessOrEqual(t, over.Wait, time.Minute)

	require.NoError(t, f.Clear(ctx, limit.Key))
	res, err := f.Reserve(ctx, limit)
	require.NoError(t, err)
	require.False(t, res.Refused(), "cleared")
	require.NoError(t, f.Release(ctx, res))
	for range 3 {
		res, err = f.Reserve(ctx, limit)
		require.NoError(t, err)
		require.False(t, res.Refused(), "the released reservation is not counted")
	}
}

// TestR075a_ConcurrentGuessesAreHeldToTheLimit asserts a burst of attempts at
// once gets no more checks than the limit allows: each is counted before it is
// checked, atomically with reading the count.
func TestR075a_ConcurrentGuessesAreHeldToTheLimit(t *testing.T) {
	f := (&Server{}).failedAttempts()
	limit := state.AttemptLimit{Key: "passcode|app|x", Max: 5, Window: time.Minute}
	var checked atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			res, err := f.Reserve(context.Background(), limit)
			if err == nil && !res.Refused() {
				checked.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 5, checked.Load())
}

// brokenAttempts cannot count.
type brokenAttempts struct{ *memoryFailedAttempts }

func (*brokenAttempts) Reserve(context.Context, ...state.AttemptLimit) (state.Reservation, error) {
	return state.Reservation{}, errors.New("database away")
}

// TestR404_AnUncountableAttemptIsAnError asserts the limit fails closed: an
// attempt that cannot be counted is answered with an error and never checked.
func TestR404_AnUncountableAttemptIsAnError(t *testing.T) {
	s := &Server{FailedAttempts: &brokenAttempts{}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	_, ok := s.reserveAttempt(w, r, nil, limited{state.AttemptLimit{Key: "k", Max: 1, Window: time.Minute}, "x"})
	require.False(t, ok)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestR404_OnlyAWrongGuessStaysCounted asserts how a reserved attempt is
// settled: a wrong guess keeps its failure, a check that could not be made
// gives it back, and a right guess gives it back and clears the key.
func TestR404_OnlyAWrongGuessStaysCounted(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	f := s.failedAttempts()
	r := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	limit := state.AttemptLimit{Key: "k", Max: 2, Window: time.Minute}
	count := func() int {
		m := f.(*memoryFailedAttempts)
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.within(limit.Key, limit.Window))
	}

	res, err := f.Reserve(ctx, limit)
	require.NoError(t, err)
	s.settle(r, res, errs.New(errs.AuthInvalid, "wrong"))
	require.Equal(t, 1, count(), "a wrong guess stays counted")

	res, err = f.Reserve(ctx, limit)
	require.NoError(t, err)
	s.settle(r, res, errs.New(errs.Internal, "database away"))
	require.Equal(t, 1, count(), "an unmade check is given back")

	res, err = f.Reserve(ctx, limit)
	require.NoError(t, err)
	s.settle(r, res, nil, limit.Key)
	require.Zero(t, count(), "a right guess clears the key")
}

// TestR404_TheWaitIsSaidInWords asserts how a refusal says how long to wait
// (R-105: self-contained, no undefined units).
func TestR404_TheWaitIsSaidInWords(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Second:                  "1 second",
		1500 * time.Millisecond:      "2 seconds",
		30 * time.Second:             "30 seconds",
		time.Minute:                  "1 minute",
		11*time.Minute + time.Second: "12 minutes",
		15 * time.Minute:             "15 minutes",
	} {
		require.Equal(t, want, waitPhrase(d), d.String())
	}
}

// TestR404_TheLimitAddressIsTheAuditedOne asserts which address the limits
// are kept per: the one the audit log records, or the peer without it.
func TestR404_TheLimitAddressIsTheAuditedOne(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	r.RemoteAddr = "10.0.0.5:40000"
	require.Equal(t, "10.0.0.5", limitAddr(r))

	r = r.WithContext(clientaddr.With(r.Context(), clientaddr.Request{SourceIP: "203.0.113.9", PeerIP: "10.0.0.5"}))
	require.Equal(t, "203.0.113.9", limitAddr(r))
}
