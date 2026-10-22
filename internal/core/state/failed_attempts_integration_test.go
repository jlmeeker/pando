//go:build integration

package state_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trypando/pando/internal/core/state"
	"github.com/trypando/pando/internal/id"
)

// TestR404_TheWaitIsUntilTheOldestFailureLeavesTheWindow asserts what a
// refusal over a limit tells someone (R-404): the time until the oldest
// failure in the window ages out of it, which is when one more attempt is
// allowed — and nothing to wait for when there are no failures.
func TestR404_TheWaitIsUntilTheOldestFailureLeavesTheWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := connected(t)
	failures := state.NewFailedAttempts(db)
	key := "signin|user|" + id.New(id.User)

	wait, err := failures.Wait(ctx, key, 15*time.Minute)
	require.NoError(t, err)
	require.Zero(t, wait)

	require.NoError(t, failures.Record(ctx, key, 15*time.Minute))
	require.NoError(t, failures.Record(ctx, key, 15*time.Minute))
	_, err = db.Exec(ctx, `
		UPDATE failed_attempts SET failed_at = now() - interval '10 minutes'
		WHERE ctid = (SELECT ctid FROM failed_attempts WHERE key = $1 LIMIT 1)`, key)
	require.NoError(t, err)

	wait, err = failures.Wait(ctx, key, 15*time.Minute)
	require.NoError(t, err)
	require.InDelta(t, (5 * time.Minute).Seconds(), wait.Seconds(), 5, "measured from the oldest failure")
}

// TestR075a_ReservationsHoldABurstToTheLimit asserts that counting an attempt
// before it is checked holds concurrent attempts to the limit (R-075a, R-404,
// R-405): of a burst of fifty against a limit of five across two keys, exactly
// five are let through to be checked, and a released one is not counted.
func TestR075a_ReservationsHoldABurstToTheLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	failures := state.NewFailedAttempts(connected(t))
	visitor := state.AttemptLimit{Key: "passcode|v|" + id.New(id.User), Max: 5, Window: time.Hour}
	app := state.AttemptLimit{Key: "passcode|app|" + id.New(id.User), Max: 100, Window: time.Hour}

	var through atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			res, err := failures.Reserve(ctx, app, visitor)
			if err == nil && !res.Refused() {
				through.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 5, through.Load())
	n, err := failures.Recent(ctx, app.Key, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 5, n, "a refused attempt counts against no limit")

	over, err := failures.Reserve(ctx, visitor)
	require.NoError(t, err)
	require.True(t, over.Refused())
	require.Greater(t, over.Wait, 59*time.Minute)

	require.NoError(t, failures.Clear(ctx, visitor.Key))
	res, err := failures.Reserve(ctx, visitor, app)
	require.NoError(t, err)
	require.False(t, res.Refused())
	require.Len(t, res.Held, 2)
	require.NoError(t, failures.Release(ctx, res))
	n, err = failures.Recent(ctx, app.Key, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 5, n, "released")
}
