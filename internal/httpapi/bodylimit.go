package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/trypando/pando/internal/errs"
)

// Limits on a request body sent to the API (R-411). Generous for what the API
// takes — a spec with every config file it carries, a detection answer, a
// sign-in — and bounded, so one request cannot make the server allocate
// without limit or hold a goroutine by sending its body slowly. A route that
// takes more (a source upload, a git host's webhook) raises them for itself
// with allowBody, and enforces its own cap.
const defaultBodyLimit = 8 << 20

// bodyIdleTimeout is how long a body may go without a byte arriving, and
// bodyTotalTimeout how long the whole of a default-sized one may take (R-411).
// Variables only so a test need not wait minutes.
var (
	bodyIdleTimeout  = time.Minute
	bodyTotalTimeout = 5 * time.Minute
)

// boundedBody is a request body held to a size and to read deadlines. The
// deadlines are set on the connection only while the body is being read, and
// cleared when it has been, so a response that streams for a long time — the
// deploy log's events, a log follow — is never cut by them; a GET has no body
// and never sets one.
type boundedBody struct {
	body io.ReadCloser
	rc   *http.ResponseController

	mu      sync.Mutex
	limit   int64
	total   time.Duration // zero: no deadline on the whole body
	raised  bool
	started time.Time
	read    int64
	over    bool
	ended   bool
	failed  error // what every read answers once the body has ended
}

type boundedBodyKey struct{}

// boundBodies holds every request body under /api/v1 to defaultBodyLimit and
// the read deadlines above.
func boundBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		b := &boundedBody{
			body: r.Body, rc: http.NewResponseController(w),
			limit: defaultBodyLimit, total: bodyTotalTimeout,
		}
		r = r.WithContext(context.WithValue(r.Context(), boundedBodyKey{}, b))
		r.Body = b
		defer b.end()
		next.ServeHTTP(w, r)
	})
}

// allowBody raises a request's body limit to limit, for a route that takes
// more than the default and checks its own cap. total is how long the whole
// body may take; zero leaves only the idle deadline, for a large upload on a
// slow link. Ignored once the body is being read.
func allowBody(r *http.Request, limit int64, total time.Duration) {
	b, ok := r.Context().Value(boundedBodyKey{}).(*boundedBody)
	if !ok {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started.IsZero() {
		b.limit, b.total, b.raised = limit, total, true
	}
}

// bodyTooLarge is the error for a body over the default limit, or nil when
// the request's body was not refused for its size.
func bodyTooLarge(r *http.Request) error {
	b, ok := r.Context().Value(boundedBodyKey{}).(*boundedBody)
	if !ok {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.over || b.raised {
		return nil
	}
	return errs.Newf(errs.ValidInvalid,
		"The request body is larger than %d MB, which is the most Pando accepts for this request.", defaultBodyLimit>>20).
		WithRemedy("Send a smaller body. A source directory is sent to POST /api/v1/apps/{appID}/source, which accepts more.")
}

func (b *boundedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.ended {
		err := b.failed
		b.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}
	if b.started.IsZero() {
		b.started = time.Now()
	}
	if left := b.limit - b.read; int64(len(p)) > left {
		// One byte past the limit, so a body exactly at it still reads EOF.
		p = p[:left+1]
	}
	deadline := time.Now().Add(bodyIdleTimeout)
	if b.total > 0 {
		deadline = minTime(deadline, b.started.Add(b.total))
	}
	b.mu.Unlock()

	_ = b.rc.SetReadDeadline(deadline)
	n, err := b.body.Read(p)

	b.mu.Lock()
	b.read += int64(n)
	if b.read > b.limit {
		b.over = true
		n -= int(b.read - b.limit)
		b.read = b.limit
		err = &http.MaxBytesError{Limit: b.limit}
	}
	b.mu.Unlock()
	if err != nil {
		b.endWith(err)
	}
	return n, err
}

func (b *boundedBody) Close() error {
	b.end()
	return b.body.Close()
}

// end clears the read deadline once the body is done with: read to its end,
// refused, failed, closed, or the handler returned.
func (b *boundedBody) end() { b.endWith(nil) }

func (b *boundedBody) endWith(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ended {
		return
	}
	b.ended = true
	if !errors.Is(err, io.EOF) {
		b.failed = err
	}
	if !b.started.IsZero() {
		_ = b.rc.SetReadDeadline(time.Time{})
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
