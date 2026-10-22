package subscription

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trypando/pando/internal/core/state"
)

// TestR375_ABodyTemplateCannotRunWithoutBound asserts that a webhook's body
// template, which any app viewer may save, cannot hold a core: a range over a
// number and a template that calls itself are refused when saved, and a
// rendering that loops past its step budget stops with an error, at save
// time and at delivery.
func TestR375_ABodyTemplateCannotRunWithoutBound(t *testing.T) {
	for _, text := range []string{
		`{{range 100000}}{{range 100000}}{{end}}{{end}}`,
		`{{range $i := 5}}x{{end}}`,
		`{{range len .Fields}}x{{end}}`,
		`{{range (100)}}x{{end}}`,
		`{{define "a"}}{{template "a" .}}{{end}}{{template "a" .}}`,
		`{{define "a"}}{{template "b" .}}{{end}}{{define "b"}}{{template "a" .}}{{end}}{{template "a" .}}`,
	} {
		start := time.Now()
		err := checkTemplate(text, "text/plain")
		require.Error(t, err, text)
		require.Less(t, time.Since(start), time.Second, text)
	}

	// A number kept in a variable gets past the reading, and the budget stops it.
	looping := `{{$n := 100000}}{{range $n}}{{range $n}}{{end}}{{end}}`
	start := time.Now()
	err := checkTemplate(looping, "text/plain")
	require.ErrorContains(t, err, "steps")
	require.Less(t, time.Since(start), 2*time.Second)

	sub := state.Subscription{PayloadTemplate: looping}
	_, err = bodyFor(sub, state.Event{ID: "evt_1", Name: "deploy.failed"}, nil, "")
	require.ErrorContains(t, err, "steps")

	// Calls between templates that end are fine, and each is counted.
	chain := `{{define "a"}}{{template "b" .}}{{template "b" .}}{{end}}{{define "b"}}{{.Type}}{{end}}{{template "a" .}}`
	require.NoError(t, checkTemplate(chain, "text/plain"))
}

// TestR375_OrdinaryBodyTemplatesStillRender asserts the bounds leave a
// template built from the event's own values working: loops over fields and
// data, conditionals, with, and the json and default functions.
func TestR375_OrdinaryBodyTemplatesStillRender(t *testing.T) {
	text := `{"text": {{json .Subject}}, "fields": [{{range $i, $f := .Fields}}{{if $i}},{{end}}{{json $f.Label}}{{end}}],` +
		` "data": { {{range $k, $v := .Data}}{{json $k}}: {{json $v}}, {{end}}"app": {{with .App}}{{json .Name}}{{else}}""{{end}} },` +
		` "who": {{json (default "system" .Actor.ID)}} }`
	require.NoError(t, checkTemplate(text, "application/json"))

	body, err := bodyFor(state.Subscription{PayloadTemplate: text},
		state.Event{ID: "evt_1", Name: "deploy.failed", Data: map[string]any{"error_code": "X"}},
		&EnvelopeApp{ID: "app_1", Name: "Notes", Slug: "notes"}, "")
	require.NoError(t, err)
	require.Contains(t, string(body), `"Notes"`)
	require.Contains(t, string(body), `"error_code": "X"`)
}

// TestR375_TheBudgetCountsStepsAndTime asserts both halves of a rendering's
// budget.
func TestR375_TheBudgetCountsStepsAndTime(t *testing.T) {
	b := &budget{deadline: time.Now().Add(time.Hour)}
	for range maxTemplateSteps {
		_, err := b.step()
		require.NoError(t, err)
	}
	_, err := b.step()
	require.ErrorContains(t, err, "steps")

	late := &budget{deadline: time.Now().Add(-time.Second)}
	_, err = late.step()
	require.ErrorContains(t, err, "longer than")
}
