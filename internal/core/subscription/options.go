package subscription

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/trypando/pando/internal/adapter/api"
	"github.com/trypando/pando/internal/core/state"
	"github.com/trypando/pando/internal/errs"
)

// How a webhook is sent, for a receiver that expects a particular request
// (R-375): its method, content type, headers of its own, and a body template.

// Limits on what a subscription may ask for [P].
const (
	maxHeaders      = 20
	maxHeaderValue  = 4096
	maxTemplate     = 16 << 10
	maxRenderedBody = 256 << 10

	// maxTemplateSteps is how many loop iterations and template calls one
	// rendering may make, and maxTemplateTime how long it may run. A body
	// built from an event's fields takes a few dozen steps; a template asking
	// for more is a loop with no bound, which would hold a core for as long
	// as it ran and could not be canceled.
	maxTemplateSteps = 10_000
	maxTemplateTime  = time.Second
)

var methods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

// headerName is RFC 9110's token: what an HTTP field name may be.
var headerName = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

// reservedHeaders are set by Pando or by the transport, and a subscription
// may not set them: a forged Pando-Signature would defeat the signature, and
// the rest describe the request the transport is making.
var reservedHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "transfer-encoding": true,
	"connection": true, "keep-alive": true, "te": true, "trailer": true, "upgrade": true,
	"proxy-authorization": true, "proxy-connection": true, "user-agent": true,
}

// checkHeaders validates custom headers and returns their names, sorted, in
// their canonical spelling.
func checkHeaders(headers map[string]string) ([]string, map[string]string, error) {
	if len(headers) > maxHeaders {
		return nil, nil, errs.Newf(errs.ValidInvalid, "A webhook may have at most %d headers of its own.", maxHeaders)
	}
	out := make(map[string]string, len(headers))
	names := make([]string, 0, len(headers))
	for name, value := range headers {
		name = strings.TrimSpace(name)
		if !headerName.MatchString(name) {
			return nil, nil, errs.Newf(errs.ValidInvalid,
				"%q is not a header name. Use letters, digits and hyphens, such as Authorization or X-Api-Key.", name)
		}
		lower := strings.ToLower(name)
		if reservedHeaders[lower] || strings.HasPrefix(lower, "pando-") {
			return nil, nil, errs.Newf(errs.ValidInvalid,
				"Pando sets the %s header itself, so a webhook cannot. Choose the content type with content_type; Pando-* headers carry the event and its signature.", name)
		}
		if strings.ContainsAny(value, "\r\n") || len(value) > maxHeaderValue {
			return nil, nil, errs.Newf(errs.ValidInvalid,
				"The value of the %s header must be one line of at most %d characters.", name, maxHeaderValue)
		}
		canonical := httpCanonical(name)
		if _, dup := out[canonical]; dup {
			return nil, nil, errs.Newf(errs.ValidInvalid, "The %s header is given twice.", canonical)
		}
		out[canonical] = value
		names = append(names, canonical)
	}
	sort.Strings(names)
	return names, out, nil
}

func httpCanonical(name string) string {
	parts := strings.Split(strings.ToLower(name), "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func checkMethod(method string) (string, error) {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		return "POST", nil
	}
	if !methods[m] {
		return "", errs.Newf(errs.ValidInvalid, "%q is not a method a webhook can use. Valid answers: POST, PUT or PATCH.", method)
	}
	return m, nil
}

func checkContentType(ct string) (string, error) {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return "application/json", nil
	}
	if strings.ContainsAny(ct, "\r\n") || !strings.Contains(ct, "/") {
		return "", errs.Newf(errs.ValidInvalid,
			"%q is not a content type. Use one such as application/json or application/x-www-form-urlencoded.", ct)
	}
	return ct, nil
}

// TemplateData is what a body template is given: the event as the envelope
// carries it, and the same event described for a person.
//
//	{"text": {{json .Subject}}, "url": {{json .Link}}}
//	{{.Type}} on {{.App.Name}}: {{index .Data "error_code"}}
type TemplateData struct {
	ID         string
	Type       string
	OccurredAt time.Time
	App        EnvelopeApp
	Actor      Actor
	Data       map[string]any

	// Subject, Body and Fields are the event as a notification describes it.
	Subject string
	Body    string
	Fields  []api.NotificationField
	Link    string

	// Envelope is Pando's own body, for a template that wraps it.
	Envelope Envelope
}

var templateFuncs = template.FuncMap{
	// json renders a value as JSON: a string quoted and escaped, which is how
	// a value goes into a JSON body safely.
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	// default is its second argument unless that is empty.
	"default": func(fallback, v any) any {
		if v == nil || v == "" {
			return fallback
		}
		return v
	},
}

// tickFunc is the function a rendering's budget is counted through: parsed
// templates have a call to it put at the top of every loop body and every
// template, so neither can run without being counted.
const tickFunc = "pandoStep"

// parseTemplate reads a body template and refuses one whose running time has
// no bound in the text itself: a range over a number, and a template that
// calls itself, directly or through another. What remains is bounded by the
// event it is given and by the step budget render enforces.
func parseTemplate(text string) (*template.Template, error) {
	funcs := template.FuncMap{tickFunc: func() (string, error) { return "", nil }}
	for name, f := range templateFuncs {
		funcs[name] = f
	}
	t, err := template.New("payload").Funcs(funcs).Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, err
	}
	calls := map[string][]string{}
	for _, tmpl := range t.Templates() {
		if tmpl.Tree == nil || tmpl.Root == nil {
			continue
		}
		if err := bound(tmpl.Root, tmpl.Name(), calls); err != nil {
			return nil, err
		}
	}
	if name := recursive(calls); name != "" {
		return nil, fmt.Errorf("the template %q calls itself, which could run without end", name)
	}
	for _, tmpl := range t.Templates() {
		if tmpl.Tree != nil && tmpl.Root != nil {
			tmpl.Root.Nodes = append([]parse.Node{tick()}, tmpl.Root.Nodes...)
		}
	}
	return t, nil
}

// bound walks a template's nodes, refusing a range over a number, recording
// which templates it calls, and counting each loop body as a step.
func bound(n parse.Node, in string, calls map[string][]string) error {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := bound(c, in, calls); err != nil {
				return err
			}
		}
	case *parse.RangeNode:
		if rangesOverNumber(n.Pipe) {
			return fmt.Errorf("{{range %s}} ranges over a number; a template may range only over the event's values, such as {{range .Fields}}", n.Pipe)
		}
		if n.List != nil {
			n.List.Nodes = append([]parse.Node{tick()}, n.List.Nodes...)
		}
		return boundBranch(n.List, n.ElseList, in, calls)
	case *parse.IfNode:
		return boundBranch(n.List, n.ElseList, in, calls)
	case *parse.WithNode:
		return boundBranch(n.List, n.ElseList, in, calls)
	case *parse.TemplateNode:
		calls[in] = append(calls[in], n.Name)
	}
	return nil
}

func boundBranch(list, elseList *parse.ListNode, in string, calls map[string][]string) error {
	if err := bound(list, in, calls); err != nil {
		return err
	}
	return bound(elseList, in, calls)
}

// rangesOverNumber reports whether a range's pipeline is, or ends in, a
// number: a literal, or a function such as len whose result is one.
func rangesOverNumber(pipe *parse.PipeNode) bool {
	if pipe == nil || len(pipe.Cmds) == 0 {
		return false
	}
	last := pipe.Cmds[len(pipe.Cmds)-1]
	if len(last.Args) == 0 {
		return false
	}
	switch a := last.Args[0].(type) {
	case *parse.NumberNode:
		return true
	case *parse.IdentifierNode:
		return a.Ident == "len"
	case *parse.PipeNode:
		return rangesOverNumber(a)
	}
	return false
}

// recursive names a template that reaches itself through calls, or "".
func recursive(calls map[string][]string) string {
	const (
		unvisited = iota
		visiting
		done
	)
	state := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		switch state[name] {
		case visiting:
			return true
		case done:
			return false
		}
		state[name] = visiting
		for _, next := range calls[name] {
			if visit(next) {
				return true
			}
		}
		state[name] = done
		return false
	}
	names := make([]string, 0, len(calls))
	for name := range calls {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if state[name] == unvisited && visit(name) {
			return name
		}
	}
	return ""
}

// tick is a call to the step budget.
func tick() parse.Node {
	return &parse.ActionNode{NodeType: parse.NodeAction, Pipe: &parse.PipeNode{
		NodeType: parse.NodePipe,
		Cmds: []*parse.CommandNode{{
			NodeType: parse.NodeCommand,
			Args:     []parse.Node{parse.NewIdentifier(tickFunc)},
		}},
	}}
}

// budget is one rendering's allowance of steps and time.
type budget struct {
	steps    int
	deadline time.Time
}

func (b *budget) step() (string, error) {
	b.steps++
	if b.steps > maxTemplateSteps {
		return "", fmt.Errorf("the template took more than %d steps; loop only over the event's values", maxTemplateSteps)
	}
	if time.Now().After(b.deadline) {
		return "", fmt.Errorf("the template took longer than %s to render", maxTemplateTime)
	}
	return "", nil
}

// checkTemplate parses a body template and renders it for a sample event, so
// a mistake is found when the subscription is saved rather than in its
// delivery log. A JSON content type needs the result to be JSON.
func checkTemplate(text, contentType string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if len(text) > maxTemplate {
		return errs.Newf(errs.ValidInvalid, "A body template may be at most %d characters.", maxTemplate)
	}
	t, err := parseTemplate(text)
	if err != nil {
		return errs.New(errs.ValidInvalid, "The body template could not be read: "+err.Error()).
			WithRemedy("Templates use Go template syntax, such as {\"text\": {{json .Subject}}}. docs/events.md lists what a template is given.")
	}
	sample := state.Event{
		ID: "evt_sample", Name: "deploy.failed", AppID: "app_sample", ActorKind: "system",
		Data:       map[string]any{"error_code": "BUILD_FAILED", "message": "The build exited with status 1."},
		OccurredAt: time.Now().UTC(),
	}
	body, err := render(t, sample, &EnvelopeApp{ID: "app_sample", Name: "Sample", Slug: "sample"}, "")
	if err != nil {
		return errs.New(errs.ValidInvalid, "The body template could not be rendered for a sample event: "+err.Error())
	}
	if isJSON(contentType) && !json.Valid(body) {
		return errs.New(errs.ValidInvalid,
			"The body template does not produce JSON, and the content type is "+contentType+". "+
				"Put a value in with json, such as {\"text\": {{json .Subject}}}, or choose another content type.")
	}
	return nil
}

func isJSON(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "application/json") || strings.Contains(ct, "+json")
}

// render produces a delivery's body from a template.
func render(t *template.Template, e state.Event, app *EnvelopeApp, link string) ([]byte, error) {
	n := Describe(e, app)
	data := TemplateData{
		ID: e.ID, Type: e.Name, OccurredAt: e.OccurredAt.UTC(),
		Actor: Actor{Kind: e.ActorKind, ID: e.ActorID, OnBehalfOf: e.OnBehalfOf},
		Data:  e.Data, Subject: n.Subject, Body: n.Body, Fields: n.Fields, Link: link,
		Envelope: envelopeOf(e, app, link),
	}
	if app != nil {
		data.App = *app
	}
	if data.Data == nil {
		data.Data = map[string]any{}
	}
	b := &budget{deadline: time.Now().Add(maxTemplateTime)}
	t = t.Funcs(template.FuncMap{tickFunc: b.step})
	var buf bytes.Buffer
	if err := t.Execute(&limitWriter{w: &buf, left: maxRenderedBody}, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// limitWriter stops a template that would render an unbounded body.
type limitWriter struct {
	w    *bytes.Buffer
	left int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, fmt.Errorf("the body would be larger than %d bytes", maxRenderedBody)
	}
	l.left -= len(p)
	return l.w.Write(p)
}

// bodyFor is a delivery's body: the subscription's template, or the envelope.
func bodyFor(sub state.Subscription, e state.Event, app *EnvelopeApp, link string) ([]byte, error) {
	if strings.TrimSpace(sub.PayloadTemplate) == "" {
		return jsonMarshal(envelopeOf(e, app, link))
	}
	t, err := parseTemplate(sub.PayloadTemplate)
	if err != nil {
		return nil, sentence("The body template could not be read: " + err.Error())
	}
	body, err := render(t, e, app, link)
	if err != nil {
		return nil, sentence("The body template could not be rendered for this event: " + err.Error())
	}
	return body, nil
}
