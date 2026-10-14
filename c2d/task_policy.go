// task_policy.go — the authorization plane, PORTED from the Python control
// plane (phantom/core/task_policy.py).
//
// Why porting was the only honest option: POST /api/v1/queue is a remote
// task-injection primitive. Guarded by mTLS + the operator token alone, the Go
// data plane could push ANY command to any enrolled beacon — verbs an
// operator's grant manifest excludes, and free-form `shell <cmd>` — while the
// Python listener refused exactly that. "The policy lives in Python" is a fair
// sentence and a bad security boundary, because c2d exists to be the FIELD
// deployment (a static binary instead of a venv), and the field is where the
// queue is reachable from more than the operator's laptop.
//
// The port keeps the Python semantics verb for verb, including the audit
// vocabulary, so the two backends cannot disagree about what a beacon may be
// asked to do. Three copies of the verb list now exist BY DESIGN — this one,
// phantom/core/task_policy.py and the dispatcher in payloads/beacon/src/
// main.cpp — and `scripts/c2d_parity_check.py` plus tests/test_beacon_verb_
// contract.py pin all three together.
package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxTaskArgs    = 8
	maxTaskArgLen  = 4096
	maxLegacyBytes = 8192
)

// BeaconVerbs is the beacon's dispatch surface — the SAME list the Python
// control plane allows and the C++ dispatcher implements.
var BeaconVerbs = []string{
	"audio", "auth-rotate", "browser-list", "browser-pivot",
	"browser-pivot-stop", "bt-scan", "bt-scan-json", "camera", "cat",
	"cd", "cd..", "cdp-cookies", "cdp-eval", "cdp-fetch", "cdp-launch",
	"cdp-nav", "cookies", "cookies-json", "dir", "download", "drives",
	"edr-kill", "edrcheck", "exec", "exit", "find", "gps", "health",
	"inject", "inject-eb", "inject-tl", "keylog", "kill", "ls",
	"mem-run", "migrate", "netinfo", "netstat", "netstat-json", "persist",
	"portfwd", "portfwd-stop", "processes", "pwd", "recon", "remote",
	"run", "screen-dump", "screen-record", "screen-record-live",
	"screen-stream", "screen-stream-stop", "screenshot", "set-sleep",
	"shell", "sleep", "smb-pipe", "smb-pipe-stop", "socks", "socks-stop",
	"sysinfo", "unpersist", "upload", "whoami", "wlan-locate",
	"wlan-scan",
}

// HighImpactVerbs execute attacker-controlled code on the target; a grant set
// can exclude them without touching anything else.
var HighImpactVerbs = []string{
	"edr-kill", "exec", "inject", "inject-eb", "inject-tl", "mem-run",
	"migrate", "run", "shell",
}

var beaconVerbSet = func() map[string]bool {
	out := make(map[string]bool, len(BeaconVerbs))
	for _, verb := range BeaconVerbs {
		out[verb] = true
	}
	return out
}()

var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// TypedTask is the structured task form: a grant key plus typed args.
type TypedTask struct {
	CapabilityID string
	Args         []string
	ScopeRef     string
	ExpiresAt    float64 // epoch seconds; 0 = no expiry
	TaskID       string
	PolicyHash   string
}

// Render is the wire form the beacon consumes (verb + args).
func (t TypedTask) Render() string {
	parts := []string{t.CapabilityID}
	for _, a := range t.Args {
		if a != "" {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

// Expired mirrors TypedTask.is_expired: no deadline is not expired, and a
// deadline in the past is. The caller passes the clock so tests are stable.
func (t TypedTask) Expired(now float64) bool {
	if t.ExpiresAt == 0 {
		return false
	}
	return now > t.ExpiresAt
}

// PolicyDecision is one verdict, with the SAME mode/reason vocabulary the
// Python side audits.
type PolicyDecision struct {
	Allowed bool
	Reason  string
	Mode    string // typed | legacy | typed-denied | legacy-denied
	Command string
}

// TaskPolicy is the per-beacon grant table. Deny-by-default once a manifest
// exists; legacy-open until the operator narrows it (the documented upgrade
// behaviour, preserved so no engagement breaks on a backend switch).
type TaskPolicy struct {
	grants map[string]map[string]bool
}

// NewTaskPolicy returns an empty (legacy-open) policy.
func NewTaskPolicy() *TaskPolicy {
	return &TaskPolicy{grants: map[string]map[string]bool{}}
}

// NewTaskPolicyFromEnv seeds per-beacon manifests from
// PHANTOM_BEACON_GRANTS="<id>:verb,verb;<id>:verb" and CONSUMES the variable,
// exactly like policy() in Python (a second read must not re-apply it).
func NewTaskPolicyFromEnv() *TaskPolicy {
	p := NewTaskPolicy()
	spec := strings.TrimSpace(os.Getenv("PHANTOM_BEACON_GRANTS"))
	if spec == "" {
		return p
	}
	for _, part := range strings.Split(spec, ";") {
		if !strings.Contains(part, ":") {
			continue
		}
		bits := strings.SplitN(part, ":", 2)
		var verbs []string
		for _, v := range strings.Split(bits[1], ",") {
			if v = strings.TrimSpace(v); v != "" {
				verbs = append(verbs, v)
			}
		}
		p.SetGrants(strings.TrimSpace(bits[0]), verbs)
	}
	os.Unsetenv("PHANTOM_BEACON_GRANTS")
	return p
}

// SetGrants restricts a beacon to an explicit capability manifest.
func (p *TaskPolicy) SetGrants(beaconID string, grants []string) {
	clean := map[string]bool{}
	for _, g := range grants {
		if g = strings.TrimSpace(g); g != "" {
			clean[g] = true
		}
	}
	p.grants[beaconID] = clean
}

// ClearGrants returns a beacon to the legacy-open default.
func (p *TaskPolicy) ClearGrants(beaconID string) {
	delete(p.grants, beaconID)
}

// Grants reports the manifest for a beacon (sorted, for the operator API).
func (p *TaskPolicy) Grants(beaconID string) ([]string, bool) {
	g, ok := p.grants[beaconID]
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(g))
	for k := range g {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, true
}

// authorized: no manifest means legacy-open. "shell" grants the OS-execution
// verb as a whole; a "shell <cmd>" key needs the "shell" grant.
func (p *TaskPolicy) authorized(beaconID, key string) bool {
	g, ok := p.grants[beaconID]
	if !ok {
		return true
	}
	if g[key] {
		return true
	}
	if strings.HasPrefix(key, "shell ") {
		return g["shell"]
	}
	return false
}

// CheckTyped validates the structured form.
func (p *TaskPolicy) CheckTyped(beaconID string, task TypedTask, now float64) PolicyDecision {
	if task.Expired(now) {
		return PolicyDecision{Reason: "task expired", Mode: "typed-denied"}
	}
	if task.CapabilityID == "" {
		return PolicyDecision{Reason: "missing capability_id", Mode: "typed-denied"}
	}
	if !p.authorized(beaconID, task.CapabilityID) {
		return PolicyDecision{
			Reason: "capability '" + task.CapabilityID + "' not granted for beacon " + beaconID,
			Mode:   "typed-denied"}
	}
	if len(task.Args) > maxTaskArgs {
		return PolicyDecision{Reason: "too many args", Mode: "typed-denied"}
	}
	for _, a := range task.Args {
		if len(a) > maxTaskArgLen {
			return PolicyDecision{Reason: "invalid arg", Mode: "typed-denied"}
		}
	}
	return PolicyDecision{Allowed: true, Reason: "ok", Mode: "typed",
		Command: task.Render()}
}

// CheckLegacy is the explicit compatibility adapter for string tasks: the
// first token must be a verb the beacon dispatches, and free-form OS commands
// ride only the `shell` verb (which grants can revoke).
func (p *TaskPolicy) CheckLegacy(beaconID, command string) PolicyDecision {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return PolicyDecision{Reason: "empty command", Mode: "legacy-denied"}
	}
	if len(cmd) > maxLegacyBytes {
		return PolicyDecision{Reason: "command too long", Mode: "legacy-denied"}
	}
	verb := cmd
	if idx := strings.IndexAny(cmd, " \t\n"); idx >= 0 {
		verb = cmd[:idx]
	}
	if !beaconVerbSet[verb] {
		return PolicyDecision{
			Reason: "unknown beacon verb '" + verb + "' — wrap OS commands as 'shell <cmd>'",
			Mode:   "legacy-denied"}
	}
	if !p.authorized(beaconID, verb) {
		return PolicyDecision{
			Reason: "verb '" + verb + "' not granted for beacon " + beaconID,
			Mode:   "legacy-denied"}
	}
	return PolicyDecision{Allowed: true, Reason: "ok", Mode: "legacy", Command: cmd}
}

// CheckCommand routes one queued string through the policy. It is the single
// entry point the HTTP handler uses, so no route can forget the check.
func (p *TaskPolicy) CheckCommand(beaconID, command string) PolicyDecision {
	return p.CheckLegacy(beaconID, command)
}

// ValidTaskID mirrors _TASK_ID_OK in the Python policy. An EMPTY id is valid:
// the queue mints one. A supplied id must be short and boring, because it
// comes back on the wire and lands in the audit record.
func ValidTaskID(id string) bool {
	return id == "" || taskIDPattern.MatchString(id)
}

// nowSeconds is the clock the policy compares deadlines against.
func nowSeconds() float64 { return float64(time.Now().Unix()) }
