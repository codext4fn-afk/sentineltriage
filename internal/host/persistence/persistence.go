// Package persistence audits Linux persistence mechanisms by reading system
// configuration files only: the dynamic-linker preload list, cron tables, and
// systemd unit and timer files. It never inspects other processes' memory or
// environment; its inputs are on-disk configuration an administrator can read
// and reason about.
//
// All reads go through an fs.FS so the collector is unit-testable on any OS
// against a synthetic tree; the live root is injected per platform via build
// tags.
package persistence

import (
	"context"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// maxFileBytes caps any single config read; these files are small, and the cap
// stops a symlinked device or a tampered multi-gigabyte file from stalling the
// collector.
const maxFileBytes = 1 << 20

// Collector audits persistence configuration under its root.
type Collector struct {
	root        fs.FS
	unsupported bool
}

// FromFS builds a collector over an arbitrary filesystem root, used by tests
// and by the per-platform constructors.
func FromFS(root fs.FS) *Collector { return &Collector{root: root} }

// Unsupported returns a collector that reports the platform gap at run time.
func Unsupported() *Collector { return &Collector{unsupported: true} }

// Name implements engine.Collector.
func (c *Collector) Name() string { return "host.persistence" }

// Engine implements engine.Collector.
func (c *Collector) Engine() finding.Engine { return finding.EngineHost }

// tempExec flags commands that run from world-writable staging directories, a
// recurring trait of persistence implants.
var tempExec = regexp.MustCompile(`(^|[\s=:"'])(/tmp/|/dev/shm/|/var/tmp/)`)

// Run implements engine.Collector. Each probe is independent: a permission
// error on one path is recorded as a coverage gap and the audit proceeds, so a
// non-root run still reports everything it can read.
func (c *Collector) Run(ctx context.Context, sink engine.Sink) error {
	if c.unsupported {
		return engine.ErrUnsupported
	}
	for _, probe := range []func(context.Context, engine.Sink){
		c.checkPreload,
		c.checkCron,
		c.checkSystemd,
	} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		probe(ctx, sink)
	}
	return ctx.Err()
}

// checkPreload treats a non-empty /etc/ld.so.preload as high signal: it forces
// a shared object into every dynamically linked process and is a canonical
// userland-rootkit persistence and hooking mechanism.
func (c *Collector) checkPreload(_ context.Context, sink engine.Sink) {
	const path = "etc/ld.so.preload"
	data, _, err := c.read(path)
	if degraded(sink, path, err) || data == nil {
		return
	}
	for _, line := range nonEmptyLines(string(data)) {
		sink.Emit(finding.Finding{
			RuleID:      "host.persistence.ld-preload",
			Title:       "Library injected globally via /etc/ld.so.preload",
			Severity:    finding.SeverityHigh,
			Confidence:  finding.ConfidenceMedium,
			Techniques:  []string{"T1574.006"},
			Location:    finding.Location{Path: "/" + path, Artifact: line},
			Evidence:    map[string]string{"preloaded": line},
			Remediation: "Confirm this library is expected. /etc/ld.so.preload loads a shared object into every process and is frequently used by userland rootkits; an unexplained entry warrants investigation.",
		})
	}
}

// checkCron scans the system crontab and drop-in directory for jobs that
// execute from world-writable staging paths.
func (c *Collector) checkCron(ctx context.Context, sink engine.Sink) {
	paths := append([]string{"etc/crontab"}, c.glob("etc/cron.d/*")...)
	for _, p := range paths {
		if ctx.Err() != nil {
			return
		}
		data, info, err := c.read(p)
		if degraded(sink, p, err) || data == nil {
			continue
		}
		if info != nil && worldWritable(info) {
			sink.Emit(mkFile("host.persistence.cron-writable",
				"Cron file is writable by non-owners",
				finding.SeverityMedium, finding.ConfidenceHigh, "T1053.003", p,
				"Restrict this cron file to root ownership and 0644 (or stricter); a writable schedule lets any local user run code as its configured user."))
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if tempExec.MatchString(line) {
				sink.Emit(mkLine("host.persistence.cron-temp-exec",
					"Cron job executes from a world-writable directory",
					finding.SeverityMedium, finding.ConfidenceMedium, "T1053.003", p, i+1, clip(line),
					"Cron jobs should run vetted binaries from controlled paths; execution from /tmp, /var/tmp, or /dev/shm is a common persistence-staging pattern."))
			}
		}
	}
}

// checkSystemd scans system unit and timer files for staging-path execution
// and weak permissions.
func (c *Collector) checkSystemd(ctx context.Context, sink engine.Sink) {
	units := c.glob("etc/systemd/system/*.service")
	timers := c.glob("etc/systemd/system/*.timer")
	for _, p := range append(units, timers...) {
		if ctx.Err() != nil {
			return
		}
		data, info, err := c.read(p)
		if degraded(sink, p, err) || data == nil {
			continue
		}
		isTimer := strings.HasSuffix(p, ".timer")
		technique := "T1543.002"
		if isTimer {
			technique = "T1053.006"
		}
		if info != nil && worldWritable(info) {
			sink.Emit(mkFile("host.persistence.unit-writable",
				"systemd unit file is writable by non-owners",
				finding.SeverityMedium, finding.ConfidenceHigh, technique, p,
				"Restrict the unit file to root ownership and 0644; a writable unit lets a local user alter what runs at boot or on a timer."))
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "Exec") {
				continue
			}
			if tempExec.MatchString(trimmed) {
				sink.Emit(mkLine("host.persistence.unit-temp-exec",
					"systemd unit executes from a world-writable directory",
					finding.SeverityMedium, finding.ConfidenceMedium, technique, p, i+1, clip(trimmed),
					"A unit whose ExecStart runs from /tmp, /var/tmp, or /dev/shm is atypical and a known persistence-staging pattern; confirm the unit is legitimate."))
			}
		}
	}
}

// --- fs helpers ---

func (c *Collector) read(path string) ([]byte, fs.FileInfo, error) {
	f, err := c.root.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, _ := f.Stat()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes))
	if err != nil {
		return nil, info, err
	}
	return data, info, nil
}

func (c *Collector) glob(pattern string) []string {
	m, err := fs.Glob(c.root, pattern)
	if err != nil {
		return nil
	}
	sort.Strings(m)
	return m
}

// degraded converts a read error into a coverage record. A missing file is
// normal (the mechanism is simply not configured) and is neither a finding nor
// a gap. Returns true when the caller should stop processing this path.
func degraded(sink engine.Sink, path string, err error) bool {
	if err == nil {
		return false
	}
	if d, ok := engine.DegradationFor("/"+path, err); ok {
		sink.Degrade(d)
	}
	return true
}

func worldWritable(info fs.FileInfo) bool {
	// Group- or other-writable: anyone outside the owner can tamper.
	return info.Mode().Perm()&0o022 != 0
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func clip(s string) string {
	const max = 160
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func mkFile(rule, title string, sev finding.Severity, conf finding.Confidence, tech, path, fix string) finding.Finding {
	return finding.Finding{
		RuleID: rule, Title: title, Severity: sev, Confidence: conf,
		Techniques: []string{tech}, Location: finding.Location{Path: "/" + path},
		Remediation: fix,
	}
}

func mkLine(rule, title string, sev finding.Severity, conf finding.Confidence, tech, path string, line int, evidence, fix string) finding.Finding {
	f := mkFile(rule, title, sev, conf, tech, path, fix)
	f.Location.StartLine = line
	f.Evidence = map[string]string{"command": evidence}
	return f
}
