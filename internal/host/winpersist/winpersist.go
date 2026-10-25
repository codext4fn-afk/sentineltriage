// Package winpersist audits Windows autostart locations: registry Run keys,
// Winlogon values, Startup folders, scheduled task definitions, and service
// registrations. It reads configuration only, in the spirit of Sysinternals
// Autoruns, and reports entries whose launch command matches well-known abuse
// patterns rather than inventorying every autostart.
//
// Collection is behind the Source interface. The analysis in this file is
// portable and unit-tested on every OS against a fake source; the live
// registry and filesystem source is built only on Windows.
package winpersist

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Autorun is one value under a Run-style registry key.
type Autorun struct {
	Key     string // display path, e.g. HKLM\Software\Microsoft\Windows\CurrentVersion\Run
	Name    string
	Command string
}

// RegValue is a single named registry value, used for Winlogon.
type RegValue struct {
	Key   string
	Name  string
	Value string
}

// StartupFile is a file found in a per-user or all-users Startup folder.
type StartupFile struct {
	Path string
}

// Task is one Exec action from a scheduled task definition.
type Task struct {
	Name      string // task path as shown by schtasks, e.g. \Vendor\Updater
	File      string // on-disk XML definition
	Command   string
	Arguments string
}

// Service is a Win32 service registration (drivers are excluded by the source).
type Service struct {
	Key       string
	Name      string
	ImagePath string
}

// Gap is a location the source could not read.
type Gap struct {
	Scope string
	Err   error
}

// Source enumerates autostart locations. Implementations return every entry
// they can read plus a Gap for each location they could not; a missing key or
// folder is reported as a Gap wrapping fs.ErrNotExist and is filtered out by
// the collector, since an unconfigured mechanism is not a coverage gap.
type Source interface {
	Autoruns() ([]Autorun, []Gap)
	Winlogon() ([]RegValue, []Gap)
	StartupFiles() ([]StartupFile, []Gap)
	Services() ([]Service, []Gap)
	Tasks(ctx context.Context) ([]Task, []Gap)
}

// Collector implements engine.Collector over a Source.
type Collector struct {
	src Source
}

// FromSource builds a collector over src.
func FromSource(src Source) *Collector { return &Collector{src: src} }

// Name implements engine.Collector.
func (c *Collector) Name() string { return "host.persistence.windows" }

// Engine implements engine.Collector.
func (c *Collector) Engine() finding.Engine { return finding.EngineHost }

// Run implements engine.Collector. Scheduled tasks run last because the task
// store is the only location that requires a directory walk and the one most
// often denied to non-administrators.
func (c *Collector) Run(ctx context.Context, sink engine.Sink) error {
	for _, probe := range []func(context.Context, engine.Sink){
		c.checkAutoruns,
		c.checkWinlogon,
		c.checkStartup,
		c.checkServices,
		c.checkTasks,
	} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		probe(ctx, sink)
	}
	return ctx.Err()
}

func (c *Collector) checkAutoruns(_ context.Context, sink engine.Sink) {
	entries, gaps := c.src.Autoruns()
	degrade(sink, gaps)
	for _, e := range entries {
		v, ok := classifyCommand(e.Command)
		if !ok {
			continue
		}
		sink.Emit(finding.Finding{
			RuleID:     "host.persistence.run-key-suspicious",
			Title:      "Run key entry " + v.reason,
			Severity:   v.severity,
			Confidence: finding.ConfidenceMedium,
			Techniques: append([]string{"T1547.001"}, v.techniques...),
			Location:   finding.Location{Path: e.Key, Artifact: valueName(e.Name)},
			Evidence:   map[string]string{"value": valueName(e.Name), "command": clip(e.Command)},
			Remediation: "Confirm the program is expected to start at logon. Remove the Run value if it is not, " +
				"then locate and investigate the referenced file.",
		})
	}
}

func (c *Collector) checkWinlogon(_ context.Context, sink engine.Sink) {
	values, gaps := c.src.Winlogon()
	degrade(sink, gaps)
	for _, v := range values {
		var expected string
		switch strings.ToLower(v.Name) {
		case "userinit":
			expected = "userinit.exe"
		case "shell":
			expected = "explorer.exe"
		default:
			continue
		}
		if extra := unexpectedEntries(v.Value, expected); len(extra) > 0 {
			sink.Emit(finding.Finding{
				RuleID:     "host.persistence.winlogon-modified",
				Title:      "Winlogon " + v.Name + " launches an additional program",
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceHigh,
				Techniques: []string{"T1547.004"},
				Location:   finding.Location{Path: v.Key, Artifact: v.Name},
				Evidence:   map[string]string{"value": clip(v.Value), "unexpected": clip(strings.Join(extra, ", "))},
				Remediation: "Winlogon " + v.Name + " should reference only " + expected + ". Restore the default " +
					"value and investigate the additional entry.",
			})
		}
	}
}

// startupBenign covers the shortcut and metadata files Windows itself places
// in Startup folders. Anything else is unusual enough to report.
var startupBenign = map[string]bool{".lnk": true, ".url": true, ".ini": true}

var startupScript = map[string]bool{
	".bat": true, ".cmd": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".ps1": true, ".hta": true,
}

func (c *Collector) checkStartup(_ context.Context, sink engine.Sink) {
	files, gaps := c.src.StartupFiles()
	degrade(sink, gaps)
	for _, f := range files {
		ext := strings.ToLower(path.Ext(strings.ReplaceAll(f.Path, `\`, "/")))
		if startupBenign[ext] {
			continue
		}
		conf := finding.ConfidenceLow
		if startupScript[ext] {
			conf = finding.ConfidenceMedium
		}
		sink.Emit(finding.Finding{
			RuleID:     "host.persistence.startup-file",
			Title:      "Startup folder contains a script or executable instead of a shortcut",
			Severity:   finding.SeverityMedium,
			Confidence: conf,
			Techniques: []string{"T1547.001"},
			Location:   finding.Location{Path: f.Path},
			Remediation: "Installers place shortcuts (.lnk) in Startup folders, not scripts or binaries. " +
				"Verify the file's origin and remove it if it is not expected.",
		})
	}
}

func (c *Collector) checkServices(_ context.Context, sink engine.Sink) {
	services, gaps := c.src.Services()
	degrade(sink, gaps)
	for _, s := range services {
		loc := finding.Location{Path: s.Key, Artifact: s.Name}
		if v, ok := classifyCommand(s.ImagePath); ok {
			// Services run as LocalSystem by default, so any of these patterns
			// is at least High.
			sev := max(v.severity, finding.SeverityHigh)
			sink.Emit(finding.Finding{
				RuleID:     "host.persistence.service-suspicious",
				Title:      "Service " + v.reason,
				Severity:   sev,
				Confidence: finding.ConfidenceMedium,
				Techniques: append([]string{"T1543.003"}, v.techniques...),
				Location:   loc,
				Evidence:   map[string]string{"service": s.Name, "image_path": clip(s.ImagePath)},
				Remediation: "Confirm the service is legitimate. Services normally run signed binaries from " +
					"Program Files or System32.",
			})
		}
		if exe, ok := unquotedWithSpace(s.ImagePath); ok {
			sink.Emit(finding.Finding{
				RuleID:     "host.persistence.service-unquoted-path",
				Title:      "Service binary path is unquoted and contains spaces",
				Severity:   finding.SeverityMedium,
				Confidence: finding.ConfidenceLow,
				Techniques: []string{"T1574.009"},
				Location:   loc,
				Evidence:   map[string]string{"service": s.Name, "executable": clip(exe)},
				Remediation: "Quote the executable path in the service ImagePath. Whether this is exploitable " +
					"depends on write access to the intermediate directories.",
			})
		}
	}
}

func (c *Collector) checkTasks(ctx context.Context, sink engine.Sink) {
	tasks, gaps := c.src.Tasks(ctx)
	degrade(sink, gaps)
	for _, t := range tasks {
		cmd := strings.TrimSpace(t.Command + " " + t.Arguments)
		v, ok := classifyCommand(cmd)
		if !ok {
			continue
		}
		sink.Emit(finding.Finding{
			RuleID:     "host.persistence.task-suspicious",
			Title:      "Scheduled task " + v.reason,
			Severity:   v.severity,
			Confidence: finding.ConfidenceMedium,
			Techniques: append([]string{"T1053.005"}, v.techniques...),
			Location:   finding.Location{Path: t.File, Artifact: t.Name},
			Evidence:   map[string]string{"task": t.Name, "command": clip(cmd)},
			Remediation: "Inspect the task with schtasks /query /tn \"" + t.Name + "\" /v and remove it if " +
				"it is not expected.",
		})
	}
}

func degrade(sink engine.Sink, gaps []Gap) {
	for _, g := range gaps {
		if d, ok := engine.DegradationFor(g.Scope, g.Err); ok {
			sink.Degrade(d)
		}
	}
}

// --- command classification ---

type verdict struct {
	reason     string
	severity   finding.Severity
	techniques []string
}

var (
	rePowerShell = regexp.MustCompile(`\b(powershell|pwsh)(\.exe)?\b`)
	// Any unambiguous prefix of -EncodedCommand is accepted by PowerShell.
	rePSEncoded  = regexp.MustCompile(`\s-e(c|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s`)
	rePSHidden   = regexp.MustCompile(`\s-w(i|in|ind|indo|indow|indows|indowst\w*)?\s+h(i|id|idd|idde|idden)?\b`)
	rePSDownload = regexp.MustCompile(`frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|invoke-webrequest|\biwr\b`)
	reMshta      = regexp.MustCompile(`\bmshta(\.exe)?\b`)
	reRegsvr32   = regexp.MustCompile(`\bregsvr32(\.exe)?\b.*(/i:\s*https?:|scrobj\.dll)`)
	reRundll32JS = regexp.MustCompile(`\brundll32(\.exe)?\b.*(javascript:|vbscript:|https?://)`)
	// User-writable staging locations. Program Files, System32, and
	// ProgramData application folders are deliberately absent: they are where
	// legitimate software lives, and flagging them would bury real findings.
	reStaging = regexp.MustCompile(`(\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\\$recycle\.bin\\|%temp%|%tmp%|\\downloads\\)`)
)

// classifyCommand returns the most severe abuse pattern matched by cmd.
func classifyCommand(cmd string) (verdict, bool) {
	c := " " + strings.ToLower(strings.ReplaceAll(cmd, "/", `\`)) + " "
	raw := " " + strings.ToLower(cmd) + " "

	switch {
	case rePowerShell.MatchString(c) && (rePSEncoded.MatchString(raw) || rePSHidden.MatchString(raw) || rePSDownload.MatchString(raw)):
		return verdict{"runs encoded, hidden, or download-and-execute PowerShell", finding.SeverityHigh, []string{"T1059.001"}}, true
	case reMshta.MatchString(c):
		return verdict{"launches mshta", finding.SeverityHigh, []string{"T1218.005"}}, true
	case reRegsvr32.MatchString(raw):
		return verdict{"loads a scriptlet through regsvr32", finding.SeverityHigh, []string{"T1218.010"}}, true
	case reRundll32JS.MatchString(raw):
		return verdict{"executes script or a URL through rundll32", finding.SeverityHigh, []string{"T1218.011"}}, true
	case reStaging.MatchString(c):
		return verdict{"executes from a user-writable staging directory", finding.SeverityMedium, nil}, true
	}
	return verdict{}, false
}

// unexpectedEntries splits a comma-separated Winlogon value and returns the
// entries whose file name is not want. Paths and the trailing comma Windows
// writes after userinit.exe are tolerated.
func unexpectedEntries(value, want string) []string {
	var extra []string
	for _, part := range strings.Split(value, ",") {
		p := strings.Trim(strings.TrimSpace(part), `"`)
		if p == "" {
			continue
		}
		base := strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
		if base != want {
			extra = append(extra, p)
		}
	}
	return extra
}

// unquotedWithSpace reports an unquoted ImagePath whose executable portion
// contains a space, the precondition for path interception.
func unquotedWithSpace(image string) (string, bool) {
	s := strings.TrimSpace(image)
	if s == "" || strings.HasPrefix(s, `"`) {
		return "", false
	}
	i := strings.Index(strings.ToLower(s), ".exe")
	if i < 0 {
		return "", false
	}
	exe := s[:i+4]
	return exe, strings.Contains(exe, " ")
}

// --- task XML ---

type taskXML struct {
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// parseTask decodes a Task Scheduler XML definition. Definitions on disk are
// UTF-16LE with a BOM and declare encoding="UTF-16", which encoding/xml
// rejects, so the bytes are transcoded first and the declared charset ignored.
func parseTask(name, file string, data []byte) ([]Task, error) {
	text, err := toUTF8(data)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(text))
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var t taskXML
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	out := make([]Task, 0, len(t.Actions.Exec))
	for _, e := range t.Actions.Exec {
		out = append(out, Task{
			Name:      name,
			File:      file,
			Command:   strings.TrimSpace(e.Command),
			Arguments: strings.TrimSpace(e.Arguments),
		})
	}
	return out, nil
}

func toUTF8(b []byte) ([]byte, error) {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return decodeUTF16(b[2:], false), nil
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return decodeUTF16(b[2:], true), nil
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return b[3:], nil
	}
	return b, nil
}

func decodeUTF16(b []byte, bigEndian bool) []byte {
	u := make([]uint16, len(b)/2)
	for i := range u {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return []byte(string(utf16.Decode(u)))
}

func valueName(n string) string {
	if n == "" {
		return "(Default)"
	}
	return n
}

func clip(s string) string {
	const limit = 200
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
