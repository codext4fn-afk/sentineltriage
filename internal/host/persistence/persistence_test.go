package persistence

import (
	"context"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

type sink struct {
	mu sync.Mutex
	f  []finding.Finding
	d  []engine.Degradation
}

func (s *sink) Emit(f finding.Finding)       { s.mu.Lock(); defer s.mu.Unlock(); s.f = append(s.f, f) }
func (s *sink) Degrade(d engine.Degradation) { s.mu.Lock(); defer s.mu.Unlock(); s.d = append(s.d, d) }

func scan(t *testing.T, mfs fs.FS) *sink {
	t.Helper()
	s := &sink{}
	if err := FromFS(mfs).Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range s.f {
		if err := attack.Validate(f.Techniques); err != nil {
			t.Errorf("%s: invalid techniques: %v", f.RuleID, err)
		}
	}
	return s
}

func rule(s *sink, id string) *finding.Finding {
	for i := range s.f {
		if s.f[i].RuleID == id {
			return &s.f[i]
		}
	}
	return nil
}

func TestEmptyRootProducesNothing(t *testing.T) {
	s := scan(t, fstest.MapFS{})
	if len(s.f) != 0 || len(s.d) != 0 {
		t.Errorf("empty root: findings=%d gaps=%d, want 0/0 (absent files are not gaps)", len(s.f), len(s.d))
	}
}

func TestLdPreload(t *testing.T) {
	s := scan(t, fstest.MapFS{
		"etc/ld.so.preload": &fstest.MapFile{Data: []byte("# comment\n/usr/lib/evil.so\n/opt/legit.so\n")},
	})
	f := rule(s, "host.persistence.ld-preload")
	if f == nil {
		t.Fatal("ld.so.preload not flagged")
	}
	if f.Severity != finding.SeverityHigh || f.Location.Path != "/etc/ld.so.preload" {
		t.Errorf("unexpected finding: %+v", f)
	}
	// One finding per non-comment entry.
	n := 0
	for _, x := range s.f {
		if x.RuleID == "host.persistence.ld-preload" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("preload findings = %d, want 2", n)
	}
}

func TestCronTempExecAndWritable(t *testing.T) {
	s := scan(t, fstest.MapFS{
		"etc/crontab":     &fstest.MapFile{Data: []byte("* * * * * root /usr/bin/backup\n*/5 * * * * root /tmp/.x/run.sh\n")},
		"etc/cron.d/task": &fstest.MapFile{Data: []byte("0 0 * * * root /usr/local/bin/ok\n"), Mode: 0o666},
	})
	if f := rule(s, "host.persistence.cron-temp-exec"); f == nil || f.Location.StartLine != 2 {
		t.Errorf("temp-exec cron line not flagged correctly: %+v", f)
	}
	if rule(s, "host.persistence.cron-writable") == nil {
		t.Error("world-writable cron file not flagged")
	}
	// The /usr/bin/backup line is benign and must not be flagged.
	for _, f := range s.f {
		if f.RuleID == "host.persistence.cron-temp-exec" && f.Location.StartLine == 1 {
			t.Error("benign cron line flagged")
		}
	}
}

func TestSystemdUnitAndTimer(t *testing.T) {
	s := scan(t, fstest.MapFS{
		"etc/systemd/system/evil.service": &fstest.MapFile{Data: []byte("[Service]\nExecStart=/dev/shm/payload\n")},
		"etc/systemd/system/evil.timer":   &fstest.MapFile{Data: []byte("[Timer]\nOnCalendar=*:0/5\n"), Mode: 0o660},
		"etc/systemd/system/ok.service":   &fstest.MapFile{Data: []byte("[Service]\nExecStart=/usr/bin/app\n")},
	})
	svc := rule(s, "host.persistence.unit-temp-exec")
	if svc == nil || svc.Techniques[0] != "T1543.002" {
		t.Errorf("service temp-exec not mapped to T1543.002: %+v", svc)
	}
	w := rule(s, "host.persistence.unit-writable")
	if w == nil || w.Techniques[0] != "T1053.006" {
		t.Errorf("writable timer not mapped to T1053.006: %+v", w)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	err := Unsupported().Run(context.Background(), &sink{})
	if err != engine.ErrUnsupported {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestPermissionDeniedBecomesGap(t *testing.T) {
	s := scan(t, denyFS{inner: fstest.MapFS{
		"etc/ld.so.preload": &fstest.MapFile{Data: []byte("/x.so\n")},
	}, deny: "etc/ld.so.preload"})
	if len(s.f) != 0 {
		t.Error("denied file should yield no finding")
	}
	if len(s.d) != 1 || s.d[0].Reason != engine.ReasonPermission {
		t.Errorf("permission gap not recorded: %+v", s.d)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := FromFS(fstest.MapFS{"etc/crontab": &fstest.MapFile{Data: []byte("x")}}).Run(ctx, &sink{})
	if err == nil {
		t.Error("cancelled run returned nil")
	}
}

// denyFS wraps an fs.FS and returns a permission error for one path.
type denyFS struct {
	inner fs.FS
	deny  string
}

func (d denyFS) Open(name string) (fs.File, error) {
	if name == d.deny {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.inner.Open(name)
}
