//go:build windows

package winpersist

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// New returns a collector over the live registry and filesystem.
func New() *Collector { return FromSource(systemSource{}) }

// maxTaskBytes caps a single task definition read. Real definitions are a few
// kilobytes; the cap bounds a tampered or corrupt file.
const maxTaskBytes = 1 << 20

// Service Type bits for user-mode services. Kernel and file-system drivers
// (0x1, 0x2) are excluded: their ImagePath semantics differ and they are out
// of scope for this collector.
const (
	serviceWin32OwnProcess   = 0x10
	serviceWin32ShareProcess = 0x20
)

type systemSource struct{}

type regLoc struct {
	root     registry.Key
	rootName string
	path     string
}

func (l regLoc) String() string { return l.rootName + `\` + l.path }

// Both registry views are read explicitly. A 64-bit process sees the native
// view by default; WOW6432Node holds what 32-bit installers registered.
var runKeys = []regLoc{
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
}

// HKCU Winlogon\Shell overrides the machine value for that user, which is why
// both hives are read.
var winlogonKeys = []regLoc{
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`},
}

func (systemSource) Autoruns() ([]Autorun, []Gap) {
	var out []Autorun
	var gaps []Gap
	for _, loc := range runKeys {
		vals, err := readStringValues(loc)
		if err != nil {
			gaps = append(gaps, Gap{Scope: loc.String(), Err: err})
			continue
		}
		for _, v := range vals {
			out = append(out, Autorun{Key: v.Key, Name: v.Name, Command: v.Value})
		}
	}
	return out, gaps
}

func (systemSource) Winlogon() ([]RegValue, []Gap) {
	var out []RegValue
	var gaps []Gap
	for _, loc := range winlogonKeys {
		vals, err := readStringValues(loc)
		if err != nil {
			gaps = append(gaps, Gap{Scope: loc.String(), Err: err})
			continue
		}
		for _, v := range vals {
			if n := strings.ToLower(v.Name); n == "userinit" || n == "shell" {
				out = append(out, v)
			}
		}
	}
	return out, gaps
}

// readStringValues returns every string-typed value under loc. Values of
// other types (DWORD flags, binary blobs) are skipped, not reported as errors.
func readStringValues(loc regLoc) ([]RegValue, error) {
	k, err := registry.OpenKey(loc.root, loc.path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	out := make([]RegValue, 0, len(names))
	for _, n := range names {
		v, _, err := k.GetStringValue(n)
		if err != nil {
			continue
		}
		out = append(out, RegValue{Key: loc.String(), Name: n, Value: v})
	}
	return out, nil
}

func (systemSource) StartupFiles() ([]StartupFile, []Gap) {
	var dirs []string
	if d := os.Getenv("APPDATA"); d != "" {
		dirs = append(dirs, filepath.Join(d, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	if d := os.Getenv("ProgramData"); d != "" {
		dirs = append(dirs, filepath.Join(d, `Microsoft\Windows\Start Menu\Programs\StartUp`))
	}
	var out []StartupFile
	var gaps []Gap
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			gaps = append(gaps, Gap{Scope: dir, Err: err})
			continue
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				out = append(out, StartupFile{Path: filepath.Join(dir, e.Name())})
			}
		}
	}
	return out, gaps
}

func (systemSource) Services() ([]Service, []Gap) {
	const base = `SYSTEM\CurrentControlSet\Services`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, []Gap{{Scope: `HKLM\` + base, Err: err}}
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil, []Gap{{Scope: `HKLM\` + base, Err: err}}
	}

	var out []Service
	var gaps []Gap
	for _, n := range names {
		keyPath := `HKLM\` + base + `\` + n
		k, err := registry.OpenKey(root, n, registry.QUERY_VALUE)
		if err != nil {
			gaps = append(gaps, Gap{Scope: keyPath, Err: err})
			continue
		}
		typ, _, terr := k.GetIntegerValue("Type")
		img, _, ierr := k.GetStringValue("ImagePath")
		k.Close()
		if terr != nil || ierr != nil || typ&(serviceWin32OwnProcess|serviceWin32ShareProcess) == 0 {
			continue
		}
		out = append(out, Service{Key: keyPath, Name: n, ImagePath: img})
	}
	return out, gaps
}

// Tasks walks the on-disk task store. Listing it usually requires
// administrator rights; a non-elevated run records one permission gap for the
// root and still reports every other location.
func (systemSource) Tasks(ctx context.Context) ([]Task, []Gap) {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	root := filepath.Join(sysroot, `System32\Tasks`)

	var out []Task
	var gaps []Gap
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			gaps = append(gaps, Gap{Scope: p, Err: err})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, err := readCapped(p)
		if err != nil {
			gaps = append(gaps, Gap{Scope: p, Err: err})
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		tasks, err := parseTask(`\`+rel, p, data)
		if err != nil {
			// A malformed definition is skipped rather than reported: the
			// scheduler would refuse to load it too.
			return nil
		}
		out = append(out, tasks...)
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) && !errors.Is(walkErr, context.DeadlineExceeded) {
		gaps = append(gaps, Gap{Scope: root, Err: walkErr})
	}
	return out, gaps
}

func readCapped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxTaskBytes))
}
