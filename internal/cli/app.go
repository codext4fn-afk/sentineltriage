package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/audit"
	"github.com/codext4fn-afk/sentineltriage/internal/config"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
	"github.com/codext4fn-afk/sentineltriage/internal/host/persistence"
	"github.com/codext4fn-afk/sentineltriage/internal/report"
	"github.com/codext4fn-afk/sentineltriage/internal/report/html"
	"github.com/codext4fn-afk/sentineltriage/internal/report/jsonout"
	"github.com/codext4fn-afk/sentineltriage/internal/report/sarif"
	"github.com/codext4fn-afk/sentineltriage/internal/ui"
)

// Version is injected at build time:
//
//	go build -ldflags "-X github.com/codext4fn-afk/sentineltriage/internal/cli.Version=v1.0.0"
var Version = "dev"

// Factory builds an engine's collectors from the resolved configuration. A
// factory error is a configuration problem (exit 2), e.g. an unreadable rules
// directory; platform gaps are expressed by collectors returning
// engine.ErrUnsupported at run time instead.
type Factory func(cfg *config.Config, log *slog.Logger) ([]engine.Collector, error)

// renderCtx is everything a report writer may need. Exit code and
// coverage-threshold state are resolved before writing so SARIF's invocation
// record is accurate.
type renderCtx struct {
	result    *engine.Result
	jsonMeta  jsonout.Meta
	sarifMeta sarif.Meta
}

type reportWriter struct {
	file  string
	write func(io.Writer, renderCtx) error
}

var writers = map[string]reportWriter{
	config.FormatJSON: {"sentinel.json", func(w io.Writer, c renderCtx) error {
		return jsonout.Write(w, jsonout.Build(c.result, c.jsonMeta))
	}},
	config.FormatSARIF: {"sentinel.sarif", func(w io.Writer, c renderCtx) error {
		return sarif.Write(w, sarif.Build(c.result, c.sarifMeta))
	}},
	config.FormatHTML: {"sentinel.html", func(w io.Writer, c renderCtx) error {
		return html.Write(w, c.result, c.jsonMeta)
	}},
}

// App is the process entry point with every external dependency injectable.
type App struct {
	Stdout    io.Writer
	Stderr    io.Writer
	StdoutTTY bool
	StderrTTY bool
	Getenv    func(string) string
	Hostname  func() (string, error)
	Factories map[finding.Engine]Factory
}

// New returns an App bound to the given process streams.
func New(stdout, stderr *os.File) *App {
	return &App{
		Stdout:    stdout,
		Stderr:    stderr,
		StdoutTTY: isTerminal(stdout),
		StderrTTY: isTerminal(stderr),
		Getenv:    os.Getenv,
		Hostname:  os.Hostname,
		Factories: DefaultFactories(),
	}
}

// DefaultFactories returns the collectors compiled into this build. An enabled
// engine with no factory contributes no collectors.
func DefaultFactories() map[finding.Engine]Factory {
	return map[finding.Engine]Factory{
		finding.EngineHost: func(_ *config.Config, _ *slog.Logger) ([]engine.Collector, error) {
			// persistence.New is build-tagged: a real root on Linux, an
			// unsupported stub elsewhere that reports a coverage gap.
			return []engine.Collector{persistence.New()}, nil
		},
		finding.EngineAudit: func(cfg *config.Config, _ *slog.Logger) ([]engine.Collector, error) {
			ae := cfg.Engines.Audit
			return []engine.Collector{audit.New(audit.Config{
				Roots:        ae.Paths,
				MaxFileBytes: ae.MaxFileBytes,
				Exclude:      ae.Exclude,
				Workers:      cfg.Concurrency,
			})}, nil
		},
	}
}

// isTerminal avoids an isatty dependency; ModeCharDevice is set for consoles
// on both Unix and Windows, and unset for pipes, files, and CI log capture.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Run executes one CLI invocation. ctx cancellation (SIGINT/SIGTERM) stops
// collection but not report writing: a partial report flagged as interrupted
// is more useful to a responder than none.
func (a *App) Run(ctx context.Context, args []string) ExitCode {
	f, err := parseFlags(args, a.Stderr)
	switch {
	case errors.Is(err, errHelp):
		return ExitClean
	case err != nil:
		return a.usageError(err)
	case f.version:
		fmt.Fprintln(a.Stdout, versionString())
		return ExitClean
	}

	cfg := config.Default()
	if f.configPath != "" {
		if cfg, err = config.LoadFile(f.configPath); err != nil {
			return a.usageError(err)
		}
	}
	if err := f.apply(&cfg); err != nil {
		return a.usageError(err)
	}
	for _, format := range cfg.Output.Formats {
		if _, ok := writers[format]; !ok {
			return a.usageError(fmt.Errorf("report format %q is not available in this build", format))
		}
	}
	if f.printConfig {
		b, err := cfg.Marshal()
		if err != nil {
			return a.usageError(err)
		}
		_, _ = a.Stdout.Write(b)
		return ExitClean
	}

	log, err := newLogger(a.Stderr, f.logLevel, f.logFormat, a.StderrTTY && a.Getenv("CI") == "")
	if err != nil {
		return a.usageError(err)
	}

	collectors, err := a.collectors(&cfg, log)
	if err != nil {
		return a.usageError(err)
	}
	if len(collectors) == 0 {
		log.Error("no collectors available for the enabled engines")
		fmt.Fprintln(a.Stderr, "sentinel: no collectors available for the enabled engines")
		return ExitRuntime
	}

	r := a.renderer(f)
	orch, err := engine.New(engine.Options{
		Budget:      time.Duration(cfg.Budget),
		UnitTimeout: time.Duration(cfg.CollectorTimeout),
		Concurrency: cfg.Concurrency,
		OnFinish:    r.CollectorDone,
		Logger:      log,
	}, collectors...)
	if err != nil {
		log.Error("engine initialisation failed", "error", err)
		return ExitRuntime
	}

	log.Info("run starting", "collectors", len(collectors), "budget", time.Duration(cfg.Budget).String())
	res := orch.Run(ctx)

	host, _ := a.Hostname()
	meta := jsonout.Meta{ToolVersion: Version, Hostname: host, FailOn: cfg.FailOn}
	// The exit code is resolved before writing so SARIF's invocation record
	// reports it; the provisional decision ignores write errors, which cannot
	// yet have occurred.
	provisional, _ := Decide(res, cfg.FailOn, cfg.MinCoverage, nil)
	rc := renderCtx{
		result:    res,
		jsonMeta:  meta,
		sarifMeta: sarif.Meta{ToolVersion: Version, ExitCode: int(provisional), IncludeHost: cfg.Output.SARIFIncludeHost},
	}
	written, werr := writeReports(cfg.Output, rc)
	if f.stdoutFormat == stdoutJSON {
		werr = errors.Join(werr, jsonout.Write(a.Stdout, jsonout.Build(res, meta)))
	}
	if werr != nil {
		log.Error("report output failed", "error", werr)
	}

	code, reason := Decide(res, cfg.FailOn, cfg.MinCoverage, werr)
	r.Summary(ui.RunSummary{Result: res, FailOn: cfg.FailOn, Reports: written, ExitCode: int(code), Reason: reason})
	log.Info("run finished", "exit_code", int(code), "reason", reason, "duration_ms", res.Duration().Milliseconds())
	return code
}

func (a *App) usageError(err error) ExitCode {
	fmt.Fprintf(a.Stderr, "sentinel: %v\nRun 'sentinel --help' for usage.\n", err)
	return ExitUsage
}

// collectors resolves factories in a fixed engine order so that collector
// scheduling, and therefore timing under a tight budget, is reproducible.
func (a *App) collectors(cfg *config.Config, log *slog.Logger) ([]engine.Collector, error) {
	var out []engine.Collector
	for _, e := range []struct {
		eng     finding.Engine
		enabled bool
	}{
		{finding.EngineHost, cfg.Engines.Host.Enabled},
		{finding.EngineAudit, cfg.Engines.Audit.Enabled},
	} {
		if !e.enabled {
			continue
		}
		factory, ok := a.Factories[e.eng]
		if !ok {
			log.Warn("engine enabled but not compiled into this build", "engine", e.eng)
			continue
		}
		cs, err := factory(cfg, log.With("engine", e.eng))
		if err != nil {
			return nil, fmt.Errorf("%s engine: %w", e.eng, err)
		}
		out = append(out, cs...)
	}
	return out, nil
}

func (a *App) renderer(f *flags) ui.Renderer {
	// The live view needs a real terminal and must not fight machine-readable
	// stdout; fall back to plain output otherwise, even when --tui is set.
	if f.tui && ui.TUIAvailable() && a.StdoutTTY && !f.quiet && f.stdoutFormat == stdoutSummary && a.Getenv("CI") == "" {
		return ui.NewTUIRenderer(a.Stderr)
	}
	color := !f.noColor && a.StdoutTTY && a.StderrTTY && a.Getenv("NO_COLOR") == "" && a.Getenv("CI") == ""
	p := &ui.Plain{Progress: a.Stderr, Out: a.Stdout, Color: color}
	if f.quiet {
		p.Progress = io.Discard
	}
	if f.quiet || f.stdoutFormat != stdoutSummary {
		p.Out = io.Discard
	}
	return p
}

func writeReports(out config.Output, rc renderCtx) ([]string, error) {
	if len(out.Formats) == 0 {
		return nil, nil
	}
	if err := report.EnsureDir(out.Dir); err != nil {
		return nil, err
	}
	var written []string
	var errs []error
	for _, format := range out.Formats {
		w := writers[format]
		path := filepath.Join(out.Dir, w.file)
		err := report.WriteAtomic(path, report.FileMode, func(dst io.Writer) error { return w.write(dst, rc) })
		if err != nil {
			errs = append(errs, fmt.Errorf("%s report: %w", format, err))
			continue
		}
		written = append(written, path)
	}
	return written, errors.Join(errs...)
}

func newLogger(w io.Writer, level, format string, interactive bool) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "auto":
		if interactive {
			return slog.New(slog.NewTextHandler(w, opts)), nil
		}
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid --log-format %q (want auto, text, or json)", format)
	}
}

func versionString() string {
	rev, dirty := "unknown", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
	}
	return fmt.Sprintf("sentinel %s (%s%s, %s/%s, %s)", Version, rev, dirty, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
