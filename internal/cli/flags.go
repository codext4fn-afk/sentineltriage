package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/codext4fn-afk/sentineltriage/internal/config"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// errHelp signals that usage was printed on request and the process should
// exit 0, matching GNU convention for --help.
var errHelp = errors.New("help requested")

// Stdout formats.
const (
	stdoutSummary = "summary"
	stdoutJSON    = "json"
	stdoutNone    = "none"
)

type flags struct {
	set *pflag.FlagSet

	configPath       string
	engines          []string
	failOn           string
	minCoverage      float64
	budget           time.Duration
	collectorTimeout time.Duration
	jobs             int
	outputDir        string
	reports          []string
	sarifIncludeHost bool
	stdoutFormat     string
	procRoot         string
	maxFileBytes     int64
	logLevel         string
	logFormat        string
	quiet            bool
	noColor          bool
	tui              bool
	printConfig      bool
	version          bool
	help             bool

	paths []string
}

const usageHeader = `Usage: sentinel [OPTION]... [PATH]...
Triage the local host and audit each PATH (default ".") for security issues.

Options:
`

const usageFooter = `
Exit status:
  0    no findings at or above --fail-on
  1    findings at or above --fail-on
  2    invalid flags, configuration, or rules
  3    runtime failure: nothing observed, or a report could not be written
  4    coverage below --min-coverage
  130  interrupted

Configuration is read only from --config; it is never discovered implicitly
from the scanned tree.
`

func parseFlags(args []string, stderr io.Writer) (*flags, error) {
	f := &flags{}
	fs := pflag.NewFlagSet("sentinel", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(stderr)
	f.set = fs

	fs.StringVarP(&f.configPath, "config", "c", "", "load configuration from `FILE`")
	fs.StringSliceVarP(&f.engines, "engine", "e", nil, "engines to run: host, audit, all (repeatable)")
	fs.StringVar(&f.failOn, "fail-on", "", "exit 1 on findings at or above `SEVERITY` (info|low|medium|high|critical)")
	fs.Float64Var(&f.minCoverage, "min-coverage", 0, "exit 4 when collector coverage is below `RATIO` (0-1)")
	fs.DurationVarP(&f.budget, "timeout", "t", 0, "global time budget for the run (default 10s)")
	fs.DurationVar(&f.collectorTimeout, "collector-timeout", 0, "per-collector time limit (default: --timeout)")
	fs.IntVarP(&f.jobs, "jobs", "j", 0, "collectors to run in parallel (default: CPU count)")
	fs.StringVarP(&f.outputDir, "output-dir", "o", "", "write reports into `DIR` (default sentinel-report)")
	fs.StringSliceVarP(&f.reports, "report", "r", nil, "report formats: json, sarif, html, none (repeatable)")
	fs.BoolVar(&f.sarifIncludeHost, "sarif-include-host", false, "include host-engine findings in the SARIF file")
	fs.StringVarP(&f.stdoutFormat, "format", "f", stdoutSummary, "stdout format: summary, json, none")
	fs.StringVar(&f.procRoot, "proc-root", "", "procfs mount to triage (default /proc)")
	fs.Int64Var(&f.maxFileBytes, "max-file-bytes", 0, "skip audited files larger than `N` bytes")
	fs.StringVar(&f.logLevel, "log-level", "warn", "diagnostic log level: debug, info, warn, error")
	fs.StringVar(&f.logFormat, "log-format", "auto", "diagnostic log format on stderr: auto, text, json")
	fs.BoolVarP(&f.quiet, "quiet", "q", false, "suppress progress and summary output")
	fs.BoolVar(&f.noColor, "no-color", false, "disable ANSI colors (also honours NO_COLOR)")
	fs.BoolVar(&f.tui, "tui", false, "use the interactive live view (requires a -tags tui build and a TTY)")
	fs.BoolVar(&f.printConfig, "print-config", false, "print the effective configuration and exit")
	fs.BoolVarP(&f.version, "version", "V", false, "print version information and exit")
	fs.BoolVarP(&f.help, "help", "h", false, "show this help and exit")

	fs.Usage = func() {
		fmt.Fprint(stderr, usageHeader)
		fmt.Fprint(stderr, fs.FlagUsages())
		fmt.Fprint(stderr, usageFooter)
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if f.help {
		fs.Usage()
		return nil, errHelp
	}
	switch f.stdoutFormat {
	case stdoutSummary, stdoutJSON, stdoutNone:
	default:
		return nil, fmt.Errorf("invalid --format %q (want summary, json, or none)", f.stdoutFormat)
	}
	f.paths = fs.Args()
	return f, nil
}

// apply overlays explicitly set flags onto cfg and re-validates. Only flags the
// user actually passed override the config file; pflag's Changed is the
// source of truth, not comparison against zero values.
func (f *flags) apply(cfg *config.Config) error {
	ch := f.set.Changed
	if ch("engine") {
		host, audit := false, false
		for _, e := range f.engines {
			if strings.EqualFold(strings.TrimSpace(e), "all") {
				host, audit = true, true
				continue
			}
			eng, err := finding.ParseEngine(e)
			if err != nil {
				return err
			}
			host = host || eng == finding.EngineHost
			audit = audit || eng == finding.EngineAudit
		}
		cfg.Engines.Host.Enabled, cfg.Engines.Audit.Enabled = host, audit
	}
	if ch("fail-on") {
		sev, err := finding.ParseSeverity(f.failOn)
		if err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
		cfg.FailOn = sev
	}
	if ch("min-coverage") {
		cfg.MinCoverage = f.minCoverage
	}
	if ch("timeout") {
		cfg.Budget = config.Duration(f.budget)
	}
	if ch("collector-timeout") {
		cfg.CollectorTimeout = config.Duration(f.collectorTimeout)
	}
	if ch("jobs") {
		cfg.Concurrency = f.jobs
	}
	if ch("output-dir") {
		cfg.Output.Dir = f.outputDir
	}
	if ch("report") {
		formats := make([]string, 0, len(f.reports))
		for _, r := range f.reports {
			r = strings.ToLower(strings.TrimSpace(r))
			if r == "none" {
				formats = nil
				break
			}
			if !slices.Contains(formats, r) {
				formats = append(formats, r)
			}
		}
		cfg.Output.Formats = formats
	}
	if ch("proc-root") {
		cfg.Engines.Host.ProcRoot = f.procRoot
	}
	if ch("sarif-include-host") {
		cfg.Output.SARIFIncludeHost = f.sarifIncludeHost
	}
	if ch("max-file-bytes") {
		cfg.Engines.Audit.MaxFileBytes = f.maxFileBytes
	}
	if len(f.paths) > 0 {
		cfg.Engines.Audit.Paths = f.paths
	}
	return cfg.Validate()
}
