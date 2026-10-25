// Package config loads and validates SentinelTriage's run configuration.
//
// Precedence is defaults < config file < command-line flags. There is no
// implicit discovery of a config file in the working directory: a scanned
// repository could otherwise ship a .sentinel.yaml that disables its own
// detections or lowers the failure threshold. Config is loaded only from an
// explicit --config path.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// SchemaVersion is the only config schema this build accepts.
const SchemaVersion = 1

// maxConfigBytes guards against a config path pointing at a device or a
// multi-gigabyte file; real configs are a few kilobytes.
const maxConfigBytes = 1 << 20

// Duration is a time.Duration that decodes from Go duration strings ("10s").
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler. Bare integers are rejected
// because "timeout: 10" is ambiguous between seconds and nanoseconds.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return fmt.Errorf("line %d: duration must be a string such as \"10s\"", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config is the fully resolved run configuration.
type Config struct {
	Version int `yaml:"version"`
	// Budget is the global wall-clock limit for the run.
	Budget Duration `yaml:"budget"`
	// CollectorTimeout caps any one collector; 0 means "same as budget".
	CollectorTimeout Duration         `yaml:"collector_timeout"`
	Concurrency      int              `yaml:"concurrency"`
	FailOn           finding.Severity `yaml:"fail_on"`
	MinCoverage      float64          `yaml:"min_coverage"`
	Engines          Engines          `yaml:"engines"`
	Output           Output           `yaml:"output"`
}

// Engines toggles and tunes each engine.
type Engines struct {
	Host  HostEngine  `yaml:"host"`
	Audit AuditEngine `yaml:"audit"`
}

// HostEngine configures live host triage.
type HostEngine struct {
	Enabled bool `yaml:"enabled"`
	// ProcRoot allows triage of a mounted image or a container's /proc.
	ProcRoot string `yaml:"proc_root"`
}

// AuditEngine configures the static repository audit.
type AuditEngine struct {
	Enabled      bool     `yaml:"enabled"`
	Paths        []string `yaml:"paths"`
	MaxFileBytes int64    `yaml:"max_file_bytes"`
	RulesDirs    []string `yaml:"rules_dirs"`
	Exclude      []string `yaml:"exclude"`
}

// Output selects report sinks.
type Output struct {
	Dir     string   `yaml:"dir"`
	Formats []string `yaml:"formats"`
	// SARIFIncludeHost admits host-engine findings into the SARIF file. Off by
	// default because code scanning is organized around repository files.
	SARIFIncludeHost bool `yaml:"sarif_include_host"`
}

// Supported report formats.
const (
	FormatJSON  = "json"
	FormatSARIF = "sarif"
	FormatHTML  = "html"
)

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Version: SchemaVersion,
		Budget:  Duration(10 * time.Second),
		FailOn:  finding.SeverityHigh,
		Engines: Engines{
			Host: HostEngine{Enabled: true, ProcRoot: "/proc"},
			Audit: AuditEngine{
				Enabled:      true,
				Paths:        []string{"."},
				MaxFileBytes: 2 << 20,
			},
		},
		Output: Output{
			Dir:     "sentinel-report",
			Formats: []string{FormatJSON, FormatSARIF, FormatHTML},
		},
	}
}

// Load decodes YAML from r on top of Default and validates the result.
// Unknown keys are errors: a misspelled "fail_onn" must not silently fall back
// to the default threshold.
func Load(r io.Reader) (Config, error) {
	cfg := Default()
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return cfg, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, errors.New("config is empty")
	}
	// Cleared so the file must declare its schema version explicitly rather
	// than inheriting the default's.
	cfg.Version = 0
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return cfg, errors.New("config must contain exactly one YAML document")
	}
	if cfg.Version != SchemaVersion {
		return cfg, fmt.Errorf("config version %d unsupported (this build reads version %d)", cfg.Version, SchemaVersion)
	}
	return cfg, cfg.Validate()
}

// LoadFile opens path and calls Load.
func LoadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Default(), err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Default(), err
	}
	if !st.Mode().IsRegular() {
		return Default(), fmt.Errorf("%s is not a regular file", path)
	}
	cfg, err := Load(f)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks cross-field invariants. It is re-run after flags are
// applied, so flag overrides receive identical scrutiny.
func (c *Config) Validate() error {
	var errs []error
	if c.Budget <= 0 {
		errs = append(errs, errors.New("budget must be positive"))
	}
	if c.CollectorTimeout < 0 {
		errs = append(errs, errors.New("collector_timeout must be non-negative"))
	}
	if c.Concurrency < 0 || c.Concurrency > 1024 {
		errs = append(errs, errors.New("concurrency must be between 0 (auto) and 1024"))
	}
	if !c.FailOn.Valid() {
		errs = append(errs, fmt.Errorf("invalid fail_on %v", c.FailOn))
	}
	if c.MinCoverage < 0 || c.MinCoverage > 1 {
		errs = append(errs, errors.New("min_coverage must be between 0 and 1"))
	}
	if !c.Engines.Host.Enabled && !c.Engines.Audit.Enabled {
		errs = append(errs, errors.New("at least one engine must be enabled"))
	}
	if c.Engines.Host.Enabled && c.Engines.Host.ProcRoot == "" {
		errs = append(errs, errors.New("engines.host.proc_root must be set"))
	}
	if c.Engines.Audit.Enabled {
		if len(c.Engines.Audit.Paths) == 0 {
			errs = append(errs, errors.New("engines.audit.paths must not be empty"))
		}
		if c.Engines.Audit.MaxFileBytes <= 0 {
			errs = append(errs, errors.New("engines.audit.max_file_bytes must be positive"))
		}
	}
	for _, f := range c.Output.Formats {
		switch f {
		case FormatJSON, FormatSARIF, FormatHTML:
		default:
			errs = append(errs, fmt.Errorf("unknown output format %q", f))
		}
	}
	if len(c.Output.Formats) > 0 && c.Output.Dir == "" {
		errs = append(errs, errors.New("output.dir must be set when formats are enabled"))
	}
	return errors.Join(errs...)
}

// Marshal renders the configuration as YAML, used by --print-config.
func (c *Config) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
