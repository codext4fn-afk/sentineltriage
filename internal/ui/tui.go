//go:build tui

// This file is compiled only with -tags tui. It adds the interactive Bubble
// Tea live view and its dependency tree (bubbletea, lipgloss). The default
// build uses the plain renderer and carries none of these modules, keeping the
// standard binary's supply chain minimal.
package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// TUIAvailable reports that the interactive renderer is compiled in.
func TUIAvailable() bool { return true }

// NewTUIRenderer starts a Bubble Tea program on its own goroutine and returns a
// Renderer that feeds it engine events. The program owns the terminal until
// Summary sends the final frame and quits.
func NewTUIRenderer(out io.Writer) Renderer {
	m := &model{collectors: map[string]engine.CollectorReport{}}
	p := tea.NewProgram(m, tea.WithOutput(out))
	t := &tui{p: p, done: make(chan struct{})}
	go func() {
		_, _ = p.Run()
		close(t.done)
	}()
	return t
}

type tui struct {
	p    *tea.Program
	done chan struct{}
}

// CollectorDone implements Renderer. Send is safe to call from the engine's
// worker goroutines; Bubble Tea serializes messages into its own loop.
func (t *tui) CollectorDone(r engine.CollectorReport) { t.p.Send(collectorMsg(r)) }

// Summary implements Renderer. It delivers the final state, asks the program
// to quit, and blocks until the terminal is restored so the process does not
// exit mid-redraw.
func (t *tui) Summary(s RunSummary) {
	t.p.Send(summaryMsg(s))
	<-t.done
}

type collectorMsg engine.CollectorReport
type summaryMsg RunSummary

type model struct {
	order      []string
	collectors map[string]engine.CollectorReport
	summary    *RunSummary
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case collectorMsg:
		r := engine.CollectorReport(msg)
		if _, ok := m.collectors[r.Name]; !ok {
			m.order = append(m.order, r.Name)
			sort.Strings(m.order)
		}
		m.collectors[r.Name] = r
	case summaryMsg:
		s := RunSummary(msg)
		m.summary = &s
		return m, tea.Quit
	case tea.KeyMsg:
		if k := msg.String(); k == "ctrl+c" || k == "q" {
			return m, tea.Quit
		}
	}
	return m, nil
}

var (
	styTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4aa3ff"))
	styMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	styOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("#3fb950"))
	styWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd166"))
	styErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5c6c"))
	sevStyle = map[finding.Severity]lipgloss.Style{
		finding.SeverityCritical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff5c6c")),
		finding.SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color("#ff8c42")),
		finding.SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd166")),
		finding.SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color("#4aa3ff")),
		finding.SeverityInfo:     styMuted,
	}
)

func (m *model) View() string {
	var b strings.Builder
	b.WriteString(styTitle.Render("SentinelTriage") + "\n\n")

	for _, name := range m.order {
		r := m.collectors[name]
		b.WriteString("  " + statusStyle(r.Status).Render(pad(string(r.Status), 11)))
		b.WriteString("  " + pad(r.Name, 26))
		b.WriteString(styMuted.Render(fmt.Sprintf("%5dms  %d findings\n", r.DurationMS, r.Findings)))
	}

	if m.summary == nil {
		b.WriteString("\n" + styMuted.Render("scanning…  (q to abort)"))
		return b.String()
	}

	s := m.summary
	counts := s.Result.SeverityCounts()
	b.WriteString("\n")
	for sev := finding.SeverityCritical; ; sev-- {
		b.WriteString("  " + sevStyle[sev].Render(fmt.Sprintf("%s %d", sev, counts[sev])))
		if sev == finding.SeverityInfo {
			break
		}
	}
	b.WriteString("\n")
	b.WriteString(styMuted.Render(fmt.Sprintf("  coverage %.0f%%  ·  %d collectors  ·  %s\n",
		s.Result.Coverage()*100, len(s.Result.Collectors), s.Result.Duration().Round(1e6))))

	verdict := fmt.Sprintf("  exit %d: %s", s.ExitCode, s.Reason)
	if s.ExitCode == 0 {
		b.WriteString(styOK.Render(verdict))
	} else {
		b.WriteString(styErr.Render(verdict))
	}
	b.WriteString("\n")
	return b.String()
}

func statusStyle(s engine.Status) lipgloss.Style {
	switch s {
	case engine.StatusOK:
		return styOK
	case engine.StatusDegraded, engine.StatusTimeout, engine.StatusUnsupported:
		return styWarn
	default:
		return styErr
	}
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
