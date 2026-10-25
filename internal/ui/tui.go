package ui

import (
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// NewTUIRenderer starts the interactive full-screen view on its own goroutine.
// The program owns the terminal (alternate screen, raw input) until the user
// quits; quitting before the scan finishes calls cancel, which the CLI wires
// to the run context so the scan stops and a partial report is written.
func NewTUIRenderer(out io.Writer, cancel func()) Renderer {
	m := &model{v: view{sortCol: colSev, interactive: true}, cancel: cancel}
	p := tea.NewProgram(m, tea.WithOutput(out), tea.WithAltScreen())
	t := &tui{p: p, out: out, done: make(chan struct{})}
	go func() {
		_, _ = p.Run()
		close(t.done)
	}()
	return t
}

type tui struct {
	p    *tea.Program
	out  io.Writer
	done chan struct{}
}

// CollectorDone implements Renderer. Send is safe from any goroutine; Bubble
// Tea serializes messages into its event loop.
func (t *tui) CollectorDone(r engine.CollectorReport) { t.p.Send(collectorMsg(r)) }

// Summary implements Renderer. It hands the final result to the view and
// blocks until the user quits, then prints the verdict line to the restored
// screen so the outcome stays in scrollback.
func (t *tui) Summary(s RunSummary) {
	t.p.Send(summaryMsg(s))
	<-t.done
	v := view{sum: &s}
	fmt.Fprintln(t.out, v.footer(200, 0).render(true))
}

type collectorMsg engine.CollectorReport
type summaryMsg RunSummary

type model struct {
	v      view
	w, h   int
	cancel func()
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case collectorMsg:
		if m.v.sum == nil {
			m.v.live = append(m.v.live, engine.CollectorReport(msg))
		}
	case summaryMsg:
		s := RunSummary(msg)
		m.v.sum = &s
	case tea.KeyMsg:
		return m, m.key(msg.String())
	}
	return m, nil
}

func (m *model) key(k string) tea.Cmd {
	page := max(m.h-24, 1)
	switch k {
	case "q", "esc", "ctrl+c":
		if m.v.sum == nil && m.cancel != nil {
			m.cancel()
		}
		return tea.Quit
	case "up", "k":
		m.v.selected--
	case "down", "j":
		m.v.selected++
	case "pgup":
		m.v.selected -= page
	case "pgdown", " ":
		m.v.selected += page
	case "home", "g":
		m.v.selected = 0
	case "end", "G":
		m.v.selected = len(m.v.rows()) - 1
	case ",":
		m.v.sortCol = (m.v.sortCol + numCols - 1) % numCols
	case ".":
		m.v.sortCol = (m.v.sortCol + 1) % numCols
	case "/":
		m.v.asc = !m.v.asc
	case "f":
		m.v.minSev = (m.v.minSev + 1) % (finding.SeverityCritical + 1)
		m.v.selected, m.v.offset = 0, 0
	}
	if m.v.selected < 0 {
		m.v.selected = 0
	}
	return nil
}

func (m *model) View() string {
	if m.w == 0 {
		return ""
	}
	lines := m.v.render(m.w, m.h)
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l.render(true))
	}
	return b.String()
}
