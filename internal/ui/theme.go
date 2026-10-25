package ui

import (
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Palette is the Tomorrow Night family used by zenith and many terminal
// themes: muted, readable on dark backgrounds, and distinct under the common
// forms of color blindness for the severity ramp.
const (
	cBorder   = "#7c7f84"
	cBorderHi = "#cc6666"
	cTitle    = "#e0e0e0"
	cMuted    = "#969896"
	cHeaderBg = "#4d5057"
	cHeaderFg = "#ffffff"
	cSelect   = "#c397d8"
	cOlive    = "#b5bd68"
	cBlue     = "#81a2be"
	cTeal     = "#8abeb7"
	cYellow   = "#f0c674"
	cOrange   = "#de935f"
	cRed      = "#cc6666"
)

var (
	stTitle  = sty{fg: cTitle}
	stMuted  = sty{fg: cMuted}
	stHeader = sty{fg: cHeaderFg, bg: cHeaderBg, bold: true}
	stSelect = sty{fg: cSelect, bold: true}
	stBold   = sty{bold: true}
)

func sevStyle(s finding.Severity) sty {
	switch s {
	case finding.SeverityCritical:
		return sty{fg: cRed, bold: true}
	case finding.SeverityHigh:
		return sty{fg: cOrange}
	case finding.SeverityMedium:
		return sty{fg: cYellow}
	case finding.SeverityLow:
		return sty{fg: cBlue}
	default:
		return sty{fg: cMuted}
	}
}

func sevShort(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "CRIT"
	case finding.SeverityHigh:
		return "HIGH"
	case finding.SeverityMedium:
		return "MED"
	case finding.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func statusStyle(s engine.Status) sty {
	switch s {
	case engine.StatusOK:
		return sty{fg: cOlive}
	case engine.StatusDegraded, engine.StatusUnsupported, engine.StatusTimeout:
		return sty{fg: cYellow}
	default:
		return sty{fg: cRed, bold: true}
	}
}
