// Package drift analyzes infrastructure-as-code for insecure defaults:
// Dockerfiles and Kubernetes manifests. Findings describe weakened posture,
// not observed intrusion, so most carry low-to-medium confidence and map to
// ATT&CK only where the setting directly grants an adversary capability.
package drift

import (
	"path"
	"regexp"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/afind"
	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Dockerfile analyzes Dockerfiles for unpinned bases, root execution, and
// remote-code-into-shell patterns.
type Dockerfile struct{}

// Name implements audit.Analyzer.
func (Dockerfile) Name() string { return "drift.dockerfile" }

// Applies matches files named Dockerfile or Containerfile, with or without a
// stage suffix (Dockerfile.ci, api.Dockerfile).
func (Dockerfile) Applies(rel string) bool {
	b := path.Base(rel)
	return b == "Dockerfile" || b == "Containerfile" ||
		strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".Dockerfile") ||
		strings.HasPrefix(b, "Containerfile.")
}

type instruction struct {
	cmd  string // uppercased keyword, e.g. FROM
	args string // remainder, continuations joined
	line int    // 1-based line of the keyword
}

var (
	reDigest    = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)
	rePipeShell = regexp.MustCompile(`\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b`)
	reRootUser  = regexp.MustCompile(`^(0|root)(:|$)`)
)

// Analyze implements audit.Analyzer.
func (Dockerfile) Analyze(f walker.File, emit func(finding.Finding)) {
	instrs := parse(f.Content)

	// Root-execution analysis is per final stage: a build stage running as
	// root is irrelevant if the runtime stage drops privilege. Track the final
	// stage's USER directive and the line its FROM began on.
	lastFromLine := 0
	stageUser := ""
	stageUserLine := 0

	for _, in := range instrs {
		switch in.cmd {
		case "FROM":
			lastFromLine = in.line
			stageUser, stageUserLine = "", 0
			if ref := firstField(in.args); ref != "" && !reDigest.MatchString(ref) {
				if tag := imageTag(ref); tag == "" || tag == "latest" {
					emit(afind.New("drift.dockerfile.unpinned-base",
						"Base image is not pinned to a digest or version",
						finding.SeverityMedium, finding.ConfidenceHigh).
						Path(f.Rel).Line(in.line).Evidence("image", ref).
						Fix("Pin the base image to an immutable digest, e.g. FROM image@sha256:<digest>, so rebuilds are reproducible and cannot be silently repointed.").Done())
				}
			}
		case "USER":
			stageUser = firstField(in.args)
			stageUserLine = in.line
		case "ADD":
			if url := firstField(in.args); strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
				emit(afind.New("drift.dockerfile.add-url",
					"ADD fetches from a URL without integrity verification",
					finding.SeverityMedium, finding.ConfidenceHigh).
					Path(f.Rel).Line(in.line).Evidence("url", url).
					Fix("Replace ADD <url> with a RUN that downloads and verifies a checksum, or vendor the artifact and use COPY.").Done())
			}
		case "RUN":
			if rePipeShell.MatchString(in.args) {
				emit(afind.New("drift.dockerfile.remote-exec",
					"RUN pipes a downloaded script straight into a shell",
					finding.SeverityMedium, finding.ConfidenceMedium).
					Path(f.Rel).Line(in.line).Evidence("snippet", clip(in.args)).Tech("T1059.004").
					Fix("Download to a file, verify its checksum or signature, then execute it.").Done())
			}
		}
	}

	if lastFromLine > 0 && (stageUser == "" || reRootUser.MatchString(stageUser)) {
		line := stageUserLine
		if line == 0 {
			line = lastFromLine
		}
		emit(afind.New("drift.dockerfile.root-user",
			"Container's final stage runs as root",
			finding.SeverityHigh, finding.ConfidenceMedium).
			Path(f.Rel).Line(line).Evidence("user", orNone(stageUser)).Tech("T1611").
			Fix("Add a non-root USER to the final stage; combine with a read-only root filesystem and dropped Linux capabilities at runtime.").Done())
	}
}

// parse tokenizes a Dockerfile into instructions, joining backslash line
// continuations and skipping comments. Line numbers refer to the keyword line.
func parse(content []byte) []instruction {
	var out []instruction
	lines := strings.Split(string(content), "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		start := i + 1
		joined := trimmed
		for strings.HasSuffix(strings.TrimRight(joined, " \t"), "\\") {
			joined = strings.TrimRight(joined, " \t")
			joined = joined[:len(joined)-1]
			i++
			if i >= len(lines) {
				break
			}
			next := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			if strings.HasPrefix(next, "#") {
				continue
			}
			joined += " " + next
		}
		kw, rest, _ := strings.Cut(joined, " ")
		out = append(out, instruction{cmd: strings.ToUpper(kw), args: strings.TrimSpace(rest), line: start})
	}
	return out
}

func firstField(s string) string {
	if fs := strings.Fields(s); len(fs) > 0 {
		return fs[0]
	}
	return ""
}

// imageTag returns the tag portion of an image reference, or "" if untagged.
// A ':' inside a registry host:port is distinguished from a tag separator by
// requiring the tag portion to contain no '/'.
func imageTag(ref string) string {
	ref = strings.SplitN(ref, "@", 2)[0]
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ""
	}
	return ref[i+1:]
}

func clip(s string) string {
	const max = 120
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(none declared)"
	}
	return s
}
