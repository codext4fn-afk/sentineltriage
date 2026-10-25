package drift

import (
	"slices"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func analyze(a interface {
	Applies(string) bool
	Analyze(walker.File, func(finding.Finding))
}, rel, body string) []finding.Finding {
	f := walker.File{Rel: rel, Content: []byte(body)}
	if !a.Applies(f.Rel) {
		return nil
	}
	var out []finding.Finding
	a.Analyze(f, func(x finding.Finding) { out = append(out, x) })
	return out
}

func ruleIDs(fs []finding.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	slices.Sort(ids)
	return ids
}

func has(fs []finding.Finding, rule string) *finding.Finding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestDockerfileApplies(t *testing.T) {
	d := Dockerfile{}
	for _, name := range []string{"Dockerfile", "api.Dockerfile", "Dockerfile.ci", "Containerfile"} {
		if !d.Applies(name) {
			t.Errorf("%s should apply", name)
		}
	}
	for _, name := range []string{"dockerfile.md", "notes.txt", "k8s.yaml"} {
		if d.Applies(name) {
			t.Errorf("%s should not apply", name)
		}
	}
}

func TestDockerfileInsecure(t *testing.T) {
	body := `
FROM golang:latest AS build
RUN curl -sSL https://example.com/install.sh | bash
ADD https://example.com/tool.tar.gz /opt/

FROM alpine:latest
ADD https://example.com/app /app
`
	fs := analyze(Dockerfile{}, "Dockerfile", body)
	want := []string{
		"drift.dockerfile.add-url", "drift.dockerfile.add-url",
		"drift.dockerfile.remote-exec",
		"drift.dockerfile.root-user",
		"drift.dockerfile.unpinned-base", "drift.dockerfile.unpinned-base",
	}
	if got := ruleIDs(fs); !slices.Equal(got, want) {
		t.Errorf("rules = %v,\nwant %v", got, want)
	}
	if f := has(fs, "drift.dockerfile.root-user"); f == nil || f.Location.StartLine != 6 {
		t.Errorf("root-user should anchor on final FROM line 6, got %+v", f)
	}
}

func TestDockerfileSecureIsQuiet(t *testing.T) {
	body := `
FROM golang:1.25@sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + ` AS build
RUN echo build

FROM gcr.io/distroless/static:nonroot@sha256:` + "1111111111111111111111111111111111111111111111111111111111111111" + `
USER 65532:65532
COPY --from=build /app /app
`
	if fs := analyze(Dockerfile{}, "Dockerfile", body); len(fs) != 0 {
		t.Errorf("pinned, non-root Dockerfile produced findings: %v", ruleIDs(fs))
	}
}

func TestDockerfileRegistryPortIsNotATag(t *testing.T) {
	// localhost:5000/img is untagged (the colon is a port); should flag as
	// unpinned, and must not misread "5000/img" as a tag.
	fs := analyze(Dockerfile{}, "Dockerfile", "FROM localhost:5000/img\nUSER app\n")
	if has(fs, "drift.dockerfile.unpinned-base") == nil {
		t.Error("registry-port image not detected as unpinned")
	}
}

func TestDockerfileRootDetectedWhenNoUser(t *testing.T) {
	fs := analyze(Dockerfile{}, "Dockerfile", "FROM alpine:3.20\nCMD [\"/bin/sh\"]\n")
	if has(fs, "drift.dockerfile.root-user") == nil {
		t.Error("missing USER should flag root execution")
	}
}

func TestDockerfileContinuationLineJoining(t *testing.T) {
	// The pipe-to-shell spans a continuation; detection must see the joined form.
	body := "FROM alpine:3.20\nUSER app\nRUN curl -sSL https://x/y.sh \\\n  | sh\n"
	if has(analyze(Dockerfile{}, "Dockerfile", body), "drift.dockerfile.remote-exec") == nil {
		t.Error("continuation join failed; remote-exec not detected")
	}
}
