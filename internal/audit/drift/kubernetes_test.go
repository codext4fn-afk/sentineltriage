package drift

import (
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
)

func TestKubernetesPrivilegedPod(t *testing.T) {
	body := `
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        capabilities:
          add: [SYS_ADMIN, NET_BIND_SERVICE]
`
	fs := analyze(Kubernetes{}, "pod.yaml", body)
	for _, rule := range []string{
		"drift.k8s.host-pid", "drift.k8s.privileged",
		"drift.k8s.privilege-escalation", "drift.k8s.run-as-root",
		"drift.k8s.dangerous-capability",
	} {
		if has(fs, rule) == nil {
			t.Errorf("missing %s; got %v", rule, ruleIDs(fs))
		}
	}
	// SYS_ADMIN is dangerous, NET_BIND_SERVICE is not: exactly one cap finding.
	cap := has(fs, "drift.k8s.dangerous-capability")
	if cap == nil || cap.Evidence["capability"] != "SYS_ADMIN" {
		t.Errorf("capability finding = %+v", cap)
	}
	if priv := has(fs, "drift.k8s.privileged"); priv != nil {
		if priv.Location.StartLine == 0 {
			t.Error("privileged finding has no source line")
		}
		if err := attack.Validate(priv.Techniques); err != nil {
			t.Errorf("privileged techniques invalid: %v", err)
		}
	}
}

func TestKubernetesDeploymentTemplateDescent(t *testing.T) {
	body := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:1.0
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
`
	fs := analyze(Kubernetes{}, "deploy.yaml", body)
	// Hardened container: no privileged/escalation/root findings.
	for _, rule := range []string{"drift.k8s.privileged", "drift.k8s.run-as-root", "drift.k8s.privilege-escalation"} {
		if has(fs, rule) != nil {
			t.Errorf("hardened deployment wrongly flagged %s", rule)
		}
	}
}

func TestKubernetesCronJobDeepNesting(t *testing.T) {
	body := `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: backup:latest
              securityContext:
                privileged: true
`
	if has(analyze(Kubernetes{}, "cron.yaml", body), "drift.k8s.privileged") == nil {
		t.Error("CronJob pod spec not reached through nested template")
	}
}

func TestKubernetesMultiDocument(t *testing.T) {
	body := `
kind: ConfigMap
metadata:
  name: cfg
data:
  k: v
---
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: x
      securityContext:
        privileged: true
`
	if has(analyze(Kubernetes{}, "multi.yaml", body), "drift.k8s.privileged") == nil {
		t.Error("second YAML document not analyzed")
	}
}

func TestKubernetesIgnoresNonManifestYAML(t *testing.T) {
	// A CI config and a Helm-templated file must not produce findings.
	for _, body := range []string{
		"jobs:\n  build:\n    steps:\n      - run: make\n",
		"image: {{ .Values.image }}\nprivileged: true\n",
	} {
		if fs := analyze(Kubernetes{}, "x.yaml", body); len(fs) != 0 {
			t.Errorf("non-manifest YAML flagged: %v", ruleIDs(fs))
		}
	}
}
