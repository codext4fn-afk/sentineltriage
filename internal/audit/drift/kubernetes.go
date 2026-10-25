package drift

import (
	"path"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/afind"
	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Kubernetes analyzes Kubernetes manifests for privilege and isolation
// weaknesses. It parses YAML into nodes rather than typed structs so that
// every finding can cite the exact source line, which is what makes the SARIF
// output actionable in a pull-request review.
type Kubernetes struct{}

// Name implements audit.Analyzer.
func (Kubernetes) Name() string { return "drift.kubernetes" }

// workloadKinds carry a pod template this analyzer understands.
var workloadKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"ReplicaSet": true, "Job": true, "CronJob": true, "ReplicationController": true,
}

// Applies matches .yaml/.yml files. Content is confirmed to be a Kubernetes
// object inside Analyze, since YAML is used for much more than manifests.
func (Kubernetes) Applies(f walker.File) bool {
	ext := strings.ToLower(path.Ext(f.Rel))
	return ext == ".yaml" || ext == ".yml"
}

// Analyze implements audit.Analyzer.
func (k Kubernetes) Analyze(f walker.File, emit func(finding.Finding)) {
	dec := yaml.NewDecoder(strings.NewReader(string(f.Content)))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			// Malformed or non-Kubernetes YAML is out of scope, not an error:
			// a Helm template or a CI config will not decode cleanly, and the
			// audit must not fail on it.
			return
		}
		root := documentRoot(&doc)
		if root == nil || root.Kind != yaml.MappingNode {
			continue
		}
		kind := scalar(mapGet(root, "kind"))
		if !workloadKinds[kind] {
			continue
		}
		k.inspect(f.Rel, kind, root, emit)
	}
}

// inspect walks from a workload root to its pod spec and container list.
func (k Kubernetes) inspect(rel, kind string, root *yaml.Node, emit func(finding.Finding)) {
	name := scalar(mapGet(descend(root, "metadata"), "name"))
	podSpec := podSpecOf(kind, root)
	if podSpec == nil {
		return
	}
	ctx := identity{rel: rel, kind: kind, name: name}

	k.checkPodSpec(ctx, podSpec, emit)
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, c := range seq(mapGet(podSpec, field)) {
			k.checkContainer(ctx, c, emit)
		}
	}
}

type identity struct {
	rel, kind, name string
}

func (id identity) ev(b afind.B, node *yaml.Node) afind.B {
	b = b.Path(id.rel).Evidence("kind", id.kind)
	if id.name != "" {
		b = b.Evidence("name", id.name)
	}
	if node != nil && node.Line > 0 {
		b = b.Line(node.Line)
	}
	return b
}

func (Kubernetes) checkPodSpec(id identity, spec *yaml.Node, emit func(finding.Finding)) {
	for _, hn := range []struct {
		field, rule, label string
	}{
		{"hostPID", "drift.k8s.host-pid", "hostPID"},
		{"hostNetwork", "drift.k8s.host-network", "hostNetwork"},
		{"hostIPC", "drift.k8s.host-ipc", "hostIPC"},
	} {
		if n := mapGet(spec, hn.field); isTrue(n) {
			emit(id.ev(afind.New(hn.rule,
				"Pod shares the host's "+hn.label+" namespace",
				finding.SeverityHigh, finding.ConfidenceHigh), n).
				Tech("T1611").
				Fix("Remove " + hn.label + ": true; sharing a host namespace erases the container/host isolation boundary.").Done())
		}
	}
}

func (Kubernetes) checkContainer(id identity, c *yaml.Node, emit func(finding.Finding)) {
	cname := scalar(mapGet(c, "name"))
	sc := mapGet(c, "securityContext")
	anchor := func(preferred *yaml.Node) *yaml.Node {
		if preferred != nil {
			return preferred
		}
		if nameNode := mapGet(c, "name"); nameNode != nil {
			return nameNode
		}
		return c
	}
	withContainer := func(b afind.B, n *yaml.Node) afind.B {
		b = id.ev(b, anchor(n))
		if cname != "" {
			b = b.Evidence("container", cname)
		}
		return b
	}

	if n := mapGet(sc, "privileged"); isTrue(n) {
		emit(withContainer(afind.New("drift.k8s.privileged",
			"Container runs in privileged mode",
			finding.SeverityCritical, finding.ConfidenceHigh), n).
			Tech("T1611").
			Fix("Remove privileged: true. A privileged container holds all capabilities and can access host devices, which is a direct path to host compromise.").Done())
	}

	// runAsNonRoot defaults to false, so absence is itself the weakness; the
	// finding anchors on the securityContext, or the container, when absent.
	if runAsNonRoot := mapGet(sc, "runAsNonRoot"); !isTrue(runAsNonRoot) {
		if uid := mapGet(sc, "runAsUser"); scalar(uid) != "0" && uid != nil {
			// An explicit non-zero runAsUser is an acceptable alternative.
		} else {
			emit(withContainer(afind.New("drift.k8s.run-as-root",
				"Container may run as root (runAsNonRoot not set)",
				finding.SeverityMedium, finding.ConfidenceMedium), sc).
				Fix("Set securityContext.runAsNonRoot: true (and a non-zero runAsUser) so the kubelet refuses to start the container as UID 0.").Done())
		}
	}

	// allowPrivilegeEscalation defaults to true.
	if ape := mapGet(sc, "allowPrivilegeEscalation"); ape == nil || isTrue(ape) {
		emit(withContainer(afind.New("drift.k8s.privilege-escalation",
			"Container allows privilege escalation",
			finding.SeverityMedium, finding.ConfidenceMedium), ape).
			Fix("Set securityContext.allowPrivilegeEscalation: false to block setuid binaries and file capabilities from granting more privilege than the parent process.").Done())
	}

	for _, cap := range seq(descend(sc, "capabilities", "add")) {
		name := strings.ToUpper(scalar(cap))
		if dangerousCap[name] {
			emit(withContainer(afind.New("drift.k8s.dangerous-capability",
				"Container adds a dangerous Linux capability",
				finding.SeverityHigh, finding.ConfidenceHigh), cap).
				Evidence("capability", name).Tech("T1611").
				Fix("Drop ALL capabilities and add back only the specific, non-escalating ones the workload needs.").Done())
		}
	}
}

// dangerousCap lists capabilities that grant host-level power or are common
// container-escape primitives.
var dangerousCap = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"NET_ADMIN": true, "NET_RAW": true, "DAC_READ_SEARCH": true, "SYS_BOOT": true,
}

// podSpecOf returns the pod spec node for a workload kind, descending through
// the controller's template where one exists. CronJob nests one level deeper.
func podSpecOf(kind string, root *yaml.Node) *yaml.Node {
	switch kind {
	case "Pod":
		return mapGet(root, "spec")
	case "CronJob":
		return descend(root, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return descend(root, "spec", "template", "spec")
	}
}

// --- yaml.Node navigation helpers ---

func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return n.Content[0]
	}
	return n
}

// mapGet returns the value node for key in a mapping node, or nil.
func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// descend follows a chain of mapping keys.
func descend(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		n = mapGet(n, k)
		if n == nil {
			return nil
		}
	}
	return n
}

func seq(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// isTrue reports whether n is a scalar YAML true.
func isTrue(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && strings.EqualFold(n.Value, "true")
}
