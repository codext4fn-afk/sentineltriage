// Package attack is the single source of truth for MITRE ATT&CK identifiers
// referenced anywhere in SentinelTriage. Rules and collectors cite IDs; this
// package decides whether those IDs exist.
//
// Mapping policy: cite a sub-technique only when the observed artifact proves
// it. When evidence is consistent with several sub-techniques, cite the parent.
package attack

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Version is the ATT&CK Enterprise release this table was curated against.
// It is stamped into every report so consumers can detect mapping drift.
//
// NOTE: when bumping, diff the release's revoked/deprecated object list against
// this table; renamed techniques keep their IDs but revoked ones do not.
const Version = "enterprise-v18"

// Tactic is an ATT&CK tactic short name.
type Tactic string

const (
	TacticExecution           Tactic = "execution"
	TacticPersistence         Tactic = "persistence"
	TacticPrivilegeEscalation Tactic = "privilege-escalation"
	TacticDefenseEvasion      Tactic = "defense-evasion"
	TacticCredentialAccess    Tactic = "credential-access"
	TacticCommandAndControl   Tactic = "command-and-control"
)

// Technique is a curated ATT&CK technique or sub-technique entry.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []Tactic `json:"tactics"`
}

// URL returns the canonical attack.mitre.org page for the technique.
func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/"
}

var idPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// table holds only techniques SentinelTriage can produce evidence for.
// Parents are listed whenever a sub-technique is, so fallback-to-parent is
// always resolvable.
var table = map[string]Technique{
	"T1014": {"T1014", "Rootkit", []Tactic{TacticDefenseEvasion}},

	"T1036":     {"T1036", "Masquerading", []Tactic{TacticDefenseEvasion}},
	"T1036.005": {"T1036.005", "Masquerading: Match Legitimate Resource Name or Location", []Tactic{TacticDefenseEvasion}},

	"T1053":     {"T1053", "Scheduled Task/Job", []Tactic{TacticExecution, TacticPersistence, TacticPrivilegeEscalation}},
	"T1053.003": {"T1053.003", "Scheduled Task/Job: Cron", []Tactic{TacticExecution, TacticPersistence, TacticPrivilegeEscalation}},
	"T1053.005": {"T1053.005", "Scheduled Task/Job: Scheduled Task", []Tactic{TacticExecution, TacticPersistence, TacticPrivilegeEscalation}},
	"T1053.006": {"T1053.006", "Scheduled Task/Job: Systemd Timers", []Tactic{TacticExecution, TacticPersistence, TacticPrivilegeEscalation}},

	"T1059":     {"T1059", "Command and Scripting Interpreter", []Tactic{TacticExecution}},
	"T1059.001": {"T1059.001", "Command and Scripting Interpreter: PowerShell", []Tactic{TacticExecution}},
	"T1059.004": {"T1059.004", "Command and Scripting Interpreter: Unix Shell", []Tactic{TacticExecution}},

	"T1070":     {"T1070", "Indicator Removal", []Tactic{TacticDefenseEvasion}},
	"T1070.004": {"T1070.004", "Indicator Removal: File Deletion", []Tactic{TacticDefenseEvasion}},

	"T1098":     {"T1098", "Account Manipulation", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1098.004": {"T1098.004", "Account Manipulation: SSH Authorized Keys", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},

	"T1218":     {"T1218", "System Binary Proxy Execution", []Tactic{TacticDefenseEvasion}},
	"T1218.005": {"T1218.005", "System Binary Proxy Execution: Mshta", []Tactic{TacticDefenseEvasion}},
	"T1218.010": {"T1218.010", "System Binary Proxy Execution: Regsvr32", []Tactic{TacticDefenseEvasion}},
	"T1218.011": {"T1218.011", "System Binary Proxy Execution: Rundll32", []Tactic{TacticDefenseEvasion}},

	"T1543":     {"T1543", "Create or Modify System Process", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1543.002": {"T1543.002", "Create or Modify System Process: Systemd Service", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1543.003": {"T1543.003", "Create or Modify System Process: Windows Service", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},

	"T1547":     {"T1547", "Boot or Logon Autostart Execution", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1547.001": {"T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1547.004": {"T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},

	"T1546":     {"T1546", "Event Triggered Execution", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},
	"T1546.004": {"T1546.004", "Event Triggered Execution: Unix Shell Configuration Modification", []Tactic{TacticPersistence, TacticPrivilegeEscalation}},

	"T1552":     {"T1552", "Unsecured Credentials", []Tactic{TacticCredentialAccess}},
	"T1552.001": {"T1552.001", "Unsecured Credentials: Credentials In Files", []Tactic{TacticCredentialAccess}},

	"T1571": {"T1571", "Non-Standard Port", []Tactic{TacticCommandAndControl}},

	"T1574":     {"T1574", "Hijack Execution Flow", []Tactic{TacticPersistence, TacticPrivilegeEscalation, TacticDefenseEvasion}},
	"T1574.006": {"T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", []Tactic{TacticPersistence, TacticPrivilegeEscalation, TacticDefenseEvasion}},
	"T1574.009": {"T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path", []Tactic{TacticPersistence, TacticPrivilegeEscalation, TacticDefenseEvasion}},

	"T1611": {"T1611", "Escape to Host", []Tactic{TacticPrivilegeEscalation}},

	"T1620": {"T1620", "Reflective Code Loading", []Tactic{TacticDefenseEvasion}},
}

// Lookup returns the curated entry for id.
func Lookup(id string) (Technique, bool) {
	t, ok := table[id]
	return t, ok
}

// Parent returns the parent technique ID for a sub-technique, or id unchanged.
func Parent(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// Validate rejects any ID that is malformed or absent from the curated table.
// Failing closed here is deliberate: an unknown ID in a report is worse than
// no ID, because downstream SOC tooling will trust it.
func Validate(ids []string) error {
	for _, id := range ids {
		if !idPattern.MatchString(id) {
			return fmt.Errorf("malformed ATT&CK technique ID %q", id)
		}
		if _, ok := table[id]; !ok {
			return fmt.Errorf("ATT&CK technique %q is not in the curated %s table", id, Version)
		}
	}
	return nil
}

// All returns every curated technique sorted by ID.
func All() []Technique {
	out := make([]Technique, 0, len(table))
	for _, t := range table {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
