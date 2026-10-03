// Command equivcheck compares a Go-agent envelope against a PowerShell-agent
// envelope collected on the same Windows host and reports implementation
// drift. It is the executable form of the dual-implementation contract:
//
//   - entity sets and entity_errors must match exactly;
//   - stable entities must agree on record counts and record keys;
//   - the assessment entities (shipped with unified contracts) must agree
//     on per-record field names; legacy entities report field drift as
//     warnings until their contracts are unified.
//
// Membership-ephemeral entities (processes, listening_ports, arp_neighbors)
// are warn-only: two back-to-back scans can legitimately disagree there.
// network_interfaces joins on MAC address (the implementations key NICs
// differently) and requires PS ⊆ Go, since Go also enumerates non-IP
// interfaces the PowerShell collector skips.
//
// Usage: equivcheck -go go.json -ps ps.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// warnEntities skip key/field comparison; count drift only warns.
var warnEntities = map[string]bool{
	"processes":       true,
	"listening_ports": true,
	"arp_neighbors":   true,
}

// strictFieldEntities shipped with unified cross-implementation contracts;
// field-name drift fails the gate. All other entities report field drift
// as warnings (legacy tech debt).
var strictFieldEntities = map[string]bool{
	"network_profiles": true, "wifi_networks": true, "proxy_config": true,
	"routes": true, "scheduled_tasks": true, "remote_access": true,
	"privileged_members": true, "password_policy": true, "update_health": true,
	"reliability": true, "machine_certs": true, "usb_history": true,
	"runtimes": true, "recovery": true, "network_interfaces": true,
}

type entity struct {
	Records []map[string]any `json:"records"`
}

type envelope struct {
	Entities     map[string]entity `json:"entities"`
	EntityErrors map[string]any    `json:"entity_errors"`
}

type report struct {
	failures []string
	warnings []string
	infos    []string
}

func (r *report) fail(s string) { r.failures = append(r.failures, s) }
func (r *report) warn(s string) { r.warnings = append(r.warnings, s) }
func (r *report) info(s string) { r.infos = append(r.infos, s) }

func main() {
	goPath := flag.String("go", "", "Go agent envelope JSON")
	psPath := flag.String("ps", "", "PowerShell agent envelope JSON")
	flag.Parse()
	if *goPath == "" || *psPath == "" {
		fmt.Fprintln(os.Stderr, "usage: equivcheck -go go.json -ps ps.json")
		os.Exit(2)
	}
	goEnv, err := loadEnvelope(*goPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load go envelope: %v\n", err)
		os.Exit(2)
	}
	psEnv, err := loadEnvelope(*psPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load ps envelope: %v\n", err)
		os.Exit(2)
	}
	rep := compare(goEnv, psEnv)
	for _, l := range rep.infos {
		fmt.Println("INFO  " + l)
	}
	for _, l := range rep.warnings {
		fmt.Println("WARN  " + l)
	}
	for _, l := range rep.failures {
		fmt.Println("FAIL  " + l)
	}
	if len(rep.failures) > 0 {
		fmt.Printf("EQUIVALENCE FAIL: %d failures, %d warnings\n", len(rep.failures), len(rep.warnings))
		os.Exit(1)
	}
	fmt.Printf("EQUIVALENCE PASS: %d entities compared, %d warnings\n", len(goEnv.Entities), len(rep.warnings))
}

func loadEnvelope(path string) (envelope, error) {
	var e envelope
	data, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	if e.Entities == nil {
		e.Entities = map[string]entity{}
	}
	if e.EntityErrors == nil {
		e.EntityErrors = map[string]any{}
	}
	return e, nil
}

func compare(goEnv, psEnv envelope) report {
	var rep report
	// 1. Entity sets must match exactly.
	goOnly, psOnly := keyDiff(keysOf(goEnv.Entities), keysOf(psEnv.Entities))
	if len(goOnly) > 0 {
		rep.fail(fmt.Sprintf("entities only in go: %s", strings.Join(goOnly, ", ")))
	}
	if len(psOnly) > 0 {
		rep.fail(fmt.Sprintf("entities only in ps: %s", strings.Join(psOnly, ", ")))
	}
	// 2. entity_errors keys must match exactly.
	goErrOnly, psErrOnly := keyDiff(keysOf(goEnv.EntityErrors), keysOf(psEnv.EntityErrors))
	if len(goErrOnly) > 0 {
		rep.fail(fmt.Sprintf("entity_errors only in go: %s", strings.Join(goErrOnly, ", ")))
	}
	if len(psErrOnly) > 0 {
		rep.fail(fmt.Sprintf("entity_errors only in ps: %s", strings.Join(psErrOnly, ", ")))
	}
	// 3-5. Per-entity comparison.
	for _, name := range keysOf(goEnv.Entities) {
		psEnt, ok := psEnv.Entities[name]
		if !ok {
			continue
		}
		compareEntity(&rep, name, goEnv.Entities[name], psEnt)
	}
	return rep
}

func compareEntity(rep *report, name string, goEnt, psEnt entity) {
	warnOnly := warnEntities[name]
	if len(goEnt.Records) != len(psEnt.Records) {
		msg := fmt.Sprintf("%s: record count go=%d ps=%d", name, len(goEnt.Records), len(psEnt.Records))
		if warnOnly || name == "network_interfaces" {
			// network_interfaces counts legitimately differ: Go also
			// enumerates non-IP interfaces the PS collector skips.
			rep.warn(msg)
		} else {
			rep.fail(msg)
		}
	}
	if warnOnly {
		return
	}
	goJoins := joinMap(name, goEnt.Records)
	psJoins := joinMap(name, psEnt.Records)
	if n := unjoinable(goEnt.Records, name) + unjoinable(psEnt.Records, name); n > 0 {
		rep.info(fmt.Sprintf("%s: %d records without a join value skipped", name, n))
	}
	goOnly, psOnly := keyDiff(keysOf(goJoins), keysOf(psJoins))
	if name == "network_interfaces" {
		// Asymmetric: every PS NIC must exist in Go; Go extras are
		// non-IP interfaces by design.
		if len(psOnly) > 0 {
			rep.fail(fmt.Sprintf("%s: PS NICs missing from Go: %s", name, strings.Join(psOnly, ", ")))
		} else if len(goOnly) > 0 {
			rep.info(fmt.Sprintf("%s: %d Go-only NICs (non-IP interfaces)", name, len(goOnly)))
		}
	} else {
		if len(goOnly) > 0 {
			rep.fail(fmt.Sprintf("%s: keys only in go: %s", name, strings.Join(capped(goOnly, 8), ", ")))
		}
		if len(psOnly) > 0 {
			rep.fail(fmt.Sprintf("%s: keys only in ps: %s", name, strings.Join(capped(psOnly, 8), ", ")))
		}
	}
	// Field-name parity on joined pairs.
	goFields, psFields := map[string]int{}, map[string]int{}
	pairs := 0
	for j, grec := range goJoins {
		prec, ok := psJoins[j]
		if !ok {
			continue
		}
		pairs++
		for f := range dataFields(grec) {
			goFields[f]++
		}
		for f := range dataFields(prec) {
			psFields[f]++
		}
	}
	if pairs == 0 {
		return
	}
	goFOnly, psFOnly := keyDiff(keysOf(goFields), keysOf(psFields))
	if len(goFOnly)+len(psFOnly) == 0 {
		return
	}
	msg := fmt.Sprintf("%s: field drift over %d joined records (go-only: [%s] ps-only: [%s])",
		name, pairs, strings.Join(goFOnly, ", "), strings.Join(psFOnly, ", "))
	if strictFieldEntities[name] {
		rep.fail(msg)
	} else {
		rep.warn("legacy " + msg)
	}
}

// joinKey identifies a record across implementations. NIC keys differ by
// design (Go keys by OS name, PS by index+MAC), so NICs join on MAC.
func joinKey(entity string, rec map[string]any) string {
	if entity == "network_interfaces" {
		if mac, _ := rec["mac_address"].(string); mac != "" {
			return "mac:" + strings.ToLower(mac)
		}
		return ""
	}
	key, _ := rec["key"].(string)
	return key
}

func joinMap(entity string, recs []map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, r := range recs {
		if j := joinKey(entity, r); j != "" {
			m[j] = r
		}
	}
	return m
}

func unjoinable(recs []map[string]any, entity string) int {
	n := 0
	for _, r := range recs {
		if joinKey(entity, r) == "" {
			n++
		}
	}
	return n
}

// dataFields returns non-envelope field names with null-valued fields
// dropped, so explicit-null and omitted-field styles compare equal.
func dataFields(rec map[string]any) map[string]bool {
	m := map[string]bool{}
	for k, v := range rec {
		if k == "key" || k == "fingerprint" || k == "observed_at" {
			continue
		}
		if v == nil {
			continue
		}
		m[k] = true
	}
	return m
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keyDiff returns sorted (onlyInA, onlyInB).
func keyDiff(a, b []string) ([]string, []string) {
	inB := map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	inA := map[string]bool{}
	for _, x := range a {
		inA[x] = true
	}
	var onlyA, onlyB []string
	for _, x := range a {
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}

func capped(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("…+%d more", len(s)-n))
}
