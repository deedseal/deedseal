// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ownerKeyID = "kbp-owner-ed25519-v0.2"
	ownerKeyHex = "5e6e3cd40ec7feed51f0a3d803a4e105f14dd07d2a221e6edef072cc7952bcde"
	custodyKeyID = "kbp-service-custody-ed25519-v0.1"
	custodyKeyHex = "86f86166be52a9264cd9176b7a31fb5dccaa6c5c6fd2d01aa2a33b769dd6a6c5"
)

type object = map[string]any

func block(reason string) (bool, string) { return false, reason }
func obj(v any) (object, bool) { x, ok := v.(map[string]any); return x, ok }
func str(m object, k string) (string, bool) { x, ok := m[k].(string); return x, ok }
func arr(m object, k string) ([]any, bool) { x, ok := m[k].([]any); return x, ok }
func boolean(m object, k string) (bool, bool) { x, ok := m[k].(bool); return x, ok }
func integer(m object, k string) (int64, bool) {
	n, ok := m[k].(json.Number); if !ok { return 0, false }; i, e := strconv.ParseInt(string(n), 10, 64); return i, e == nil
}
func keysExactly(m object, names ...string) bool {
	if len(m) != len(names) { return false }; for _, n := range names { if _, ok := m[n]; !ok { return false } }; return true
}
func lowerHex(s string, n int) bool {
	if len(s) != n { return false }; for _, c := range s { if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false } }; return true
}
func stringSlice(v any) ([]string, bool) {
	a, ok := v.([]any); if !ok { return nil, false }; out := make([]string, len(a)); for i, x := range a { s, ok := x.(string); if !ok { return nil, false }; out[i] = s }; return out, true
}
func normalizePaths(v any) ([]string, bool) {
	a, ok := stringSlice(v); if !ok { return nil, false }; seen := map[string]bool{}; out := []string{}
	for _, p := range a { p = strings.TrimSpace(p); if !seen[p] { seen[p] = true; out = append(out, p) } }; sort.Strings(out); return out, true
}
func sameStrings(a, b []string) bool { if len(a) != len(b) { return false }; for i := range a { if a[i] != b[i] { return false } }; return true }

// canonicalJSON reproduces Python json.dumps(..., sort_keys=True,
// separators=(",", ":"), ensure_ascii=True, allow_nan=False).
func canonicalJSON(v any) ([]byte, error) { var b bytes.Buffer; if err := writeCanonical(&b, v); err != nil { return nil, err }; return b.Bytes(), nil }
func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil: b.WriteString("null")
	case bool: if x { b.WriteString("true") } else { b.WriteString("false") }
	case string: writePyString(b, x)
	case json.Number:
		s := string(x); if _, err := strconv.ParseInt(s, 10, 64); err == nil { b.WriteString(s); return nil }; return fmt.Errorf("unsupported non-integer number")
	case []any:
		b.WriteByte('['); for i, y := range x { if i > 0 { b.WriteByte(',') }; if err := writeCanonical(b, y); err != nil { return err } }; b.WriteByte(']')
	case map[string]any:
		ks := make([]string, 0, len(x)); for k := range x { ks = append(ks, k) }; sort.Strings(ks)
		b.WriteByte('{'); for i, k := range ks { if i > 0 { b.WriteByte(',') }; writePyString(b, k); b.WriteByte(':'); if err := writeCanonical(b, x[k]); err != nil { return err } }; b.WriteByte('}')
	default: return fmt.Errorf("unsupported JSON value %T", v)
	}; return nil
}
func writePyString(b *bytes.Buffer, s string) {
	b.WriteByte('"'); for _, r := range s { switch r { case '\\': b.WriteString("\\\\"); case '"': b.WriteString("\\\""); case '\b': b.WriteString("\\b"); case '\f': b.WriteString("\\f"); case '\n': b.WriteString("\\n"); case '\r': b.WriteString("\\r"); case '\t': b.WriteString("\\t"); default:
		if r >= 0x20 && r < 0x7f { b.WriteRune(r) } else if r <= 0xffff { fmt.Fprintf(b, "\\u%04x", r) } else { a, c := utf16.EncodeRune(r); fmt.Fprintf(b, "\\u%04x\\u%04x", a, c) }
	} }; b.WriteByte('"')
}

var errDuplicate = errors.New("duplicate key")
var errTrailing = errors.New("trailing content")
func parseJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) { return nil, io.ErrUnexpectedEOF }
	d := json.NewDecoder(bytes.NewReader(raw)); d.UseNumber(); v, err := parseValue(d); if err != nil { return nil, err }
	if _, err = d.Token(); err == nil { return nil, errTrailing } else if !errors.Is(err, io.EOF) { return nil, errTrailing }
	return v, nil
}
func parseValue(d *json.Decoder) (any, error) {
	t, err := d.Token(); if err != nil { return nil, err }
	delim, ok := t.(json.Delim); if !ok { return t, nil }
	switch delim {
	case '{':
		m := object{}; for d.More() { kt, err := d.Token(); if err != nil { return nil, err }; k, ok := kt.(string); if !ok { return nil, errors.New("object key") }; if _, exists := m[k]; exists { return nil, errDuplicate }; v, err := parseValue(d); if err != nil { return nil, err }; m[k] = v }; end, err := d.Token(); if err != nil || end != json.Delim('}') { return nil, errors.New("object end") }; return m, nil
	case '[':
		a := []any{}; for d.More() { v, err := parseValue(d); if err != nil { return nil, err }; a = append(a, v) }; end, err := d.Token(); if err != nil || end != json.Delim(']') { return nil, errors.New("array end") }; return a, nil
	default: return nil, errors.New("unexpected delimiter")
	}
}

func signature(m object, version, keyID, malformed, wrong, invalid string, payload []byte, pubHex string) (bool, string) {
	if !keysExactly(m, "signature_version", "signature_algorithm", "signing_key_id", "signature_hex") { return block(malformed) }
	v, vok := str(m, "signature_version"); alg, aok := str(m, "signature_algorithm"); kid, kok := str(m, "signing_key_id"); sh, sok := str(m, "signature_hex")
	if !vok || !aok || !kok || !sok || v != version || alg != "ed25519" || !lowerHex(sh, 128) { return block(malformed) }
	if kid != keyID { return block(wrong) }
	pub, _ := hex.DecodeString(pubHex); sig, _ := hex.DecodeString(sh)
	if smallOrderPublicKey(pub) { return block(invalid) }
	// crypto/ed25519 rejects non-canonical S values. The pinned public keys are
	// decoded constants and are not small-order points.
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) { return block(invalid) }; return true, ""
}

func smallOrderPublicKey(publicKey []byte) bool {
	// The canonical torsion encodings and their non-canonical aliases are a
	// closed set. Keeping this check outside crypto/ed25519 makes the anchor
	// rule explicit even if the standard library's point checks change.
	weak := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e1dd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	encoded := hex.EncodeToString(publicKey); for _, candidate := range weak { if encoded == candidate { return true } }; return false
}

func normalizeAcceptance(v any) (object, bool) {
	m, ok := obj(v); if !ok || !keysExactly(m, "expected_changed_paths", "markers") { return nil, false }
	p, ok := normalizePaths(m["expected_changed_paths"]); if !ok { return nil, false }; markers, ok := obj(m["markers"]); if !ok { return nil, false }
	nm := object{}; for k, v := range markers { nm[strings.TrimSpace(k)] = fmt.Sprint(v) }
	pa := make([]any, len(p)); for i := range p { pa[i] = p[i] }; return object{"expected_changed_paths": pa, "markers": nm}, true
}

func verify(p object, raw []byte) (bool, string) {
	required := []string{"schema_version","roadmap_step","run_id","execution_id","implementation_head_sha","authorization","custody","scope","execution","committed_binding","closure"}
	allowed := append(append([]string{}, required...), "supplementary_evidence")
	for k := range p { found := false; for _, a := range allowed { if k == a { found = true } }; if !found { return block("block_run_passport_unknown_field") } }
	for _, k := range required { if _, ok := p[k]; !ok { return block("block_run_passport_missing_field") } }
	if sv, ok := str(p, "schema_version"); !ok || sv != "deedseal-run-passport/1.0" { return block("block_run_passport_schema_unsupported") }
	for _, k := range []string{"authorization","custody","scope","execution","committed_binding","closure"} { if _, ok := obj(p[k]); !ok { return block("block_run_passport_malformed_section") } }
	for _, k := range []string{"roadmap_step","run_id","execution_id","implementation_head_sha"} { if s, ok := str(p,k); !ok || s == "" { return block("block_public_run_passport_contract_malformed") } }
	auth,_ := obj(p["authorization"]); custody,_ := obj(p["custody"]); scope,_ := obj(p["scope"]); execution,_ := obj(p["execution"]); committed,_ := obj(p["committed_binding"]); closure,_ := obj(p["closure"])

	osig, ok := obj(auth["owner_signature"]); if !ok { return block("block_owner_authorization_malformed") }
	grantFields := []string{"grant_id","issued_by","allowed_scope","operation_class","nonce","issued_at","expires_at","run_id","head_sha","task_prompt","publication_class"}
	grant := object{"signature_version":"owner-grant-signature-v0.6"}; for _, k := range grantFields { v, exists := auth[k]; if !exists { return block("block_owner_authorization_malformed") }; grant[k]=v }
	if b, exists := auth["budget"]; exists && b != nil { return block("block_owner_authorization_malformed") }
	af, ok := normalizePaths(auth["allowed_files"]); if !ok { return block("block_owner_authorization_malformed") }; nf, ok := normalizePaths(auth["new_files"]); if !ok { return block("block_owner_authorization_malformed") }; ac, ok := normalizeAcceptance(auth["acceptance_contract"]); if !ok { return block("block_owner_authorization_malformed") }
	grant["allowed_files"] = toAny(af); grant["new_files"] = toAny(nf); grant["acceptance_contract"] = ac
	osigFields := object{}
	for _, k := range []string{"signature_version", "signature_algorithm", "signing_key_id", "signature_hex"} {
		v, exists := osig[k]; if !exists { return block("block_owner_authorization_malformed") }; osigFields[k] = v
	}
	gp, _ := canonicalJSON(grant); if pass, reason := signature(osigFields,"owner-grant-signature-v0.6",ownerKeyID,"block_owner_authorization_malformed","block_owner_authorization_wrong_key","block_owner_authorization_signature_invalid",gp,ownerKeyHex); !pass { return pass, reason }

	if rs, ok := str(custody,"record_schema"); !ok || rs != "deedseal-supervised-run-custody/1.0" { return block("block_custody_record_schema_unsupported") }
	csig, ok := obj(custody["signature"]); if !ok { return block("block_custody_record_malformed") }
	custodyNames := []string{"record_schema","publication_class","step","record_status","reason_code","execution_id","run_id","roadmap_step","evidence_ref","head_sha","target","allowed_files","argv","working_directory","agent_executable","grant_id","grant_sha256","gate_verdict","gate_reason_code","client_uid","authorized_at","completed_at","observed_pre_worktree_entries","observed_post_worktree_entries","observed_post_head_sha","observed_changed_file_count","runner_report","signature"}
	if !keysExactly(custody,custodyNames...) { return block("block_custody_record_malformed") }
	unsigned := object{}; for k,v := range custody { if k != "signature" { unsigned[k]=v } }
	ckid,_ := str(csig,"signing_key_id"); cpayload,_ := canonicalJSON(object{"domain":"kbp-service-custody-record-signature-v0.1","signature_version":"kbp-service-custody-record-signature/0.1","signature_algorithm":"ed25519","signing_key_id":ckid,"record":unsigned})
	if pass, reason := signature(csig,"kbp-service-custody-record-signature/0.1",custodyKeyID,"block_custody_record_malformed","block_custody_record_wrong_key","block_custody_record_signature_invalid",cpayload,custodyKeyHex); !pass { return pass, reason }

	if !custodyContract(p, auth, custody) { return block("block_custody_publication_contract_malformed") }
	ab, _ := canonicalJSON(auth); h := fmt.Sprintf("%x", sha256.Sum256(ab)); cg,_ := str(custody,"grant_sha256"); if h != cg { return block("block_grant_custody_binding_mismatch") }
	if strv(p,"run_id") != strv(auth,"run_id") || strv(p,"run_id") != strv(custody,"run_id") { return block("block_run_id_binding_mismatch") }
	if strv(p,"execution_id") != strv(custody,"execution_id") { return block("block_execution_id_binding_mismatch") }
	head:=strv(p,"implementation_head_sha"); if head!=strv(auth,"head_sha") || head!=strv(custody,"head_sha") || head!=strv(custody,"observed_post_head_sha") { return block("block_implementation_head_binding_mismatch") }
	if strv(auth,"grant_id") != strv(custody,"grant_id") { return block("block_grant_id_binding_mismatch") }

	if !keysExactly(scope,"allowed_files","new_files","acceptance_contract") { return block("block_public_run_passport_contract_malformed") }
	sf,ok:=normalizePaths(scope["allowed_files"]); if !ok || !sameStrings(sf,af) { return block("block_allowed_files_binding_mismatch") }; cf,ok:=normalizePaths(custody["allowed_files"]); if !ok || !sameStrings(cf,af) { return block("block_allowed_files_binding_mismatch") }
	sn,ok:=normalizePaths(scope["new_files"]); if !ok || !sameStrings(sn,nf) { return block("block_new_files_binding_mismatch") }; for _,n:=range sn { if !contains(sf,n) { return block("block_new_files_binding_mismatch") } }
	sac,ok:=normalizeAcceptance(scope["acceptance_contract"]); if !ok || !deepEqual(sac,ac) { return block("block_acceptance_contract_binding_mismatch") }; ep,_:=normalizePaths(sac["expected_changed_paths"]); if !sameStrings(ep,sf) { return block("block_acceptance_contract_binding_mismatch") }
	if !executionBindings(execution,custody,sf,sn) { return block("block_observed_paths_binding_mismatch") }
	if !shaChain(execution,sf,sn) { return block("block_sha256_chain_binding_mismatch") }
	ci,ok:=obj(committed["commit_identity"]); if !ok || !keysExactly(committed,"commit_identity","changed_paths","committed_file_hashes") || !keysExactly(ci,"parent_sha","commit_sha") || !lowerHex(strv(ci,"parent_sha"),40) || !lowerHex(strv(ci,"commit_sha"),40) { return block("block_commit_identity_binding_mismatch") }
	if strv(ci,"parent_sha") != head { return block("block_complete_cargo_changeset_binding_mismatch") }; changed,ok:=normalizePaths(committed["changed_paths"]); rawChanged,_:=stringSlice(committed["changed_paths"]); if !ok || !sameStrings(changed,rawChanged) || !sameStrings(changed,sf) { return block("block_complete_cargo_changeset_binding_mismatch") }; if strv(ci,"commit_sha")==head { return block("block_cargo_commit_equals_execution_head") }
	if !committedHashes(committed,execution,sf) { return block("block_committed_hash_binding_mismatch") }
	if !boundaryContract(custody,sf,cg) { return block("block_public_run_passport_contract_malformed") }
	if !keysExactly(closure,"closure_version","signature") { if _,yes:=closure["signature"]; !yes { return block("block_owner_closure_signature_missing") }; return block("block_owner_closure_unknown_field") }
	clv,_:=str(closure,"closure_version"); clsig,ok:=obj(closure["signature"]); if !ok { return block("block_owner_closure_signature_missing") }
	core:=object{}; for k,v:=range p { if k!="closure" { core[k]=v } }; closePayload,_:=canonicalJSON(object{"domain":"kbp-run-passport-v1-owner-closure-signature-v0.1","closure_version":clv,"passport_core":core})
	if pass,reason:=signature(clsig,"kbp-run-passport-v1-owner-closure/0.1",ownerKeyID,"block_owner_closure_signature_malformed","block_owner_closure_signature_wrong_key","block_owner_closure_signature_invalid",closePayload,ownerKeyHex); !pass { return pass,reason }
	canon,err:=canonicalJSON(p); if err!=nil || !bytes.Equal(canon,raw) { return block("block_public_run_passport_noncanonical_serialization") }
	return true,""
}

func toAny(s []string) []any { a:=make([]any,len(s)); for i:=range s { a[i]=s[i] }; return a }
func strv(m object,k string) string { s,_:=str(m,k); return s }
func contains(a []string,s string) bool { for _,x:=range a { if x==s{return true} }; return false }
func deepEqual(a,b any) bool { x,_:=canonicalJSON(a); y,_:=canonicalJSON(b); return bytes.Equal(x,y) }

func custodyContract(p,auth,c object) bool {
	vals:=map[string]string{"publication_class":"public-full-record","step":"deedseal-bounded-file-set/1.0","record_status":"OUTCOME_SUCCESS","reason_code":"allow_supervised_agent_capture_recorded","roadmap_step":"deedseal-public-run/1.0","evidence_ref":"deedseal-public-run/1.0","target":"deedseal-bounded-file-set/1.0/edit","agent_executable":"/opt/agent-runner/bin/agent","gate_verdict":"allow"}; for k,v:=range vals { if strv(c,k)!=v{return false} }
	if strv(p,"roadmap_step")!=strv(c,"roadmap_step") || strv(auth,"publication_class")!="public-full-record" || strv(auth,"operation_class")!="agent_subprocess" || strv(auth,"allowed_scope")!=strv(c,"target") || strv(c,"publication_class")!="public-full-record" { return false }
	eid:=strv(c,"execution_id"); if !lowerHex(eid,32) || strv(c,"working_directory")!="/var/lib/deedseal-quarantine/"+eid {return false}; av,ok:=stringSlice(c["argv"]); if !ok||len(av)==0||av[0]!="/opt/agent-runner/bin/agent"{return false}
	r,ok:=obj(c["runner_report"]); if !ok || !keysExactly(r,"protocol_version","execution_id","run_id","head_sha","report_status","argv","exit_code","stdout_sha256","stderr_sha256","stdout_excerpt","stderr_excerpt","os_boundary","publication_class") {return false}; if strv(r,"protocol_version")!="deedseal-agent-runner/1.0"||strv(r,"publication_class")!="public-full-record"||!deepEqual(r["argv"],c["argv"])||!lowerHex(strv(r,"stdout_sha256"),64)||!lowerHex(strv(r,"stderr_sha256"),64)||strv(r,"stdout_excerpt")!="[redacted:public-full-record]"||strv(r,"stderr_excerpt")!="[redacted:public-full-record]"{return false}; return true
}
func executionBindings(e,c object,allowed,newf []string) bool {
	if !keysExactly(e,"observed_pre_worktree_entries","observed_post_worktree_entries","observed_post_head_sha","observed_changed_file_count","sha256_chain"){return false}; for _,k:=range []string{"observed_pre_worktree_entries","observed_post_worktree_entries","observed_post_head_sha","observed_changed_file_count"}{if !deepEqual(e[k],c[k]){return false}}
	post,ok:=normalizePaths(e["observed_post_worktree_entries"]); count,cok:=integer(e,"observed_changed_file_count"); return ok&&cok&&int(count)==len(allowed)&&sameStrings(post,allowed)
}
func shaChain(e object,allowed,newf []string) bool {
	chain,ok:=obj(e["sha256_chain"]); if !ok||len(chain)!=len(allowed){return false}; for _,p:=range allowed { x,ok:=obj(chain[p]); if !ok||!keysExactly(x,"seed_sha256","staged_sha256","materialized_sha256","seed_staged_differ","stage_materialize_equal"){return false}; staged:=strv(x,"staged_sha256"); mat:=strv(x,"materialized_sha256"); equal,eok:=boolean(x,"stage_materialize_equal"); if !lowerHex(staged,64)||!lowerHex(mat,64)||staged!=mat||!eok||!equal{return false}; if contains(newf,p){if x["seed_sha256"]!=nil||x["seed_staged_differ"]!=nil{return false}}else{seed,sok:=x["seed_sha256"].(string); diff,dok:=x["seed_staged_differ"].(bool); if !sok||!lowerHex(seed,64)||seed==staged||!dok||!diff{return false}} }; return true
}
func committedHashes(c,e object,allowed []string) bool { h,ok:=obj(c["committed_file_hashes"]); chain,_:=obj(e["sha256_chain"]); if !ok||len(h)!=len(allowed){return false}; for _,p:=range allowed{x,_:=obj(chain[p]); if strv(h,p)!=strv(x,"materialized_sha256"){return false}}; return true }
func boundaryContract(c object,allowed []string,grant string) bool {
	r,_:=obj(c["runner_report"]); b,ok:=obj(r["os_boundary"]); if !ok||!keysExactly(b,"schema_version","application_status","abi","no_new_privs","handled_access_fs","default_for_handled_access","grant_sha256","rules","runtime_scratch"){return false}; abi,aok:=integer(b,"abi"); nnp,nok:=boolean(b,"no_new_privs"); rights,_:=stringSlice(b["handled_access_fs"]); want:=[]string{"write_file","remove_dir","remove_file","make_char","make_dir","make_reg","make_sock","make_fifo","make_block","make_sym"}; if !aok||abi<1||!nok||!nnp||strv(b,"schema_version")!="deedseal-landlock-applied-boundary/1.1"||strv(b,"application_status")!="applied"||strv(b,"default_for_handled_access")!="deny"||strv(b,"grant_sha256")!=grant||!sameStrings(rights,want){return false}
	rules,ok:=b["rules"].([]any); if !ok||len(rules)!=len(allowed){return false}; for i,v:=range rules{x,ok:=obj(v); if !ok||!keysExactly(x,"allowed_file","object_dev","object_ino","allowed_access_fs")||strv(x,"allowed_file")!=allowed[i]||!deepEqual(x["allowed_access_fs"],[]any{"write_file"}){return false}; d,dok:=integer(x,"object_dev"); ino,iok:=integer(x,"object_ino"); if !dok||!iok||d<0||ino<0{return false}}
	s,ok:=obj(b["runtime_scratch"]); if !ok||!keysExactly(s,"scratch_class","scratch_root_sha256","object_dev","object_ino","allowed_access_fs")||strv(s,"scratch_class")!="agent_runtime_scratch"||strv(s,"scratch_root_sha256")!="768f8b3b2a86cdbe6f711c61f47642ef334b113d22fdfee51ee28eb945e5ad8a"||!deepEqual(s["allowed_access_fs"],[]any{"write_file","make_dir","make_reg"}){return false}; d,dok:=integer(s,"object_dev"); ino,iok:=integer(s,"object_ino"); return dok&&iok&&d>=0&&ino>=0
}

// verdict is the one result produced by the shared verifier core. Native and
// WebAssembly entry points only acquire input and render this result; neither
// re-implements any PASS/BLOCK decision.
type verdict struct{pass bool;reason string}
func verifyRaw(raw []byte) verdict{
	v,err:=parseJSON(raw); if err!=nil{reason:="block_run_passport_unparseable";if errors.Is(err,errDuplicate){reason="block_run_passport_duplicate_key"}else if errors.Is(err,errTrailing){reason="block_run_passport_trailing_content"};return verdict{false,reason}}
	p,ok:=obj(v);if !ok{return verdict{false,"block_run_passport_not_object"}};pass,reason:=verify(p,raw);return verdict{pass,reason}
}
func verdictOwnerKeyID(result verdict) string{if result.pass{return ownerKeyID};return "unverified"}
func verdictLine(result verdict) string{if result.pass{return "RUN_PASSPORT_VERDICT: PASS"};return "RUN_PASSPORT_VERDICT: BLOCK "+result.reason}
func verdictOutput(result verdict) string{return "owner_trust_anchor_key_id: "+verdictOwnerKeyID(result)+"\ncustody_trust_anchor_key_id: "+custodyKeyID+"\n"+verdictLine(result)}
func verdictExitCode(result verdict) int{if result.pass{return 0};return 1}
func unreadableVerdict() verdict{return verdict{false,"passport_unreadable"}}
