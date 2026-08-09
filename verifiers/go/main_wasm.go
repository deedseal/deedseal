//go:build js && wasm

// SPDX-License-Identifier: Apache-2.0
package main

import "syscall/js"

var verifyPassportFunction js.Func
var unreadableInputFunction js.Func

func wasmResult(result verdict) map[string]any {
	return map[string]any{
		"pass":                        result.pass,
		"reason":                      result.reason,
		"exit_code":                   verdictExitCode(result),
		"verdict":                     verdictLine(result),
		"owner_trust_anchor_key_id":   verdictOwnerKeyID(result),
		"custody_trust_anchor_key_id": custodyKeyID,
	}
}

func verifyPassportFromJS(_ js.Value, arguments []js.Value) any {
	uint8Array := js.Global().Get("Uint8Array")
	if len(arguments) != 1 || !arguments[0].InstanceOf(uint8Array) {
		return map[string]any{"error": "deedsealVerifyPassport expects one Uint8Array"}
	}
	input := arguments[0]
	raw := make([]byte, input.Get("byteLength").Int())
	js.CopyBytesToGo(raw, input)
	return wasmResult(verifyRaw(raw))
}

func unreadableInputFromJS(_ js.Value, _ []js.Value) any {
	// A browser cannot hand the verifier a missing pathname or a directory.
	// The native entry point classifies those I/O failures as passport_unreadable
	// before the shared verifier core runs. The conformance harness represents
	// the same input class through this explicit, non-file API.
	return wasmResult(unreadableVerdict())
}

func main() {
	verifyPassportFunction = js.FuncOf(verifyPassportFromJS)
	unreadableInputFunction = js.FuncOf(unreadableInputFromJS)
	js.Global().Set("deedsealVerifyPassport", verifyPassportFunction)
	js.Global().Set("deedsealVerifierUnreadable", unreadableInputFunction)
	js.Global().Set("deedsealVerifierReady", true)
	select {}
}
