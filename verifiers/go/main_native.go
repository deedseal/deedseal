//go:build !js || !wasm

// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: verify_run_passport <passport-path>")
		fmt.Fprintln(os.Stderr, "verify exactly one Deedseal run passport")
		os.Exit(2)
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "RUN_PASSPORT_VERDICT: BLOCK passport_unreadable (%v)\n", err)
		os.Exit(1)
	}

	result := verifyRaw(raw)
	fmt.Println(verdictOutput(result))
	os.Exit(verdictExitCode(result))
}
