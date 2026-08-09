// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BLOCK_VERDICT_PREFIX,
  PASS_VERDICT,
  provePublishedRuns,
} from "./demo/proof.mjs";

const wasmDirectory = dirname(fileURLToPath(import.meta.url));
const demoDirectory = resolve(wasmDirectory, "demo");
const repositoryRoot = resolve(wasmDirectory, "../..");
const manifestPath = resolve(repositoryRoot, "examples/verified/conformance/manifest.json");
const wasmManifestPath = resolve(wasmDirectory, "deedseal-verifier.wasm.manifest.json");
const nativeBinary = process.argv[2];

function fail(message) {
  throw new Error(message);
}

function verdictLines(output) {
  return output
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("RUN_PASSPORT_VERDICT: "));
}

function nativeReport(inputPath) {
  const completed = spawnSync(nativeBinary, [inputPath], { encoding: "utf8" });
  if (completed.error) {
    fail(`native verifier could not run: ${completed.error.message}`);
  }
  const lines = verdictLines(`${completed.stdout}\n${completed.stderr}`);
  if (lines.length !== 1) {
    fail(`native verifier produced ${lines.length} verdict lines for ${inputPath}`);
  }
  return { exitCode: completed.status, verdict: lines[0] };
}

function assertWasmReport(report, vector) {
  if (!report || typeof report !== "object" || typeof report.verdict !== "string") {
    fail(`${vector.id}: WebAssembly did not return a verifier report`);
  }
  if (report.exit_code !== vector.expect_exit_code) {
    fail(`${vector.id}: WebAssembly exit ${report.exit_code}, expected ${vector.expect_exit_code}`);
  }
  if (vector.expect_verdict === "PASS") {
    if (report.verdict !== PASS_VERDICT) {
      fail(`${vector.id}: WebAssembly ${report.verdict}, expected ${PASS_VERDICT}`);
    }
    return;
  }
  if (vector.input_kind === "absent" || vector.input_kind === "directory") {
    if (!report.verdict.startsWith(`${BLOCK_VERDICT_PREFIX}passport_unreadable`)) {
      fail(`${vector.id}: WebAssembly did not classify unreadable input`);
    }
    return;
  }
  const expected = `${BLOCK_VERDICT_PREFIX}${vector.expect_reason}`;
  if (report.verdict !== expected) {
    fail(`${vector.id}: WebAssembly ${report.verdict}, expected ${expected}`);
  }
}

async function loadWasmVerifier() {
  const require = createRequire(import.meta.url);
  require(resolve(wasmDirectory, "wasm_exec.js"));
  if (typeof globalThis.Go !== "function") {
    fail("the checked-in Go WebAssembly runtime did not define Go");
  }
  const go = new globalThis.Go();
  const { manifest, encoded } = await loadWasmTransport();
  const bytes = Buffer.from(encoded.trim(), "base64");
  if (bytes.length === 0 || bytes.length !== manifest.raw_bytes) {
    fail("the checked-in WebAssembly artifact has no decoded bytes");
  }
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(instance);
  const deadline = Date.now() + 5000;
  while (!globalThis.deedsealVerifierReady) {
    if (Date.now() >= deadline) {
      fail("the WebAssembly verifier did not become ready");
    }
    await new Promise((resolveReady) => setTimeout(resolveReady, 10));
  }
  return {
    verify: (input) => globalThis.deedsealVerifyPassport(input),
    unreadable: () => globalThis.deedsealVerifierUnreadable(),
  };
}

function validChunkName(value) {
  return typeof value === "string" && /^deedseal-verifier\.wasm\.base64\.\d{3}$/u.test(value);
}

async function loadWasmTransport() {
  const manifest = JSON.parse(await readFile(wasmManifestPath, "utf8"));
  if (
    !manifest ||
    manifest.schema_version !== "deedseal-wasm-bundle/1" ||
    !Number.isSafeInteger(manifest.raw_bytes) ||
    manifest.raw_bytes < 1 ||
    !Number.isSafeInteger(manifest.base64_bytes) ||
    manifest.base64_bytes < 1 ||
    !Array.isArray(manifest.chunks) ||
    manifest.chunks.length === 0 ||
    !manifest.chunks.every(validChunkName)
  ) {
    fail("the checked-in WebAssembly manifest is malformed");
  }
  const chunks = await Promise.all(
    manifest.chunks.map((name) => readFile(resolve(wasmDirectory, name), "utf8")),
  );
  const encoded = chunks.join("");
  if (encoded.length !== manifest.base64_bytes) {
    fail("the checked-in WebAssembly transport size does not match its manifest");
  }
  return { manifest, encoded };
}

async function assertStaticBundle() {
  for (const path of ["demo/index.html", "demo/app.js", "demo/proof.mjs", "wasm_exec.js", "deedseal-verifier.wasm.manifest.json"]) {
    const resolved = resolve(wasmDirectory, path);
    const details = await stat(resolved);
    if (!details.isFile() || details.size === 0) {
      fail(`browser bundle has no usable ${path}`);
    }
  }
  const page = await readFile(resolve(demoDirectory, "index.html"), "utf8");
  const app = await readFile(resolve(demoDirectory, "app.js"), "utf8");
  const proof = await readFile(resolve(demoDirectory, "proof.mjs"), "utf8");
  const runtime = await readFile(resolve(wasmDirectory, "wasm_exec.js"), "utf8");
  const { manifest, encoded } = await loadWasmTransport();
  if (!page.includes("../wasm_exec.js") || !page.includes("./app.js")) {
    fail("browser page does not load its local runtime and application");
  }
  if (!page.includes("hex-view") || !page.includes("restore") || !app.includes("flipByteAtOffset")) {
    fail("browser page does not expose a real byte-flip and restore control");
  }
  if (!app.includes("./proof.mjs") || /https?:\/\//u.test(`${page}\n${app}\n${proof}\n${runtime}`)) {
    fail("browser page is not a self-contained offline bundle");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}\n?$/u.test(encoded) || Buffer.from(encoded.trim(), "base64").length === 0) {
    fail("checked-in WebAssembly transport is not base64 text");
  }
  for (const name of manifest.chunks) {
    const details = await stat(resolve(wasmDirectory, name));
    if (!details.isFile() || details.size > 1048576) {
      fail(`WebAssembly transport chunk ${name} is not a public-text-safe size`);
    }
  }
}

async function main() {
  if (!nativeBinary) {
    fail("usage: check_wasm.mjs <native-verifier-path>");
  }
  await assertStaticBundle();
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const wasm = await loadWasmVerifier();
  let checked = 0;

  for (const vector of manifest.vectors) {
    const inputPath = resolve(dirname(manifestPath), vector.input);
    const native = nativeReport(inputPath);
    const report = vector.input_kind === "absent" || vector.input_kind === "directory"
      ? wasm.unreadable()
      : wasm.verify(new Uint8Array(await readFile(inputPath)));
    assertWasmReport(report, vector);

    const matchesNative = vector.input_kind === "absent" || vector.input_kind === "directory"
      ? native.exitCode === report.exit_code && native.verdict.startsWith(`${report.verdict} (`)
      : native.exitCode === report.exit_code && native.verdict === report.verdict;
    if (!matchesNative) {
      fail(`${vector.id}: native and WebAssembly verdicts differ`);
    }
    checked += 1;
  }

  const proof = await provePublishedRuns({
    readBytes: async (path) => new Uint8Array(await readFile(resolve(demoDirectory, path))),
    verify: wasm.verify,
  });
  if (proof.runs.some((run) => run.fixtureByteDifference !== 1)) {
    fail("a published tampered twin is not exactly one byte away from its passport");
  }
  if (proof.restoredReport.verdict !== PASS_VERDICT) {
    fail("restoring the published bytes did not return PASS");
  }

  console.log(`WASM_CONFORMANCE: PASS ${checked} vectors`);
  console.log(
    `WASM_BROWSER_PROOF: PASS ${proof.runs.length} runs; self-selected byte ${proof.selfSelectedFlip.offset}`,
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(`WASM_CHECK: FAIL ${error.message}`);
    process.exit(1);
  });
