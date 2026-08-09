// SPDX-License-Identifier: Apache-2.0
import { PUBLISHED_RUNS, flipByteAtOffset, provePublishedRuns } from "./proof.mjs";

const status = document.querySelector("#status");
const results = document.querySelector("#results");
const rerun = document.querySelector("#rerun");
const byteOffset = document.querySelector("#byte-offset");
const showByte = document.querySelector("#show-byte");
const restore = document.querySelector("#restore");
const hexRange = document.querySelector("#hex-range");
const hexView = document.querySelector("#hex-view");
const interactiveVerdict = document.querySelector("#interactive-verdict");

const HEX_WINDOW_BYTES = 256;
const interactive = { original: null, current: null, verify: null, viewStart: 0 };
let verifier;
let verifierLoading;

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function decodeBase64Wasm(source, expectedBytes) {
  const binary = window.atob(source.trim());
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  if (bytes.byteLength !== expectedBytes) {
    throw new Error("the local verifier byte size does not match its manifest");
  }
  return bytes.buffer;
}

function validChunkName(value) {
  return typeof value === "string" && /^deedseal-verifier\.wasm\.base64\.\d{3}$/u.test(value);
}

async function loadWasmTransport() {
  const manifestResponse = await fetch("../deedseal-verifier.wasm.manifest.json", { cache: "no-store" });
  if (!manifestResponse.ok) {
    throw new Error(`the local verifier manifest could not be read (${manifestResponse.status})`);
  }
  const manifest = await manifestResponse.json();
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
    throw new Error("the local verifier manifest is malformed");
  }
  const chunks = await Promise.all(manifest.chunks.map(async (name) => {
    const response = await fetch(`../${name}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`the local verifier transport could not be read (${response.status})`);
    }
    return response.text();
  }));
  const source = chunks.join("");
  if (source.length !== manifest.base64_bytes) {
    throw new Error("the local verifier transport size does not match its manifest");
  }
  return { manifest, source };
}

async function loadVerifier() {
  if (verifier) {
    return verifier;
  }
  if (verifierLoading) {
    return verifierLoading;
  }
  verifierLoading = (async () => {
    if (typeof globalThis.Go !== "function") {
      throw new Error("the local Go WebAssembly runtime did not load");
    }
    const go = new globalThis.Go();
    const { manifest, source: encoded } = await loadWasmTransport();
    const source = decodeBase64Wasm(encoded, manifest.raw_bytes);
    const { instance } = await WebAssembly.instantiate(source, go.importObject);
    void go.run(instance);

    const deadline = Date.now() + 5000;
    while (!globalThis.deedsealVerifierReady) {
      if (Date.now() >= deadline) {
        throw new Error("the local verifier did not become ready");
      }
      await wait(10);
    }
    verifier = (bytes) => globalThis.deedsealVerifyPassport(bytes);
    return verifier;
  })();
  return verifierLoading;
}

async function readBytes(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`the local fixture could not be read (${response.status})`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

function addResult(label, report) {
  const row = document.createElement("li");
  row.textContent = `${label}: ${report.verdict}`;
  results.append(row);
}

function renderProof(proof) {
  results.replaceChildren();
  for (const run of proof.runs) {
    addResult(`${run.id} published passport`, run.passReport);
    addResult(`${run.id} tampered twin`, run.blockReport);
  }
  const probe = document.createElement("li");
  probe.textContent = `Self-selected one-byte probe: offset ${proof.selfSelectedFlip.offset}, ${proof.selfSelectedFlip.report.verdict}`;
  results.append(probe);
  addResult("Restored published bytes", proof.restoredReport);
}

function hexadecimal(byte) {
  return byte.toString(16).padStart(2, "0");
}

function renderHexWindow() {
  if (!interactive.current) {
    return;
  }
  const maximumStart = Math.max(0, interactive.current.length - 1);
  interactive.viewStart = Math.min(interactive.viewStart, maximumStart);
  const end = Math.min(interactive.viewStart + HEX_WINDOW_BYTES, interactive.current.length);
  hexRange.textContent = `Showing bytes ${interactive.viewStart}–${end - 1} of ${interactive.current.length}. Select any byte to flip its low bit.`;
  hexView.replaceChildren();
  for (let offset = interactive.viewStart; offset < end; offset += 1) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "hex-byte";
    button.textContent = `${offset.toString().padStart(5, "0")}: ${hexadecimal(interactive.current[offset])}`;
    button.setAttribute("aria-label", `Flip byte ${offset}, hexadecimal ${hexadecimal(interactive.current[offset])}`);
    button.addEventListener("click", () => {
      void flipSelectedByte(offset);
    });
    hexView.append(button);
  }
}

function setInteractiveVerdict(label, report) {
  interactiveVerdict.textContent = `${label}: ${report.verdict}`;
}

function flipSelectedByte(offset) {
  interactive.current = flipByteAtOffset(interactive.current, offset);
  const report = interactive.verify(interactive.current);
  setInteractiveVerdict(`Flipped byte ${offset}`, report);
  renderHexWindow();
}

function restorePublishedBytes() {
  interactive.current = interactive.original.slice();
  const report = interactive.verify(interactive.current);
  setInteractiveVerdict("Restored published bytes", report);
  renderHexWindow();
}

async function prepareHexDemo(verify) {
  interactive.original = await readBytes(PUBLISHED_RUNS[0].passport);
  interactive.current = interactive.original.slice();
  interactive.verify = verify;
  interactive.viewStart = 0;
  byteOffset.min = "0";
  byteOffset.max = String(interactive.current.length - 1);
  byteOffset.value = "0";
  const report = verify(interactive.current);
  setInteractiveVerdict("Loaded published bytes", report);
  showByte.disabled = false;
  restore.disabled = false;
  renderHexWindow();
}

function showSelectedByte() {
  const offset = Number(byteOffset.value);
  if (!Number.isInteger(offset) || offset < 0 || offset >= interactive.current.length) {
    interactiveVerdict.textContent = "Choose a byte offset inside the published passport.";
    return;
  }
  interactive.viewStart = Math.floor(offset / HEX_WINDOW_BYTES) * HEX_WINDOW_BYTES;
  renderHexWindow();
}

async function run() {
  rerun.disabled = true;
  status.textContent = "Loading the local verifier and published fixtures…";
  results.replaceChildren();
  try {
    const verify = await loadVerifier();
    const proof = await provePublishedRuns({ readBytes, verify });
    renderProof(proof);
    await prepareHexDemo(verify);
    status.textContent = "Offline verification complete. No network service was used.";
  } catch (error) {
    status.textContent = `Offline verification failed: ${error.message}`;
  } finally {
    rerun.disabled = false;
  }
}

rerun.addEventListener("click", run);
showByte.addEventListener("click", showSelectedByte);
restore.addEventListener("click", () => {
  void restorePublishedBytes();
});
void run();
