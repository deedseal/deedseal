// SPDX-License-Identifier: Apache-2.0

export const PASS_VERDICT = "RUN_PASSPORT_VERDICT: PASS";
export const BLOCK_VERDICT_PREFIX = "RUN_PASSPORT_VERDICT: BLOCK ";

export const PUBLISHED_RUNS = Object.freeze([
  Object.freeze({
    id: "deedseal-bounded-run-001",
    passport: "../../../examples/verified/run-passport.json",
    tampered: "../../../examples/verified/run-passport.tampered.json",
  }),
  Object.freeze({
    id: "deedseal-bounded-run-002",
    passport: "../../../examples/verified/run-002/run-passport.json",
    tampered: "../../../examples/verified/run-002/run-passport.tampered.json",
  }),
]);

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} did not produce bytes`);
  }
  return value;
}

function assertReport(report, expected, label) {
  if (!report || typeof report !== "object" || typeof report.verdict !== "string") {
    throw new Error(`${label} did not produce a verifier report`);
  }
  if (expected === "PASS") {
    if (report.exit_code !== 0 || report.verdict !== PASS_VERDICT) {
      throw new Error(`${label} did not verify PASS`);
    }
    return report;
  }
  if (report.exit_code !== 1 || !report.verdict.startsWith(BLOCK_VERDICT_PREFIX)) {
    throw new Error(`${label} did not verify BLOCK`);
  }
  return report;
}

export function countDifferentBytes(left, right) {
  if (left.length !== right.length) {
    return Number.POSITIVE_INFINITY;
  }
  let count = 0;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      count += 1;
    }
  }
  return count;
}

export function flipByteAtOffset(original, offset) {
  assertBytes(original, "published passport");
  if (!Number.isInteger(offset) || offset < 0 || offset >= original.length) {
    throw new Error("the selected byte offset is outside the passport");
  }
  const mutated = original.slice();
  mutated[offset] ^= 1;
  return mutated;
}

// The selected offset is not a fixture constant. The probe tries a distinct
// one-byte mutation at each position and returns only the first mutation the
// WebAssembly verifier itself refuses.
export function findBlockingOneByteFlip(verify, original) {
  assertBytes(original, "published passport");
  for (let offset = 0; offset < original.length; offset += 1) {
    const mutated = flipByteAtOffset(original, offset);
    const report = verify(mutated);
    if (
      report &&
      report.exit_code === 1 &&
      typeof report.verdict === "string" &&
      report.verdict.startsWith(BLOCK_VERDICT_PREFIX)
    ) {
      return { offset, original: original[offset], mutated: mutated[offset], bytes: mutated, report };
    }
  }
  throw new Error("the verifier did not refuse any one-byte mutation");
}

export async function provePublishedRuns({ readBytes, verify }) {
  if (typeof readBytes !== "function" || typeof verify !== "function") {
    throw new Error("the proof needs byte loading and a verifier");
  }

  const runs = [];
  let firstOriginal;
  for (const run of PUBLISHED_RUNS) {
    const original = assertBytes(await readBytes(run.passport), `${run.id} passport`);
    const tampered = assertBytes(await readBytes(run.tampered), `${run.id} tampered passport`);
    const passReport = assertReport(verify(original), "PASS", `${run.id} passport`);
    const blockReport = assertReport(verify(tampered), "BLOCK", `${run.id} tampered passport`);
    runs.push({ id: run.id, passReport, blockReport, fixtureByteDifference: countDifferentBytes(original, tampered) });
    firstOriginal ??= original;
  }

  const selfSelectedFlip = findBlockingOneByteFlip(verify, firstOriginal);
  if (countDifferentBytes(firstOriginal, selfSelectedFlip.bytes) !== 1) {
    throw new Error("the selected mutation was not exactly one byte");
  }
  const restoredReport = assertReport(verify(firstOriginal.slice()), "PASS", "restored published passport");

  return { runs, selfSelectedFlip, restoredReport };
}
