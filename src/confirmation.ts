/**
 * Two-phase PoC confirmation gate (phase 1: PromoteFinding evidence bundle;
 * phase 2: main-agent ConfirmFinding commit).
 *
 * Extracted verbatim from ledger.ts so the trust-critical machinery lives in
 * one readable module. ledger.ts re-exports every public symbol here, so
 * callers and tests are unchanged.
 *
 * The gate's contract:
 * - Zero exit + complete output capture = run integrity, never proof.
 * - Evidence must be nonce-bound, schema-valid, carry a discriminating
 *   response-body predicate, and survive durable-hash re-verification.
 * - Target-dependence requires a machine differential: the attack request
 *   must satisfy the predicate while a legitimate same-host baseline request
 *   (declared in the evidence) must not.
 * - Only the main agent commits the phase-2 verdict; only the ledger can
 *   transition a case to confirmed.
 */

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, statSync } from "node:fs";

import { basename } from "node:path";

import {
  evidenceNonceMatches,
  type MainAgentVerdict,
  normalizeEvidence,
  parsePoCEvidence,
  scanArtifactForSecrets,
  validateMainAgentVerdict,
} from "./evidence.ts";
import { type HarnessVerifyResult, sameRequest, verifyUrlBindingError } from "./harness-verify.ts";
import type {
  CaseRecord,
  CaseUpdateResult,
  EvidenceItem,
  MainAgentVerdictRecord,
  NormalizedCaseInput,
  PendingConfirmation,
  PocEvidenceRun,
} from "./ledger.ts";
import { getCaseById, readWorkspaceArtifact } from "./ledger.ts";
import {
  appendCaseEvent,
  buildRecord,
  getDb,
  insertEvidenceItem,
  stableShortId,
  upsertCase,
  validateCase,
  withImmediateTransaction,
} from "./ledger-internal.ts";

/** PoC evidence has a tighter runner-side cap and must remain equally bounded on re-read. */
const POC_EVIDENCE_MAX_BYTES = 256 * 1024;

/** Immutable module-start role; child shells cannot upgrade this process by unsetting an env var. */
const PROCESS_STARTED_AS_SUBAGENT = process.env.PI_SUBAGENT_CHILD === "1";

/** Pending confirmation expires after 1h — re-run PromoteFinding for a fresh bundle. */
export const PENDING_CONFIRM_TTL_MS = 60 * 60 * 1000;

// ── Report contract gate (confirmed → reported) ──────────────────────

/** Typed, fail-closed error for an invalid report contract. */
export class ReportContractError extends Error {
  readonly code = "REPORT_CONTRACT_INVALID";
  readonly violations: string[];

  constructor(violations: string[]) {
    super(
      `report contract invalid (${violations.length} violation(s)):\n- ${violations.join("\n- ")}`,
    );
    this.name = "ReportContractError";
    this.violations = violations;
  }
}

/** The closed-schema contract companion path for a report markdown path. */
export function reportContractPathFor(reportPath: string): string {
  return reportPath.replace(/\.md$/i, ".contract.json");
}

/** Hard cap on the contract document — it is metadata, not a report carrier. */
const REPORT_CONTRACT_MAX_BYTES = 64 * 1024;

/** Keys the closed schema accepts; anything else is a violation. */
const REPORT_CONTRACT_KEYS = new Set([
  "case_id",
  "title",
  "severity",
  "summary",
  "impact",
  "remediation",
  "steps",
  "evidence_ids",
  "coverage_refs",
]);

/**
 * Validate the closed-schema report contract for a confirmed case:
 * - a regular, non-symlink JSON file of bounded size exists at contractPath;
 * - only schema keys are present, and the required text fields are non-empty;
 * - evidence_ids reference ONLY evidence items that exist on this case, and
 *   include at least one observation and one reproduction item;
 * - coverage_refs reference ONLY (asset, class) cells recorded on this case.
 *
 * Throws ReportContractError (fail closed) on any violation.
 */
export function validateReportContract(record: CaseRecord, contractPath: string): void {
  const violations: string[] = [];
  let stat: ReturnType<typeof statSync>;
  try {
    stat = statSync(contractPath);
  } catch {
    throw new ReportContractError([
      `report contract not found: ${basename(contractPath)} (write the closed-schema JSON contract next to the report, then retry status='reported')`,
    ]);
  }
  if (!stat.isFile()) violations.push("report contract path is not a regular file");
  if (lstatSync(contractPath).isSymbolicLink()) {
    violations.push("report contract must not be a symbolic link");
  }
  if (stat.size > REPORT_CONTRACT_MAX_BYTES) {
    violations.push(
      `report contract too large (${stat.size} bytes; max ${REPORT_CONTRACT_MAX_BYTES})`,
    );
  }
  if (violations.length > 0) throw new ReportContractError(violations);

  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(contractPath, "utf8"));
  } catch (e) {
    throw new ReportContractError([`report contract is not valid JSON: ${(e as Error).message}`]);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new ReportContractError(["report contract must be a JSON object"]);
  }
  const contract = doc as Record<string, unknown>;
  for (const key of Object.keys(contract)) {
    if (!REPORT_CONTRACT_KEYS.has(key)) {
      violations.push(`unknown key "${key}" — the report contract schema is closed`);
    }
  }
  for (const required of ["case_id", "title", "severity", "summary", "impact", "remediation"]) {
    const v = contract[required];
    if (typeof v !== "string" || v.trim().length === 0) {
      violations.push(`"${required}" must be a non-empty string`);
    }
  }
  if (contract.case_id !== record.id) {
    violations.push(`"case_id" must be ${record.id} (got ${String(contract.case_id)})`);
  }
  const SEVERITIES = ["info", "low", "medium", "high", "critical"];
  if (
    typeof contract.severity === "string" &&
    !(record.severity
      ? contract.severity === record.severity
      : SEVERITIES.includes(contract.severity))
  ) {
    violations.push(
      `"severity" must match the case severity (${record.severity ?? "unset"}) or be a valid severity`,
    );
  }
  if (!Array.isArray(contract.steps) || contract.steps.length === 0) {
    violations.push('"steps" must be a non-empty array of reproduction steps');
  } else if (!contract.steps.every((s: unknown) => typeof s === "string" && s.trim().length > 0)) {
    violations.push('"steps" entries must be non-empty strings');
  }

  const items = record.evidenceItems ?? [];
  const knownIds = new Set(items.map((i) => i.id));
  const evidenceIds = contract.evidence_ids;
  if (!Array.isArray(evidenceIds) || evidenceIds.length === 0) {
    violations.push('"evidence_ids" must be a non-empty array of evidence item ids');
  } else {
    if (!evidenceIds.every((id: unknown) => typeof id === "string" && knownIds.has(id))) {
      violations.push('"evidence_ids" references evidence items that do not exist on this case');
    }
    const referenced = items.filter((i) => evidenceIds.includes(i.id));
    if (!referenced.some((i) => i.role === "observation")) {
      violations.push('"evidence_ids" must include at least one observation item');
    }
    if (!referenced.some((i) => i.role === "reproduction")) {
      violations.push('"evidence_ids" must include at least one reproduction item');
    }
  }

  const coverageRefs = contract.coverage_refs;
  if (coverageRefs !== undefined && !Array.isArray(coverageRefs)) {
    violations.push('"coverage_refs" must be an array of { asset, class } objects');
  } else if (Array.isArray(coverageRefs)) {
    const cells = new Set((record.coverageItems ?? []).map((c) => `${c.asset}\n${c.class}`));
    for (const [index, ref] of coverageRefs.entries()) {
      if (
        typeof ref !== "object" ||
        ref === null ||
        typeof (ref as Record<string, unknown>).asset !== "string" ||
        typeof (ref as Record<string, unknown>).class !== "string"
      ) {
        violations.push(`"coverage_refs[${index}]" must be an { asset, class } object`);
      } else if (
        !cells.has(`${(ref as { asset: string }).asset}\n${(ref as { class: string }).class}`)
      ) {
        violations.push(
          `"coverage_refs[${index}]" references a coverage cell not recorded on this case`,
        );
      }
    }
  }

  if (violations.length > 0) throw new ReportContractError(violations);
}

function validateRunEvidence(run: PocEvidenceRun, label: string): void {
  if (!run.completed) {
    throw new Error(`${label} did not complete; a crash is not evidence`);
  }
  if (!run.outputComplete) {
    throw new Error(`${label} output capture was incomplete; evidence checks are unsafe`);
  }
  if (run.exitCode !== 0) {
    throw new Error(
      `${label} exited with ${run.exitCode}; exit 0 is required for a complete run but is never sufficient proof`,
    );
  }
  if (!run.evidence || !run.evidenceSha256) {
    throw new Error(
      `${label} has no evidence.json — the PoC must write evidence to $PI_POC_EVIDENCE_DIR`,
    );
  }
  if (!evidenceNonceMatches(run.evidence, run.nonce)) {
    throw new Error(`${label} evidence nonce mismatch — evidence not bound to this run`);
  }
  const parsed = parsePoCEvidence(run.evidence);
  if (!parsed.ok) {
    throw new Error(`${label} evidence contract invalid: ${parsed.error}`);
  }
  if (!run.evidencePath) {
    throw new Error(`${label} has no durable evidencePath; ephemeral evidence cannot confirm`);
  }
  const artifact = readWorkspaceArtifact(run.evidencePath);
  if (artifact.bytes.byteLength > POC_EVIDENCE_MAX_BYTES) {
    throw new Error(
      `${label} durable evidence exceeds ${POC_EVIDENCE_MAX_BYTES} bytes; evidence cannot be revalidated safely`,
    );
  }
  const durableHash = createHash("sha256").update(artifact.bytes).digest("hex");
  if (durableHash !== run.evidenceSha256) {
    throw new Error(`${label} durable evidence hash does not match evidenceSha256`);
  }
  let durableRaw: unknown;
  try {
    durableRaw = JSON.parse(artifact.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} durable evidence is not valid JSON: ${(error as Error).message}`);
  }
  const durable = parsePoCEvidence(durableRaw);
  if (!durable.ok) {
    throw new Error(`${label} durable evidence contract invalid: ${durable.error}`);
  }
  if (
    normalizeEvidence(durable.evidence) !== normalizeEvidence(run.evidence) ||
    JSON.stringify(durable.evidence.observations) !== JSON.stringify(run.evidence.observations)
  ) {
    throw new Error(`${label} durable evidence bytes do not match the stored evidence object`);
  }
}

/** Determinism on normalized evidence (nonce/observations stripped). */
function assertEvidenceDifferential(bundle: PendingConfirmation): void {
  const [r1, r2] = bundle.targetRuns;
  if (normalizeEvidence(r1.evidence) !== normalizeEvidence(r2.evidence)) {
    throw new Error(
      "Target runs produced inconsistent evidence — the exploit did not reproduce deterministically",
    );
  }
}

function assertMachineConfirmation(bundle: PendingConfirmation): void {
  assertHarnessTargetOnly(
    bundle.harnessVerified,
    "HARNESS DIFFERENTIAL FAILED",
    "no machine-owned attack/baseline replay was recorded",
  );
}

function assertHarnessTargetOnly(
  harness: HarnessVerifyResult | undefined,
  label: string,
  missingNote: string,
): asserts harness is HarnessVerifyResult {
  if (
    !harness?.attempted ||
    harness.pass !== true ||
    harness.differential !== "target_only" ||
    harness.target?.matched !== true ||
    harness.control?.matched !== false
  ) {
    throw new Error(`${label}: ${harness?.note ?? missingNote}`);
  }
}

/**
 * Gate for phase 1 of promotion: case must exist, be investigating, and have
 * poc/evidence/impact/severity/target. The disconfirmation is provided by the
 * main agent at confirm time, so it is NOT a precondition here. Returns the
 * record when promotable, throws otherwise. Exported so PromoteFinding can
 * validate BEFORE paying for (potentially slow) sandboxed PoC runs.
 */
export function assertPromotable(id: string): CaseRecord {
  const current = getCaseById(id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
  }
  if (current.status !== "investigating") {
    throw new Error(`PromoteFinding requires an investigating case (current: ${current.status})`);
  }
  if (!current.poc) {
    throw new Error("CONFIRMED requires poc; set poc on the case first");
  }
  if (!current.evidence) {
    throw new Error("CONFIRMED requires evidence; set evidence on the case first");
  }
  if (!current.impact) {
    throw new Error("CONFIRMED requires impact; set impact on the case first");
  }
  if (!current.severity) {
    throw new Error("CONFIRMED requires severity; set severity on the case first");
  }
  if (!current.target) {
    throw new Error(
      "CONFIRMED requires target (what host/repo/scope this affects); set target on the case first",
    );
  }
  // Evidence-chain closure: the observation item must be ARTIFACT-BACKED. A
  // summary-only observation is agent prose about itself — promotion requires
  // a real file with its SHA-256 as the initial signal. (The reproduction item
  // is always artifact-backed: the gate writes it from the evidence hash.)
  if (!current.evidenceItems?.some((e: EvidenceItem) => e.role === "observation" && e.sha256)) {
    throw new Error(
      "Evidence chain incomplete: CONFIRMED requires an artifact-backed observation evidence item " +
        "(EvidenceAdd role=observation with artifact_path — the initial signal, stored as basename + SHA-256) " +
        "in addition to the auto-recorded reproduction item. Add the artifact-backed observation item and retry promotion.",
    );
  }
  return current;
}

/**
 * Phase 1: validate a same-host attack-vs-baseline bundle. The differential is
 * proven by the harness replay (attack matched, baseline did not, both against
 * the case target) — the discriminating variable is the request's identity or
 * a parameter, not the host.
 */
function validateBundle(current: CaseRecord, id: string, bundle: PendingConfirmation): CaseRecord {
  if (bundle.targetRuns.length !== 2) throw new Error("Confirmation requires two target runs");
  const targetRunTarget = bundle.targetRuns[0]?.target;
  if (!targetRunTarget || bundle.targetRuns.some((r) => r.target !== targetRunTarget)) {
    throw new Error("Confirmation requires both runs against the same case target");
  }
  let pocHash: string | undefined;
  try {
    pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
  } catch {
    pocHash = undefined;
  }
  if (!pocHash || (bundle.pocSha256 && bundle.pocSha256 !== pocHash)) {
    throw new Error("pocSha256 does not match the PoC file on disk");
  }
  for (const run of bundle.targetRuns) {
    validateRunEvidence(run, `${run.mode} run`);
    const ev = run.evidence;
    const attackBinding = verifyUrlBindingError(ev.verify.url, targetRunTarget);
    if (attackBinding) throw new Error(`ATTACK BINDING FAILED: ${attackBinding}`);
    const baselineBinding = verifyUrlBindingError(ev.baseline.url, targetRunTarget);
    if (baselineBinding) throw new Error(`BASELINE BINDING FAILED: ${baselineBinding}`);
    if (ev.baseline && sameRequest(ev.verify, ev.baseline)) {
      throw new Error(
        "BASELINE CHECK FAILED: attack and baseline requests are identical — vary identity or a parameter",
      );
    }
  }
  if (bundle.caseId !== id) throw new Error("Pending confirmation caseId mismatch");
  assertEvidenceDifferential(bundle);
  // Machine floor: attack matched, baseline did not, both against the case target.
  assertMachineConfirmation(bundle);
  const next = buildRecord({ pendingConfirmation: bundle }, current);
  validateCase(next);
  return next;
}

/**
 * Phase 1: record the harness-observed evidence bundle on the case. The whole
 * contract is validated here — nonce binding, run completion, determinism
 * across the two target runs, and the attack/baseline differential — so a
 * bundle that cannot promote is rejected before the
 * main agent performs phase-2 review.
 */
export function storePendingConfirmation(id: string, bundle: PendingConfirmation): CaseRecord {
  const db = getDb();
  return withImmediateTransaction(db, () => {
    const current = getCaseById(id);
    if (!current) throw new Error(`Case not found: ${id}`);
    if (current.status !== "investigating") {
      throw new Error(
        `Pending confirmation requires an investigating case (current: ${current.status})`,
      );
    }
    if (bundle.caseId !== id) throw new Error("Pending confirmation caseId mismatch");
    let pocHash: string | undefined;
    try {
      pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
    } catch {
      pocHash = undefined;
    }
    if (!pocHash || (bundle.pocSha256 && bundle.pocSha256 !== pocHash)) {
      throw new Error("pocSha256 does not match the PoC file on disk");
    }
    const next = validateBundle(current, id, bundle);
    upsertCase(db, next);
    appendCaseEvent(db, {
      actor: "harness",
      caseId: id,
      eventType: "promotion_pending",
      payload: { mode: "intra_target", evidence_sha256: bundle.targetRuns[0].evidenceSha256 },
    });
    return next;
  });
}

/**
 * Phase 2: commit (or refuse) the promotion on the main agent's verdict.
 *
 * CONFIRMED requires the full bundle to still hold (completion, nonce,
 * determinism, differential), the PoC script to be unchanged since the runs
 * (pocSha256 — otherwise the main agent reviewed different bytes), and a
 * verdict accompanied by a concrete review note and a disconfirmation attempt.
 * NOT_CONFIRMED (positively disproved) and INCONCLUSIVE (neither reproduced
 * nor disproved) both record the verdict and keep the case investigating —
 * INCONCLUSIVE preserves it for manual review rather than dropping it.
 */
export function applyConfirmationResult(
  id: string,
  verdictInput: MainAgentVerdict,
  authority: { startedAsSubagent: boolean } = {
    startedAsSubagent: PROCESS_STARTED_AS_SUBAGENT || process.env.PI_SUBAGENT_CHILD === "1",
  },
): CaseUpdateResult {
  if (authority.startedAsSubagent) {
    throw new Error(
      "ConfirmFinding is reserved for the main/coordinator agent; worker processes cannot commit confirmation",
    );
  }
  const db = getDb();
  return withImmediateTransaction(db, () => {
    const current = getCaseById(id);
    if (!current) throw new Error(`Case not found: ${id}`);
    if (current.status !== "investigating") {
      throw new Error(`ConfirmFinding requires an investigating case (current: ${current.status})`);
    }
    const bundle = current.pendingConfirmation;
    if (!bundle) {
      throw new Error("No pending confirmation on this case — run PromoteFinding first");
    }
    // Fail closed on an unparseable ranAt: Date.parse(garbage) is NaN, and
    // NaN > TTL is false — a malformed timestamp must NOT make the bundle
    // immortal. Treat it as expired (re-run PromoteFinding for a fresh one).
    const ranAtMs = Date.parse(bundle.ranAt);
    if (!Number.isFinite(ranAtMs) || Date.now() - ranAtMs > PENDING_CONFIRM_TTL_MS) {
      throw new Error(
        "Pending confirmation expired or has an invalid timestamp (1h TTL) — re-run PromoteFinding for a fresh bundle",
      );
    }
    const parsed = validateMainAgentVerdict(verdictInput);
    if (!parsed.ok) throw new Error(`Invalid main-agent confirmation verdict: ${parsed.error}`);
    const verdict = parsed.verdict;
    const recorded: MainAgentVerdictRecord = {
      ...verdict,
      at: new Date().toISOString(),
      reviewer: "main_agent",
      proofStrength: verdict.verdict === "CONFIRMED" ? "predicate_differential" : undefined,
    };

    if (verdict.verdict !== "CONFIRMED") {
      // NOT_CONFIRMED (positively disproved) and INCONCLUSIVE (neither reproduced
      // nor disproved) both record the verdict, consume the attempt, and keep the
      // case investigating — neither auto-kills. INCONCLUSIVE is the fail-safe:
      // the finding is preserved for manual review, not dropped.
      const model = verdict.model ? ` (${verdict.model})` : "";
      const note =
        verdict.verdict === "INCONCLUSIVE"
          ? `main agent INCONCLUSIVE${model}: ${verdict.reasoning} — preserved for manual review, not disproved`
          : `main agent NOT_CONFIRMED${model}: ${verdict.reasoning}`;
      const next = buildRecord(
        {
          confirmerVerdict: recorded,
          pendingConfirmation: undefined,
          assumptions: [...(current.assumptions ?? []), note],
        },
        current,
      );
      // buildRecord's nullish fallback preserves the old value; consume the
      // rejected attempt explicitly so a retry must produce fresh evidence.
      next.pendingConfirmation = undefined;
      validateCase(next);
      upsertCase(db, next);
      appendCaseEvent(db, {
        caseId: id,
        actor: "main_agent",
        eventType: "confirmation_verdict",
        payload: { verdict: verdict.verdict, model: verdict.model ?? null },
      });
      return { record: next, changed: true };
    }

    // CONFIRMED — re-validate the whole bundle (defense in depth; the case may
    // have been touched between phase 1 and the verdict).
    for (const run of bundle.targetRuns) {
      validateRunEvidence(run, `${run.mode} run`);
    }
    assertEvidenceDifferential(bundle);
    assertMachineConfirmation(bundle);
    let pocHash: string | undefined;
    try {
      pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
    } catch {
      pocHash = undefined;
    }
    if (!pocHash || pocHash !== bundle.pocSha256) {
      throw new Error(
        "PoC script changed since the runs — re-run PromoteFinding (the main agent must review the exact bytes that ran)",
      );
    }
    // The case target must still be the host the PoC ran against. The
    // evidence proves nothing about a target the case adopted after the runs.
    const targetRun = bundle.targetRuns[0];
    if (!current.target || current.target !== targetRun.target) {
      throw new Error(
        "Case target changed since the PoC runs — re-run PromoteFinding against the current target " +
          `(bundle target: ${targetRun.target}, case target: ${current.target ?? "(none)"}).`,
      );
    }

    // The observation must predate the repro (provenance guard).
    const observation = current.evidenceItems?.find(
      (e: EvidenceItem) => e.role === "observation" && e.sha256,
    );
    if (observation && observation.createdAt > bundle.targetRuns[0].ranAt) {
      throw new Error(
        "Evidence chain invalid: the observation item was recorded after the PoC ran " +
          `(${observation.createdAt} > ${bundle.targetRuns[0].ranAt}). The observation must predate the repro.`,
      );
    }

    const reproductionItem: EvidenceItem = {
      id: `ev_${stableShortId(`${id}\nreproduction\n${targetRun.ranAt}`)}`,
      caseId: id,
      role: "reproduction",
      // The runner preserves each run's evidence.json in a durable dir
      // (.pi/poc-evidence/) — the artifact the hash was computed over still
      // exists, so the item stays artifact-backed and re-verifiable.
      artifactPath: targetRun.evidencePath ? basename(targetRun.evidencePath) : "evidence.json",
      sha256: targetRun.evidenceSha256,
      summary: `PoC evidence accepted (2 target runs + same-host baseline; ${recorded.proofStrength}) — main agent semantic confirmation${verdict.model ? ` (${verdict.model})` : ""}`,
      createdAt: targetRun.ranAt,
    };
    // Defense in depth: the run's evidence.json may embed secrets in
    // observations/claim text — flag it like any other artifact.
    if (targetRun.evidencePath) {
      try {
        const secretFindings = scanArtifactForSecrets(
          readWorkspaceArtifact(targetRun.evidencePath).bytes,
        );
        if (secretFindings.length > 0) {
          reproductionItem.containsSecret = true;
          reproductionItem.secretFindings = secretFindings;
        }
      } catch {
        // validateRunEvidence already proved the artifact readable; a scan
        // failure never blocks the confirmation itself.
      }
    }

    const newEvidence =
      (current.evidence ? `${current.evidence}\n\n` : "") +
      `### PoC Execution Capture (${targetRun.ranAt})\n` +
      `- **Evidence sha256:** ${targetRun.evidenceSha256}\n` +
      `- **Target:** ${targetRun.target}\n` +
      `- **Machine evidence:** ${recorded.proofStrength} (a differential is not by itself proof of exploitation)\n` +
      `- **Main-agent reviewer:** ${verdict.model ?? "unknown model"} — semantic confirmation\n` +
      `#### Target Run Output\n\`\`\`\n${targetRun.output ?? ""}\n\`\`\``;

    const update: NormalizedCaseInput = {
      status: "confirmed",
      pocVerified: {
        path: bundle.pocPath,
        exitCode: targetRun.exitCode,
        ranAt: targetRun.ranAt,
        output: targetRun.output,
        sandbox: targetRun.sandbox,
        completed: true,
        outputComplete: true,
        mode: "poc",
        target: targetRun.target,
      },
      controlVerified: {
        path: bundle.pocPath,
        exitCode: targetRun.exitCode,
        ranAt: targetRun.ranAt,
        output: `same-host baseline: ${bundle.harnessVerified?.control?.note ?? "baseline did not satisfy the attack predicate"}`,
        sandbox: targetRun.sandbox,
        completed: true,
        outputComplete: true,
        mode: "baseline",
        target: targetRun.target,
      },
      disconfirmation: verdict.disconfirmation_attempt,
      confirmerVerdict: recorded,
      pendingConfirmation: undefined,
      evidence: newEvidence,
    };

    const next = buildRecord(update, current);
    next.pendingConfirmation = undefined; // buildRecord's ?? existing keeps it; clear explicitly
    validateCase(next);
    insertEvidenceItem(db, reproductionItem);
    upsertCase(db, next);
    appendCaseEvent(db, {
      caseId: id,
      actor: "main_agent",
      eventType: "case_confirmed",
      payload: {
        verdict: "CONFIRMED",
        proof_strength: recorded.proofStrength ?? null,
        model: verdict.model ?? null,
        reproduction_evidence_id: reproductionItem.id,
      },
    });
    next.evidenceItems = [...(next.evidenceItems ?? []), reproductionItem];
    return { record: next, changed: true };
  });
}
