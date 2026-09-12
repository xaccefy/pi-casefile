/**
 * Internal shared plumbing for the casefile ledger modules.
 *
 * The single home for the DB handle, record builder, validation, transaction
 * wrapper, and text helpers. Both ledger.ts and its sibling modules
 * (confirmation.ts) import these from here — one copy, no drift. NOT a public
 * API — external callers import from ledger.ts, which re-exports what they need.
 *
 * Circular-import note: this module must stay leaf-like. It may import types
 * from ledger.ts but no runtime values, or the ledger ⇄ sibling cycle gains
 * an edge.
 */

import { createHash, randomUUID } from "node:crypto";
import type { CaseRecord, EvidenceItem, NormalizedCaseInput } from "./ledger.ts";
import type { DatabaseSync } from "./sqlite-compat/index.ts";

// ── Text helpers ─────────────────────────────────────────────────────

export function normalizeList(values: string[] | undefined): string[] {
  return Array.from(new Set((values ?? []).map((v) => v.trim()).filter(Boolean)));
}

export function normalizeText(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

export function stableShortId(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 10);
}

export { normalizeMatchText };

function normalizeMatchText(value: string | undefined): string {
  return normalizeText(value)?.toLowerCase().replace(/\s+/g, " ") ?? "";
}

// ── DB handle (module-global; ledger.ts owns lifecycle) ─────────────

let dbInstance: DatabaseSync | undefined;
let opener: (() => DatabaseSync) | undefined;

/** ledger.ts registers its schema-init opener here at module load. */
export function setDbOpener(impl: () => DatabaseSync): void {
  opener = impl;
}

export function getDb(): DatabaseSync {
  if (!dbInstance && opener) {
    // Lazy open through the owner (schema init + safe-state checks) so any
    // sibling module can start the ledger, not just ledger.ts call sites.
    dbInstance = opener();
  }
  if (!dbInstance) {
    throw new Error("Ledger database not initialized — open it via ledger.ts first");
  }
  return dbInstance;
}

/** Called by ledger.ts's getDb() after opening (or reopening) the database. */
export function setDbInstance(db: DatabaseSync): void {
  dbInstance = db;
}

export function hasDbInstance(): boolean {
  return dbInstance !== undefined;
}

export function closeDb(): void {
  if (!dbInstance) return;
  try {
    dbInstance.close();
  } catch {
    // Best-effort close.
  }
  dbInstance = undefined;
}

// ── Record building & persistence primitives ────────────────────────

export function buildRecord(input: NormalizedCaseInput, existing?: CaseRecord): CaseRecord {
  const timestamp = new Date().toISOString();
  const title = ("title" in input ? input.title : existing?.title)?.trim() ?? "";
  const id = existing?.id ?? `case_${stableShortId(`${title}\n${timestamp}\n${randomUUID()}`)}`;

  return {
    id,
    title,
    status: input.status ?? existing?.status ?? "hypothesis",
    // Once a case has been investigating/confirmed it never forgets — the kill
    // gate must not be defeatable by demoting first.
    everAdvanced:
      existing?.everAdvanced === true ||
      input.status === "investigating" ||
      input.status === "confirmed",
    confidence: input.confidence ?? existing?.confidence ?? "low",
    severity: input.severity ?? existing?.severity,
    priority: input.priority ?? existing?.priority,
    target: input.target !== undefined ? normalizeText(input.target) : existing?.target,
    endpoint: input.endpoint !== undefined ? normalizeText(input.endpoint) : existing?.endpoint,
    bugClass: input.bugClass !== undefined ? normalizeText(input.bugClass) : existing?.bugClass,
    summary: input.summary !== undefined ? normalizeText(input.summary) : existing?.summary,
    evidence: input.evidence !== undefined ? normalizeText(input.evidence) : existing?.evidence,
    impact: input.impact !== undefined ? normalizeText(input.impact) : existing?.impact,
    nextStep: input.nextStep !== undefined ? normalizeText(input.nextStep) : existing?.nextStep,
    poc: input.poc !== undefined ? normalizeText(input.poc) : existing?.poc,
    remediation:
      input.remediation !== undefined ? normalizeText(input.remediation) : existing?.remediation,
    references: normalizeList(input.references ?? existing?.references),
    blockers: normalizeList(input.blockers ?? existing?.blockers),
    tags: normalizeList(input.tags ?? existing?.tags),
    assumptions: normalizeList(input.assumptions ?? existing?.assumptions),
    disproveIf: normalizeList(input.disproveIf ?? existing?.disproveIf),
    pocVerified: input.pocVerified ?? existing?.pocVerified,
    disconfirmation:
      input.disconfirmation !== undefined
        ? normalizeText(input.disconfirmation)
        : existing?.disconfirmation,
    invariant: input.invariant !== undefined ? normalizeText(input.invariant) : existing?.invariant,
    disconfirmationVerified: input.disconfirmationVerified ?? existing?.disconfirmationVerified,
    controlVerified: input.controlVerified ?? existing?.controlVerified,
    pendingConfirmation: input.pendingConfirmation ?? existing?.pendingConfirmation,
    confirmerVerdict: input.confirmerVerdict ?? existing?.confirmerVerdict,
    reportedAt: input.reportedAt ?? existing?.reportedAt,
    reportPath: input.reportPath ?? existing?.reportPath,
    retryPolicy:
      input.retryPolicy !== undefined
        ? normalizeRetryPolicy(input.retryPolicy)
        : existing?.retryPolicy,
    evidenceItems: existing?.evidenceItems ?? [],
    coverageItems: existing?.coverageItems ?? [],
    linkedCases: existing?.linkedCases ?? [],
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
  };
}

/** Normalize a retry policy: attempts 1–10, at most 8 distinct fallback models. */
export function normalizeRetryPolicy(policy: unknown): CaseRecord["retryPolicy"] {
  if (policy === null || policy === undefined) return undefined;
  if (typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("retry_policy must be an object: { max_attempts, fallback_models? }");
  }
  const p = policy as { max_attempts?: unknown; fallback_models?: unknown };
  if (
    typeof p.max_attempts !== "number" ||
    !Number.isInteger(p.max_attempts) ||
    p.max_attempts < 1 ||
    p.max_attempts > 10
  ) {
    throw new Error("retry_policy.max_attempts must be an integer between 1 and 10");
  }
  if (p.fallback_models !== undefined && p.fallback_models !== null) {
    if (!Array.isArray(p.fallback_models) || p.fallback_models.length > 8) {
      throw new Error("retry_policy.fallback_models must be an array of at most 8 model names");
    }
    if (
      !p.fallback_models.every(
        (m) => typeof m === "string" && m.trim().length > 0 && m.trim() === m,
      )
    ) {
      throw new Error("retry_policy.fallback_models entries must be non-empty trimmed strings");
    }
  }
  const fallbackModels = Array.isArray(p.fallback_models)
    ? Array.from(new Set(p.fallback_models.map((m) => m as string)))
    : undefined;
  return fallbackModels?.length
    ? { max_attempts: p.max_attempts, fallback_models: fallbackModels }
    : { max_attempts: p.max_attempts };
}

export function validateCase(record: CaseRecord): void {
  if (!record.title.trim()) throw new Error("Case title cannot be empty");
  // Enum membership on the public API path: the tool layer schema-gates these,
  // but direct callers (tests, other integrations) must not be able to persist
  // "bogus" statuses that every later gate and reader would mis-handle.
  const STATUS = [
    "hypothesis",
    "investigating",
    "confirmed",
    "blocked",
    "killed",
    "reported",
  ] as const;
  const CONFIDENCE = ["low", "medium", "high"] as const;
  const SEVERITY = ["info", "low", "medium", "high", "critical"] as const;
  const PRIORITY = ["P0", "P1", "P2", "P3", "P4"] as const;
  if (!(STATUS as readonly string[]).includes(record.status)) {
    throw new Error(`Invalid case status: ${record.status}. Statuses: ${STATUS.join(", ")}`);
  }
  if (!(CONFIDENCE as readonly string[]).includes(record.confidence)) {
    throw new Error(
      `Invalid case confidence: ${record.confidence}. Confidence levels: ${CONFIDENCE.join(", ")}`,
    );
  }
  // Null check (not just undefined): DB reads surface absent columns as null.
  if (record.severity != null && !(SEVERITY as readonly string[]).includes(record.severity)) {
    throw new Error(
      `Invalid case severity: ${record.severity}. Severities: ${SEVERITY.join(", ")}`,
    );
  }
  if (record.priority != null && !(PRIORITY as readonly string[]).includes(record.priority)) {
    throw new Error(
      `Invalid case priority: ${record.priority}. Priorities: ${PRIORITY.join(", ")}`,
    );
  }
  // Retry policy shape is machine-read by retry tooling — re-check on write.
  if (record.retryPolicy !== undefined) normalizeRetryPolicy(record.retryPolicy);
  // Falsification conditions are load-bearing: they are required at creation
  // and must not be erasable later (CaseUpdate({ disproveIf: [] }) would wipe
  // the hypothesis's falsifiability). Re-check on every write.
  if (record.status !== "reported" && !(record.disproveIf ?? []).some((d) => d.trim())) {
    throw new Error(
      "Cases require disproveIf — falsification conditions (what would disprove this hypothesis). " +
        "They cannot be cleared once set.",
    );
  }
  // Keep this gate in lockstep with the confirmation module: a case may only
  // be CONFIRMED when it has evidence, a PoC, demonstrated impact, a severity,
  // and a named target (what host/repo/scope this affects).
  if (
    record.status === "confirmed" &&
    (!record.evidence ||
      !record.poc ||
      !record.impact ||
      !record.severity ||
      !record.target ||
      !record.disconfirmation)
  ) {
    throw new Error(
      "Confirmed cases require evidence, poc, impact, severity, target, and disconfirmation",
    );
  }
  if (record.status === "blocked" && (record.blockers ?? []).length === 0) {
    throw new Error("Blocked cases require at least one blocker");
  }
  if (
    record.status === "killed" &&
    !record.evidence &&
    !record.nextStep &&
    (record.blockers ?? []).length === 0 &&
    (record.assumptions ?? []).length === 0
  ) {
    throw new Error(
      "Killed cases require evidence, next step, blockers, or assumptions explaining why",
    );
  }
  // A case becomes REPORTED only after a report FILE that passes the content
  // gate exists on disk. Existence is not enough: any non-empty file — or a
  // directory — would otherwise flip the case to a permanent, immutable state.
  if (record.status === "reported") {
    // Imported lazily as a type-only dependency: validateReportFile is defined
    // in format helpers within ledger.ts and injected here to avoid a runtime
    // cycle. The setter runs at module init in ledger.ts.
    if (validateReportFileImpl === undefined) {
      throw new Error("Report validation unavailable — ledger not fully initialized");
    }
    const reportError = validateReportFileImpl(record.reportPath, record);
    if (reportError) {
      throw new Error(`Reported cases require a valid report file: ${reportError}`);
    }
  }
}

let validateReportFileImpl:
  | ((reportPath: string | undefined, record: CaseRecord) => string | null)
  | undefined;

export function setValidateReportFile(
  impl: (reportPath: string | undefined, record: CaseRecord) => string | null,
): void {
  validateReportFileImpl = impl;
}

export function withImmediateTransaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const value = fn();
    db.exec("COMMIT");
    return value;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore rollback errors
    }
    throw err;
  }
}

export function upsertCase(db: DatabaseSync, record: CaseRecord) {
  // Use ON CONFLICT DO UPDATE (not INSERT OR REPLACE) so FK CASCADE does not
  // wipe case_links when updating an existing primary key.
  const stmt = db.prepare(`
    INSERT INTO cases (
      id, title, status, ever_advanced, confidence, severity, priority, target, endpoint, bugClass,
      summary, evidence, impact, nextStep, poc, remediation,
      references_json, blockers_json, tags_json, assumptions_json, poc_verified_json,
      disconfirmation, disconfirmation_verified_json, disprove_if_json, control_verified_json,
      pending_confirmation_json, confirmer_verdict_json,
      reported_at, report_path, retry_policy_json, invariant, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?,
      ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(id) DO UPDATE SET
      title = excluded.title,
      status = excluded.status,
      ever_advanced = excluded.ever_advanced,
      confidence = excluded.confidence,
      severity = excluded.severity,
      priority = excluded.priority,
      target = excluded.target,
      endpoint = excluded.endpoint,
      bugClass = excluded.bugClass,
      summary = excluded.summary,
      evidence = excluded.evidence,
      impact = excluded.impact,
      nextStep = excluded.nextStep,
      poc = excluded.poc,
      remediation = excluded.remediation,
      references_json = excluded.references_json,
      blockers_json = excluded.blockers_json,
      tags_json = excluded.tags_json,
      assumptions_json = excluded.assumptions_json,
      poc_verified_json = excluded.poc_verified_json,
      disconfirmation = excluded.disconfirmation,
      disconfirmation_verified_json = excluded.disconfirmation_verified_json,
      disprove_if_json = excluded.disprove_if_json,
      control_verified_json = excluded.control_verified_json,
      pending_confirmation_json = excluded.pending_confirmation_json,
      confirmer_verdict_json = excluded.confirmer_verdict_json,
      invariant = excluded.invariant,
      reported_at = excluded.reported_at,
      report_path = excluded.report_path,
      retry_policy_json = excluded.retry_policy_json,
      created_at = excluded.created_at,
      updated_at = excluded.updated_at
  `);

  stmt.run(
    record.id,
    record.title,
    record.status,
    record.everAdvanced ? 1 : 0,
    record.confidence,
    record.severity || null,
    record.priority || null,
    record.target || null,
    record.endpoint || null,
    record.bugClass || null,
    record.summary || null,
    record.evidence || null,
    record.impact || null,
    record.nextStep || null,
    record.poc || null,
    record.remediation || null,
    JSON.stringify(record.references),
    JSON.stringify(record.blockers),
    JSON.stringify(record.tags),
    JSON.stringify(record.assumptions),
    record.pocVerified ? JSON.stringify(record.pocVerified) : null,
    record.disconfirmation || null,
    record.disconfirmationVerified ? JSON.stringify(record.disconfirmationVerified) : null,
    JSON.stringify(record.disproveIf),
    record.controlVerified ? JSON.stringify(record.controlVerified) : null,
    record.pendingConfirmation ? JSON.stringify(record.pendingConfirmation) : null,
    record.confirmerVerdict ? JSON.stringify(record.confirmerVerdict) : null,
    record.reportedAt || null,
    record.reportPath || null,
    record.retryPolicy ? JSON.stringify(record.retryPolicy) : null,
    record.invariant || null,
    record.createdAt,
    record.updatedAt,
  );
}

export function insertEvidenceItem(db: DatabaseSync, item: EvidenceItem): void {
  db.prepare(
    `INSERT INTO evidence_items (id, case_id, role, artifact_path, sha256, summary, created_at, contains_secret, secret_findings_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    item.id,
    item.caseId,
    item.role,
    item.artifactPath ?? null,
    item.sha256 ?? null,
    item.summary,
    item.createdAt,
    item.containsSecret === true ? 1 : 0,
    item.secretFindings?.length ? JSON.stringify(item.secretFindings) : null,
  );
}

// ── Event journal ────────────────────────────────────────────────────

export type CaseEvent = {
  caseId: string;
  seq: number;
  timestamp: string;
  eventType: string;
  actor: string;
  payload?: Record<string, unknown>;
};

/**
 * Append one journal event for a case. Append-only: seq is allocated as
 * max(seq)+1 under the caller's transaction, so events land in commit order.
 * Payloads must stay small and secret-free (field NAMES and ids, not values).
 */
export function appendCaseEvent(
  db: DatabaseSync,
  event: { caseId: string; eventType: string; actor?: string; payload?: Record<string, unknown> },
): void {
  const row = db
    .prepare("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM case_events WHERE case_id = ?")
    .get(event.caseId) as { max_seq: number } | undefined;
  const seq = (row?.max_seq ?? 0) + 1;
  db.prepare(
    "INSERT INTO case_events (case_id, seq, timestamp, event_type, actor, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
  ).run(
    event.caseId,
    seq,
    new Date().toISOString(),
    event.eventType,
    event.actor ?? "agent",
    event.payload ? JSON.stringify(event.payload) : null,
  );
}
