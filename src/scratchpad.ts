/**
 * Scratchpad — intermediate working-notes store for a run.
 *
 * The casefile owns state transitions; the scratchpad owns artifacts.
 * The agent writes its outputs here (recon maps, trace outputs, verification
 * logs) instead of stuffing everything into casefile text fields.
 *
 * Directory layout per run (one subdir per phase — see PHASE_DIRS):
 *   {project_root}/.scratchpad/{run_id}/
 *     recon/      — fingerprints, tech detection, surface maps
 *     hunt/       — per-class findings
 *     gapfil/     — gap-fill audit notes (legacy)
 *     trace/      — per-finding reachability traces
 *     skeptic/    — adversarial disproof attempts
 *     verify/     — PoC logs, run outputs (validate phase)
 *     chain/      — exploit-chain analysis
 *     patch/      — remediation work
 *     report/     — final report context
 *     state.json  — legacy checkpoint file (read for context gating; the
 *                   write-side checkpoint API was removed with the pipeline)
 *
 * Resume re-reads scratchpad artifacts; it does not re-run completed phases
 * (idempotent). The `.scratchpad/` directory is preserved between runs;
 * `scratchpad_clear()` clears it for a single run.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import {
  assertSafeRegularFile,
  assertSafeStateDirectory,
  ensureSafeStateDirectory,
  readSafeFile,
  writeSafeFileAtomic,
} from "./safe-state.ts";

// ── Types ────────────────────────────────────────────────────────────

export type ScratchpadPhase =
  | "recon"
  | "hunt"
  | "gapfil"
  | "trace"
  | "skeptic"
  | "validate"
  | "chain"
  | "patch"
  | "report";

export interface ScratchpadCheckpoint {
  run_id: string;
  project_root: string;
  created_at: string;
  last_updated: string;
  /** Ordered list of phases that have completed (in pipeline order). */
  completed_phases: ScratchpadPhase[];
  /** ISO timestamp of the last phase completion. */
  last_phase_at: string | null;
  /** Key IDs produced by each phase — case IDs, finding IDs, etc. */
  phase_ids: Record<ScratchpadPhase, string[]>;
  /** Free-form summary per phase, set by checkpoint(). */
  phase_summaries: Record<ScratchpadPhase, string>;
}

export interface ScratchpadResume {
  checkpoint: ScratchpadCheckpoint;
  /** Artifact references per phase: { trace: ["finding-abc.json", ...], ... } */
  artifacts: Record<string, string[]>;
}

// ── Constants ────────────────────────────────────────────────────────

// All accepted artifact buckets. Some are legacy/manual-only.
export const SCRATCHPAD_PHASES: ScratchpadPhase[] = [
  "recon",
  "hunt",
  "gapfil",
  "trace",
  "skeptic",
  "validate",
  "chain",
  "patch",
  "report",
];

const PHASE_DIRS: Record<ScratchpadPhase, string> = {
  recon: "recon",
  hunt: "hunt",
  gapfil: "gapfil",
  trace: "trace",
  skeptic: "skeptic",
  validate: "verify",
  chain: "chain",
  patch: "patch",
  report: "report",
};

const SCRATCHPAD_DIR = ".scratchpad";

// ── Helpers ──────────────────────────────────────────────────────────

let scratchpadRootOverride: string | undefined;

/**
 * Walk up from cwd to the first directory containing any of `markers`.
 * PWD is deliberately excluded (shell-set, can be stale/forged); explicit
 * env overrides win, then the real cwd walk. Shared by ledger, scratchpad,
 * and the PoC runner so the heuristic lives in one place.
 */
export function findWorkspaceRoot(envNames: string[], markers: string[]): string {
  for (const e of envNames) {
    const v = process.env[e]?.trim();
    if (v) return resolve(v);
  }

  let curr = resolve(process.cwd());
  for (let i = 0; i < 20; i++) {
    if (markers.some((m) => existsSync(join(curr, m)))) return curr;
    const parent = dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return resolve(process.cwd());
}

/** Detect the scratchpad workspace root (override, env, then walk up). */
export function detectWorkspaceRoot(): string {
  if (scratchpadRootOverride) return scratchpadRootOverride;
  return findWorkspaceRoot(
    ["XPI_SCRATCHPAD_ROOT", "PI_WORKSPACE_ROOT", "GITHUB_WORKSPACE"],
    [".git", "package.json"],
  );
}

/** Override the scratchpad root (for testing). Pass undefined to reset. */
export function setScratchpadRoot(path: string | undefined): void {
  scratchpadRootOverride = path ? resolve(path) : undefined;
}

/** The top-level scratchpad directory for a given project root. */
export function getScratchpadRoot(projectRoot?: string): string {
  const root = projectRoot ?? detectWorkspaceRoot();
  return join(root, SCRATCHPAD_DIR);
}

/**
 * Sanitize an agent-supplied name into a single safe path component. `..`/`/`
 * would let join() escape its base directory (ScratchpadClear("..") would
 * recursively delete the project root; an artifact named ".." points at the
 * phase dir itself), so anything outside the allowlist becomes `_`, and a
 * dot-only or empty result is rejected.
 */
function sanitizeName(name: string, label: string): string {
  const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!safe || /^\.+$/.test(safe)) {
    throw new Error(`Invalid ${label}: "${name}" — nothing left after sanitization`);
  }
  return safe;
}

/**
 * Sanitized name + disambiguation hash: sanitization is lossy ("a/b" and
 * "a_b" both become "a_b"), so a CHANGED name gets a content hash suffix —
 * distinct inputs can no longer silently overwrite each other's file.
 * Reads use the same mapping, so round-trips stay consistent.
 */
function sanitizeWithHashSuffix(name: string, label: string): string {
  const safe = sanitizeName(name, label);
  if (safe === name) return safe;
  const suffix = createHash("sha256").update(name).digest("hex").slice(0, 12);
  return `${safe.slice(0, 80)}-${suffix}`;
}

function runDirName(runId: string): string {
  return sanitizeWithHashSuffix(runId, "run_id");
}

function artifactFileName(name: string): string {
  return sanitizeWithHashSuffix(name, "artifact name");
}

/** Cap on a single scratchpad artifact (2 MiB) — a hallucinating or hostile
 * subagent must not be able to fill the disk with unbounded writes. */
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024;

/** The directory for a specific run. */
function getRunDir(runId: string, projectRoot?: string): string {
  return join(getScratchpadRoot(projectRoot), runDirName(runId));
}

/** The state.json path for a run. */
function getStatePath(runId: string, projectRoot?: string): string {
  return join(getRunDir(runId, projectRoot), "state.json");
}

function ensureRunDirs(runDir: string): void {
  const scratchpadRoot = dirname(runDir);
  const projectRoot = dirname(scratchpadRoot);
  const runName = basename(runDir);
  ensureSafeStateDirectory(projectRoot, [SCRATCHPAD_DIR, runName]);
  for (const phase of SCRATCHPAD_PHASES) {
    ensureSafeStateDirectory(projectRoot, [SCRATCHPAD_DIR, runName, PHASE_DIRS[phase]]);
  }
}

function readCheckpointRaw(runId: string, projectRoot?: string): ScratchpadCheckpoint | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const statePath = getStatePath(runId, projectRoot);
  if (existsSync(statePath)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId)]);
  }
  if (!assertSafeRegularFile(statePath, "Scratchpad checkpoint")) return null;
  const raw = readSafeFile(statePath, "Scratchpad checkpoint").toString("utf8");
  const cp = JSON.parse(raw) as ScratchpadCheckpoint;
  if (typeof cp !== "object" || cp === null || Array.isArray(cp)) {
    throw new Error(`Corrupt scratchpad state for ${runId}: root must be an object`);
  }
  if (cp.run_id !== runId) {
    throw new Error(`Corrupt scratchpad state for ${runId}: state belongs to ${cp.run_id}`);
  }
  if (!Array.isArray(cp.completed_phases)) {
    throw new Error(`Corrupt scratchpad state for ${runId}: completed_phases must be an array`);
  }
  for (const phase of cp.completed_phases) {
    if (!SCRATCHPAD_PHASES.includes(phase)) {
      throw new Error(`Corrupt scratchpad state for ${runId}: invalid phase ${phase}`);
    }
  }
  if (!cp.phase_ids || typeof cp.phase_ids !== "object" || Array.isArray(cp.phase_ids)) {
    cp.phase_ids = {} as Record<ScratchpadPhase, string[]>;
  }
  if (
    !cp.phase_summaries ||
    typeof cp.phase_summaries !== "object" ||
    Array.isArray(cp.phase_summaries)
  ) {
    cp.phase_summaries = {} as Record<ScratchpadPhase, string>;
  }
  return cp;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Write an artifact to a phase's subdirectory. Overwrites if the name exists.
 * Returns the full path to the written artifact.
 */
export function scratchpad_write(
  runId: string,
  phase: ScratchpadPhase,
  artifactName: string,
  content: string,
  projectRoot?: string,
): string {
  const root = projectRoot ?? detectWorkspaceRoot();
  const runDir = getRunDir(runId, root);
  ensureRunDirs(runDir);

  if (Buffer.byteLength(content, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new Error(
      `Artifact too large (${Buffer.byteLength(content, "utf8")} bytes; max ${MAX_ARTIFACT_BYTES}): ${artifactName}`,
    );
  }

  // Sanitize + disambiguate artifact name: no path traversal, no dot-only
  // escape, and lossy sanitization cannot collide two distinct names.
  const safeName = artifactFileName(artifactName);
  const dir = join(runDir, PHASE_DIRS[phase]);
  const filePath = join(dir, safeName);
  writeSafeFileAtomic(filePath, content);
  return filePath;
}

/**
 * Read an artifact. Returns null if missing.
 */
export function scratchpad_read(
  runId: string,
  phase: ScratchpadPhase,
  artifactName: string,
  projectRoot?: string,
): string | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const safeName = artifactFileName(artifactName);
  const filePath = join(getRunDir(runId, root), PHASE_DIRS[phase], safeName);
  if (existsSync(filePath)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId), PHASE_DIRS[phase]]);
  }
  if (!assertSafeRegularFile(filePath, "Scratchpad artifact")) return null;
  return readSafeFile(filePath, "Scratchpad artifact").toString("utf8");
}

/**
 * A run directory discovered by direct scan — no state.json required. The slim
 * extension surface (Write/Read/Clear only) never checkpoints, so discovery
 * must not depend on state.json existing.
 */
export type DiscoveredScratchpadRun = {
  /** Directory name under .scratchpad (the sanitized run id). */
  dir: string;
  /** Artifact file names per phase bucket, non-empty buckets only. */
  phases: Record<string, string[]>;
};

/**
 * Scan the scratchpad root for run directories carrying artifacts. Unlike
 * scratchpad_runs(), this lists runs WITHOUT a state.json checkpoint — the
 * only writer of state.json (ScratchpadInit/Checkpoint) is no longer exposed
 * as a tool, so directory scan is the primary discovery path.
 */
export function scratchpad_discover_artifacts(projectRoot?: string): DiscoveredScratchpadRun[] {
  const root = getScratchpadRoot(projectRoot);
  if (!existsSync(root)) return [];
  assertSafeStateDirectory(dirname(root), [SCRATCHPAD_DIR]);
  const out: DiscoveredScratchpadRun[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    // Dirent.isDirectory() is lstat-based: a symlinked run dir reports as a
    // symlink and is skipped here.
    if (!entry.isDirectory()) continue;
    const dir = entry.name;
    const phases: Record<string, string[]> = {};
    for (const phase of SCRATCHPAD_PHASES) {
      const phaseDir = join(root, dir, PHASE_DIRS[phase]);
      if (!existsSync(phaseDir)) continue;
      try {
        assertSafeStateDirectory(dirname(root), [SCRATCHPAD_DIR, dir, PHASE_DIRS[phase]]);
      } catch {
        continue;
      }
      const names = readdirSync(phaseDir).filter(
        (f) =>
          f !== "state.json" && assertSafeRegularFile(join(phaseDir, f), "Scratchpad artifact"),
      );
      if (names.length > 0) phases[phase] = names;
    }
    if (Object.keys(phases).length > 0) out.push({ dir, phases });
  }
  return out;
}

/**
 * Read an artifact from a DISCOVERED run directory (see
 * scratchpad_discover_artifacts) by phase bucket key. Same safety checks as
 * scratchpad_read, but addressed by directory name because the original run id
 * is unrecoverable without a checkpoint.
 */
export function scratchpad_read_discovered(
  dir: string,
  phase: ScratchpadPhase,
  artifactName: string,
  projectRoot?: string,
): string | null {
  const phaseDir = PHASE_DIRS[phase];
  if (!phaseDir) return null;
  if (!dir || dir === "." || dir === ".." || dir.includes("/") || dir.includes("\\")) return null;
  const root = getScratchpadRoot(projectRoot);
  const filePath = join(root, dir, phaseDir, artifactName);
  if (existsSync(filePath)) {
    assertSafeStateDirectory(dirname(root), [SCRATCHPAD_DIR, dir, phaseDir]);
  }
  if (!assertSafeRegularFile(filePath, "Scratchpad artifact")) return null;
  return readSafeFile(filePath, "Scratchpad artifact").toString("utf8");
}

/**
 * List all artifacts written for a phase.
 */
export function scratchpad_list(
  runId: string,
  phase: ScratchpadPhase,
  projectRoot?: string,
): string[] {
  const root = projectRoot ?? detectWorkspaceRoot();
  const dir = join(getRunDir(runId, root), PHASE_DIRS[phase]);
  if (!existsSync(dir)) return [];
  assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId), PHASE_DIRS[phase]]);
  return readdirSync(dir).filter(
    (f) => f !== "state.json" && assertSafeRegularFile(join(dir, f), "Scratchpad artifact"),
  );
}

/**
 * Read a legacy checkpoint (state.json) + artifact references for resume.
 * Returns null if the run has no checkpoint — the write-side checkpoint API
 * was removed with the pipeline; this only reads what older runs left behind.
 */
export function scratchpad_resume(runId: string, projectRoot?: string): ScratchpadResume | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const cp = readCheckpointRaw(runId, root);
  if (!cp) return null;

  // Gather artifact listing per completed phase.
  const artifacts: Record<string, string[]> = {};
  for (const phase of cp.completed_phases) {
    artifacts[phase] = scratchpad_list(runId, phase, root);
  }

  return { checkpoint: cp, artifacts };
}

/**
 * Clear a specific run's scratchpad directory — a fresh start for that one
 * run. Does not touch other runs.
 */
export function scratchpad_clear(runId: string, projectRoot?: string): void {
  const root = projectRoot ?? detectWorkspaceRoot();
  const runDir = getRunDir(runId, root);
  if (existsSync(runDir)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId)]);
    rmSync(runDir, { recursive: true, force: true });
  }
}
