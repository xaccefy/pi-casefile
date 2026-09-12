import assert from "node:assert";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  getScratchpadRoot,
  scratchpad_clear,
  scratchpad_discover_artifacts,
  scratchpad_list,
  scratchpad_read,
  scratchpad_read_discovered,
  scratchpad_resume,
  scratchpad_write,
  setScratchpadRoot,
} from "../src/scratchpad.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "scratchpad-test-"));
  setScratchpadRoot(tempDir);
});

afterEach(async () => {
  setScratchpadRoot(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

/** Run dir for a SAFE run id (dir name === run id). */
const runDir = (runId: string) => join(getScratchpadRoot(tempDir), runId);

/** Seed a legacy checkpoint (state.json) the way pre-slim runs wrote them. */
function seedCheckpoint(runId: string, phaseIds: Record<string, string[]>): void {
  writeFileSync(
    join(runDir(runId), "state.json"),
    JSON.stringify({
      run_id: runId,
      project_root: tempDir,
      created_at: new Date().toISOString(),
      last_updated: new Date().toISOString(),
      last_phase_at: null,
      completed_phases: Object.keys(phaseIds),
      phase_ids: phaseIds,
      phase_summaries: {},
    }),
    "utf8",
  );
}

describe("scratchpad", () => {
  it("write creates the phase directory structure and round-trips an artifact", () => {
    const path = scratchpad_write("run-1", "trace", "finding-abc.json", '{"reachable": true}');
    assert.ok(path.endsWith("finding-abc.json"));
    assert.ok(existsSync(join(runDir("run-1"), "recon")));
    assert.ok(existsSync(join(runDir("run-1"), "verify")));

    const content = scratchpad_read("run-1", "trace", "finding-abc.json");
    assert.strictEqual(content, '{"reachable": true}');
  });

  it("rejects a pre-planted scratchpad-directory symlink", () => {
    const outside = mkdtempSync(join(tmpdir(), "scratchpad-outside-"));
    try {
      symlinkSync(outside, join(tempDir, ".scratchpad"), "dir");
      assert.throws(() => scratchpad_write("run-1", "recon", "x.json", "x"), /real directory/);
      assert.deepStrictEqual(readdirSync(outside), []);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("rejects an artifact symlink without overwriting its target", () => {
    const outside = mkdtempSync(join(tmpdir(), "scratchpad-outside-"));
    try {
      scratchpad_write("run-1", "trace", "warmup.json", "{}");
      const victim = join(outside, "victim.txt");
      writeFileSync(victim, "operator data", "utf8");
      const artifact = join(runDir("run-1"), "trace", "finding.json");
      symlinkSync(victim, artifact);

      assert.throws(
        () => scratchpad_write("run-1", "trace", "finding.json", "attacker data"),
        /regular, non-symlink file/,
      );
      assert.strictEqual(readFileSync(victim, "utf8"), "operator data");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("read returns null for missing artifact", () => {
    assert.strictEqual(scratchpad_read("run-1", "trace", "nope.json"), null);
  });

  it("write sanitizes artifact names to prevent path traversal", () => {
    const path = scratchpad_write("run-1", "recon", "../../etc/passwd", "evil");
    // The file must land inside the recon dir — no escape.
    const reconDir = join(runDir("run-1"), "recon");
    assert.ok(path.startsWith(reconDir), `path ${path} escaped recon dir`);
    // Verify the content was actually written to the sanitized path.
    assert.strictEqual(scratchpad_read("run-1", "recon", "../../etc/passwd"), "evil");
  });

  it("run_id cannot traverse out of the scratchpad root (clear/write)", () => {
    // Regression: sanitizeRunId — ScratchpadClear("..") previously deleted the
    // project root; "../../x" wrote outside .scratchpad.
    scratchpad_write("run-1", "recon", "x.json", "x");
    assert.throws(() => scratchpad_clear(".."), /Invalid run_id/); // dot-only: rejected
    assert.ok(
      existsSync(join(tempDir, ".scratchpad", "run-1")),
      "../ clear must not touch the run dir",
    );

    const path = scratchpad_write("../../evil", "recon", "x.json", "payload");
    assert.ok(path.startsWith(tempDir), `write with traversal run_id escaped scratchpad: ${path}`);
    assert.ok(!existsSync(join(tempDir, "..", "evil")), "no dir created outside root");
  });

  it("rejects run_ids that sanitize to dot-only", () => {
    for (const id of [".", "..", "..."]) {
      assert.throws(() => scratchpad_write(id, "recon", "x.json", "x"), /Invalid run_id/);
    }
    // But separators elsewhere sanitize into a unique safe dir name.
    scratchpad_write("https://target.example.com/api", "recon", "x.json", "x");
    const dirs = readdirSync(join(tempDir, ".scratchpad"));
    assert.ok(dirs.some((d) => d.startsWith("https___target.example.com_api-")));
  });

  it("rejects dot-only artifact names on write and read (no EISDIR escape)", () => {
    scratchpad_write("run-1", "recon", "warmup.json", "{}");
    assert.throws(() => scratchpad_write("run-1", "recon", "..", "x"), /Invalid artifact name/);
    assert.throws(() => scratchpad_write("run-1", "recon", ".", "x"), /Invalid artifact name/);
    assert.throws(() => scratchpad_read("run-1", "recon", ".."), /Invalid artifact name/);
    // Sanitized-to-dot-only also rejected; nothing written.
    assert.throws(() => scratchpad_write("run-1", "recon", "...", "x"), /Invalid artifact name/);
    assert.strictEqual(
      readdirSync(join(runDir("run-1"), "recon")).length,
      1, // only warmup.json
      "no artifact written",
    );
  });

  it("list returns artifacts for a phase", () => {
    scratchpad_write("run-1", "trace", "a.json", "a");
    scratchpad_write("run-1", "trace", "b.json", "b");
    const list = scratchpad_list("run-1", "trace");
    assert.deepStrictEqual(list.sort(), ["a.json", "b.json"]);
  });

  it("list returns empty for a phase with no artifacts", () => {
    scratchpad_write("run-1", "recon", "x.json", "x");
    assert.deepStrictEqual(scratchpad_list("run-1", "trace"), []);
  });

  it("resume reads a legacy checkpoint and its artifacts", () => {
    scratchpad_write("run-1", "recon", "fingerprint.json", "tech: express");
    seedCheckpoint("run-1", { recon: ["case_r"] });

    const resume = scratchpad_resume("run-1")!;
    assert.strictEqual(resume.checkpoint.run_id, "run-1");
    assert.deepStrictEqual(resume.checkpoint.phase_ids.recon, ["case_r"]);
    assert.deepStrictEqual(resume.artifacts.recon, ["fingerprint.json"]);
  });

  it("resume returns null for a run without a checkpoint", () => {
    assert.strictEqual(scratchpad_resume("nope"), null);
    scratchpad_write("checkpointless", "recon", "x.json", "x");
    assert.strictEqual(scratchpad_resume("checkpointless"), null);
  });

  it("discovery lists runs by their artifacts — no state.json required", () => {
    scratchpad_write("run-plain", "recon", "entry-points.md", "map");
    scratchpad_write("run-checked", "trace", "finding.json", "{}");
    seedCheckpoint("run-checked", { trace: ["case_a"] });

    const runs = scratchpad_discover_artifacts(tempDir);
    const dirs = runs.map((r) => r.dir);
    assert.ok(dirs.includes("run-plain"), "checkpointless run discovered");
    assert.ok(dirs.includes("run-checked"), "checkpointed run discovered");
    const plain = runs.find((r) => r.dir === "run-plain")!;
    assert.deepStrictEqual(plain.phases.recon, ["entry-points.md"]);
    // Discovered read path works for both.
    assert.strictEqual(scratchpad_read_discovered("run-plain", "recon", "entry-points.md"), "map");
    assert.strictEqual(scratchpad_read_discovered("../evil", "recon", "x"), null);
  });

  it("clear removes a single run without touching others", () => {
    scratchpad_write("run-1", "recon", "x.json", "x");
    scratchpad_write("run-2", "recon", "y.json", "y");
    scratchpad_clear("run-1");
    const runs = readdirSync(getScratchpadRoot(tempDir));
    assert.deepStrictEqual(runs, ["run-2"]);
  });
});
