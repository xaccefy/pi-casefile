import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runPoc, setProjectRoot, setSandboxDisabledForTest } from "../src/poc-runner.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "poc-runner-test-"));
  // Pin path containment to the temp dir and keep runs hermetic: the sandbox
  // is disabled via the test seam (no Docker dependency, no image pulls), so
  // every run lands on the host with the minimal env contract.
  setProjectRoot(tempDir);
  setSandboxDisabledForTest(true);
});

afterEach(async () => {
  setProjectRoot(undefined);
  setSandboxDisabledForTest(false);
  await rm(tempDir, { recursive: true, force: true });
});

describe("poc-runner", () => {
  it("validates paths to prevent traversal", () => {
    const invalidPath = join(tempDir, "../../../etc/passwd");
    expect(() => runPoc(invalidPath, { local: true })).toThrow(
      /traversal segments|under the project workspace/,
    );
  });

  it("fails on unknown extensions", () => {
    const badPoc = join(tempDir, "poc.unknown");
    writeFileSync(badPoc, "echo 1", "utf8");
    expect(() => runPoc(badPoc, { local: true })).toThrow(/Cannot determine PoC language for/);
  });

  it("runs a shell script locally", () => {
    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho 'hello world'", "utf8");

    const result = runPoc(shPoc, { local: true });

    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("hello world");
    expect(result.sandbox).toBe(false);
  });

  it("runs on the host when the sandbox path is unavailable (no operator gates)", () => {
    // Sandbox isolation is best-effort: when the Docker path is unavailable,
    // BOTH default and local:true runs fall back to a bare host run with the
    // minimal env — there is no operator authorization gate to trip over.
    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho 'host fallback'", "utf8");

    const plain = runPoc(shPoc);
    expect(plain.sandbox).toBe(false);
    expect(plain.completed).toBe(true);
    expect(plain.output).toContain("host fallback");

    const withNetwork = runPoc(shPoc, { local: true });
    expect(withNetwork.sandbox).toBe(false);
    expect(withNetwork.completed).toBe(true);
    expect(withNetwork.output).toContain("host fallback");
  });

  it("passes the harness env contract (PI_POC_MODE / PI_POC_TARGET) to local runs", () => {
    const shPoc = join(tempDir, "poc-env.sh");
    writeFileSync(shPoc, '#!/bin/sh\nprintf \'%s|%s\' "$PI_POC_MODE" "$PI_POC_TARGET"', "utf8");

    const result = runPoc(shPoc, {
      local: true,
      env: { PI_POC_MODE: "poc", PI_POC_TARGET: "http://example.test" },
    });

    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("poc|http://example.test");
  });

  it("does not leak operator env (PI_* secrets, proxy vars) into local runs", () => {
    // Local PoC scripts are untrusted agent-authored code running on the host;
    // they must see the harness env contract + PATH, never the operator's
    // ambient process env (proxy URLs can embed credentials; operator PI_*
    // vars can be bearer secrets).
    const sentinel = `sentinel-${randomBytes(8).toString("hex")}`;
    const previousToken = process.env.PI_OPERATOR_SECRET_TOKEN;
    const previousProxy = process.env.https_proxy;
    process.env.PI_OPERATOR_SECRET_TOKEN = sentinel;
    process.env.https_proxy = "http://user:leaked-pass@proxy.example:8080";
    const shPoc = join(tempDir, "poc-envdump.sh");
    writeFileSync(shPoc, "#!/bin/sh\nenv\n", "utf8");

    try {
      const result = runPoc(shPoc, {
        local: true,
        env: { PI_POC_MODE: "poc", PI_POC_TARGET: "http://example.test" },
      });

      // Exit 0 proves PATH still resolves the interpreter under the minimal env.
      expect(result.exitCode).toBe(0);
      expect(result.output).toContain("PI_POC_MODE=poc");
      expect(result.output).toContain("PI_POC_TARGET=http://example.test");
      expect(result.output).not.toContain(sentinel);
      expect(result.output).not.toContain("leaked-pass");
    } finally {
      if (previousToken === undefined) delete process.env.PI_OPERATOR_SECRET_TOKEN;
      else process.env.PI_OPERATOR_SECRET_TOKEN = previousToken;
      if (previousProxy === undefined) delete process.env.https_proxy;
      else process.env.https_proxy = previousProxy;
    }
  });

  it("uses a fresh CSPRNG-shaped evidence nonce for every run", () => {
    const shPoc = join(tempDir, "nonce-evidence.sh");
    writeFileSync(
      shPoc,
      `#!/bin/sh
printf '{"nonce":"%s","claim":"target signal","verify":{"method":"GET","url":"http://example.test/proof","expect":{"body_contains":["target signal"]}},"observations":[],"baseline":{"method":"GET","url":"http://example.test/safe"}}' "$PI_POC_NONCE" > "$PI_POC_EVIDENCE_DIR/evidence.json"`,
      "utf8",
    );

    const first = runPoc(shPoc, { local: true });
    const second = runPoc(shPoc, { local: true });
    expect(first.nonce).toMatch(/^poc_[a-f0-9]{48}$/);
    expect(second.nonce).toMatch(/^poc_[a-f0-9]{48}$/);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.evidence?.nonce).toBe(first.nonce);
    expect(second.evidence?.nonce).toBe(second.nonce);
  });

  it("rejects oversized evidence.json before parsing or preserving it", () => {
    const shPoc = join(tempDir, "oversized-evidence.sh");
    writeFileSync(
      shPoc,
      '#!/bin/sh\nhead -c 300000 /dev/zero | tr "\\0" x > "$PI_POC_EVIDENCE_DIR/evidence.json"',
      "utf8",
    );

    const result = runPoc(shPoc, { local: true });
    expect(result.exitCode).toBe(0);
    expect(result.evidence).toBeUndefined();
    expect(result.evidencePath).toBeUndefined();
    expect(result.evidenceError).toContain("too large");
  });

  it("rejects a symlinked evidence.json", () => {
    const shPoc = join(tempDir, "symlink-evidence.sh");
    writeFileSync(
      shPoc,
      '#!/bin/sh\nln -s /etc/passwd "$PI_POC_EVIDENCE_DIR/evidence.json"',
      "utf8",
    );

    const result = runPoc(shPoc, { local: true });
    expect(result.exitCode).toBe(0);
    expect(result.evidence).toBeUndefined();
    expect(result.evidencePath).toBeUndefined();
    expect(result.evidenceError).toContain("non-symlink");
  });

  it("rejects a symlinked durable PoC evidence store", () => {
    const shPoc = join(tempDir, "valid-evidence.sh");
    writeFileSync(
      shPoc,
      `#!/bin/sh
printf '{"nonce":"%s","claim":"target signal","verify":{"method":"GET","url":"http://example.test/proof","expect":{"status":[200],"body_contains":["target signal"]}},"observations":[],"baseline":{"method":"GET","url":"http://example.test/safe"}}' "$PI_POC_NONCE" > "$PI_POC_EVIDENCE_DIR/evidence.json"`,
      "utf8",
    );
    const outside = mkdtempSync(join(tmpdir(), "poc-evidence-outside-"));
    try {
      mkdirSync(join(tempDir, ".pi"), { mode: 0o700 });
      symlinkSync(outside, join(tempDir, ".pi", "poc-evidence"), "dir");

      const result = runPoc(shPoc, { local: true });
      expect(result.exitCode).toBe(0);
      expect(result.evidence).toBeUndefined();
      expect(result.evidencePath).toBeUndefined();
      expect(result.evidenceError).toContain("could not be preserved");
      expect(readdirSync(outside)).toEqual([]);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("sanitizes control characters from output", () => {
    const shPoc = join(tempDir, "poc.sh");
    // Print ANSI color escape and a null byte
    writeFileSync(shPoc, '#!/bin/sh\nprintf "\\033[31mhello\\033[0m \\000world\\n"', "utf8");

    const result = runPoc(shPoc, { local: true });

    // ANSI codes and null byte should be stripped
    expect(result.output).not.toContain("\x1b[31m");
    expect(result.output).not.toContain("\x00");
    expect(result.output).toContain("hello world");
  });

  it("keeps the FULL sanitized output in rawOutput while output is a display slice", () => {
    const shPoc = join(tempDir, "poc.sh");
    // 5000 lines of filler, then the marker at the end — past the 4000-char
    // display window. Marker checks MUST run on rawOutput, never on output.
    const body = Array.from({ length: 500 }, () => "x".repeat(20)).join("\n");
    writeFileSync(shPoc, `#!/bin/sh\necho "${body}"\necho MARKER_AT_THE_END`, "utf8");

    const result = runPoc(shPoc, { local: true });

    expect(result.exitCode).toBe(0);
    expect(result.output).not.toContain("MARKER_AT_THE_END");
    expect(result.truncated).toBe(true);
    expect(result.rawOutput).toContain("MARKER_AT_THE_END");
  });

  it("rejects an unknown extension without a shebang", () => {
    // No env override exists anymore: an unrecognized file type must error,
    // not silently fall through.
    const poc = join(tempDir, "poc.txt");
    writeFileSync(poc, "echo hi", "utf8");

    expect(() => runPoc(poc, { local: true })).toThrow(/Cannot determine PoC language/);
  });

  it("keeps a space-containing PoC path intact (local run, no shell)", () => {
    // Local runs spawn with NO shell so a space in the path stays one arg.
    const dir = mkdtempSync(join(tempDir, "with space-"));
    const poc = join(dir, "poc.sh");
    writeFileSync(poc, "#!/bin/sh\necho 'ok from spaced path'", "utf8");

    const result = runPoc(poc, { local: true });
    expect(result.sandbox).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("ok from spaced path");
    expect(result.output).not.toContain("Cannot find module");
  });
});
