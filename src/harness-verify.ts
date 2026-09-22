/**
 * Harness-side attack/baseline replay.
 *
 * The machine floor cannot trust a caller's self-reported `re_executed`
 * boolean. This module makes the HARNESS re-send the evidence's `verify`
 * (attack) request and the evidence's `baseline` (legitimate) request with
 * its own HTTP client, applying the attack's `expect` predicates to BOTH
 * responses. The main agent supplies the predicate and the baseline; the
 * harness owns evidence acquisition and predicate execution before the later
 * semantic review.
 *
 * Policy:
 * - Private/internal hosts require explicit operator authorization; otherwise
 *   replay fails closed.
 * - Redirects are manual and every hop is checked before it is fetched.
 * - The attack request must match while the baseline request must not.
 *
 * Undici's custom dispatcher pins the approved DNS result through connect;
 * node:dns and node:net provide resolution and address classification.
 */

import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Worker } from "node:worker_threads";
import { isPublicIpAddress } from "@xaccefy/pi-shared";
import { Agent, fetch as undiciFetch } from "undici";
import type { PoCEvidence, VerifyExpect } from "./evidence.ts";

// Public re-export makes the single-source classifier identity testable across
// the web tool and confirmation replay paths.
export { isPublicIpAddress } from "@xaccefy/pi-shared";

export type HarnessVerifyResult = {
  /** true = the harness sent both attack and baseline requests and judged them. */
  attempted: boolean;
  /** Present when attempted: attack matched and baseline did not. */
  pass?: boolean;
  /** Backward-compatible target status summary. */
  status?: number;
  /** Machine-observed attack/baseline response summaries. */
  target?: HarnessResponseObservation;
  control?: HarnessResponseObservation;
  differential?: "target_only" | "both" | "control_only" | "neither";
  note: string;
};

export type HarnessResponseObservation = {
  attempted: boolean;
  matched?: boolean;
  status?: number;
  url: string;
  bodySha256?: string;
  bodyBytes?: number;
  note: string;
};

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;
const REGEX_TIMEOUT_MS = 250;

type ResolvedAddress = { address: string; family: 4 | 6 };

/** Comparison-normalize a hostname: lowercase, strip IPv6 brackets and any trailing root dot. */
function normHost(hostname: string): string {
  return hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

async function resolveHost(hostname: string): Promise<ResolvedAddress[]> {
  const host = normHost(hostname);
  const literalFamily = isIP(host);
  if (literalFamily) return [{ address: host, family: literalFamily as 4 | 6 }];
  const lookup = dnsLookup(host, { all: true, verbatim: true }) as Promise<ResolvedAddress[]>;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      lookup,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS lookup timed out")), 5_000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function parseNetworkTarget(target: string): { url: URL; explicitProtocol: boolean } | undefined {
  const value = target.trim();
  if (!value || /\s/.test(value)) return;
  const explicitProtocol = /^https?:\/\//i.test(value);
  try {
    const url = new URL(explicitProtocol ? value : `http://${value}`);
    if (!(url.protocol === "http:" || url.protocol === "https:") || !url.hostname) return;
    if (url.username || url.password) return;
    return { url, explicitProtocol };
  } catch {
    return;
  }
}

function effectivePort(url: URL): string {
  return url.port || (url.protocol === "https:" ? "443" : "80");
}

/**
 * Bind a model-authored verify URL to the target the harness actually ran.
 * A bare target permits either HTTP scheme; an explicit target URL binds the
 * scheme as well as hostname and effective port.
 */
export function verifyUrlBindingError(verifyUrl: string, target: string): string | undefined {
  const declared = parseNetworkTarget(target);
  let observed: URL;
  try {
    observed = new URL(verifyUrl);
  } catch {
    return `verify.url is not parseable: ${verifyUrl}`;
  }
  if (!declared) return `target is not an HTTP network target: ${target}`;
  const declaredHost = normHost(declared.url.hostname);
  const observedHost = normHost(observed.hostname);
  if (declaredHost !== observedHost) {
    return `verify.url host ${observedHost} does not match run target ${declaredHost}`;
  }
  if (
    (declared.url.port || observed.port) &&
    effectivePort(declared.url) !== effectivePort(observed)
  ) {
    return `verify.url port ${effectivePort(observed)} does not match run target port ${effectivePort(declared.url)}`;
  }
  if (declared.explicitProtocol && declared.url.protocol !== observed.protocol) {
    return `verify.url protocol ${observed.protocol} does not match run target protocol ${declared.url.protocol}`;
  }
  return;
}

// ── Predicate evaluation ──────────────────────────────────────────────

const REGEX_WORKER_SOURCE = `
  const { parentPort, workerData } = require("node:worker_threads");
  try {
    const matches = workerData.patterns.map((pattern) => new RegExp(pattern).test(workerData.body));
    parentPort.postMessage({ matches });
  } catch (error) {
    parentPort.postMessage({ error: error instanceof Error ? error.message : String(error) });
  }
`;

async function evaluateRegexes(
  patterns: string[],
  body: string,
): Promise<{ matches?: boolean[]; error?: string }> {
  if (patterns.length === 0) return { matches: [] };
  return new Promise((resolve) => {
    const worker = new Worker(REGEX_WORKER_SOURCE, {
      eval: true,
      workerData: { patterns, body },
    });
    let settled = false;
    const finish = (result: { matches?: boolean[]; error?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(result);
    };
    const timer = setTimeout(
      () => finish({ error: `evaluation exceeded ${REGEX_TIMEOUT_MS}ms` }),
      REGEX_TIMEOUT_MS,
    );
    worker.once("message", (message) => finish(message));
    worker.once("error", (error) =>
      finish({ error: error instanceof Error ? error.message : String(error) }),
    );
    worker.once("exit", (code) => {
      if (code !== 0) finish({ error: `worker exited with code ${code}` });
    });
  });
}

/** Apply an evidence expect spec to a harness-observed response. */
export async function evaluateExpect(
  expect: VerifyExpect,
  status: number,
  body: string,
): Promise<string[]> {
  const failures: string[] = [];
  if (expect.status && !expect.status.includes(status)) {
    failures.push(`status ${status} not in [${expect.status.join(", ")}]`);
  }
  for (const needle of expect.body_contains ?? []) {
    if (!body.includes(needle)) failures.push(`body_contains missing: ${needle}`);
  }
  const patterns = expect.body_regex ?? [];
  const regex = await evaluateRegexes(patterns, body);
  if (regex.error) {
    failures.push(`body_regex evaluation failed: ${regex.error}`);
  } else {
    for (const [index, re] of patterns.entries()) {
      if (regex.matches?.[index] !== true) failures.push(`body_regex failed: ${re}`);
    }
  }
  return failures;
}

/** Read a response body with a hard byte cap (bounded memory, honest note). */
async function readBodyCapped(
  res: Response,
): Promise<{ text: string; truncated: boolean; bytes: number; sha256: string }> {
  const reader = res.body?.getReader();
  if (!reader) {
    return {
      text: "",
      truncated: false,
      bytes: 0,
      sha256: createHash("sha256").update("").digest("hex"),
    };
  }
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    const remaining = MAX_BODY_BYTES - bytes;
    if (remaining > 0) {
      const kept = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(kept);
      bytes += kept.byteLength;
    }
    if (value.byteLength > remaining || bytes >= MAX_BODY_BYTES) {
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
  }
  const body = Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES);
  return {
    text: new TextDecoder().decode(body),
    truncated,
    bytes: body.byteLength,
    sha256: createHash("sha256").update(body).digest("hex"),
  };
}

// ── Replay ────────────────────────────────────────────────────────────

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
let harnessFetchForTest: FetchLike | undefined;

/** Test seam; production callers leave this undefined and use DNS-pinned undici. */
export function setHarnessFetchForTest(fetchImpl: FetchLike | undefined): void {
  harnessFetchForTest = fetchImpl;
}

type ReplayOptions = {
  timeoutMs?: number;
  allowPrivate?: boolean;
  /** Test-only injection; production always uses the DNS-pinned undici path. */
  fetchImpl?: FetchLike;
};

async function fetchPinned(
  url: URL,
  init: RequestInit,
  addresses: ResolvedAddress[],
): Promise<{ response: Response; close: () => Promise<void> }> {
  const first = addresses[0];
  const pinnedLookup = (
    _hostname: string,
    options: { all?: boolean },
    callback: (
      error: NodeJS.ErrnoException | null,
      address: string | ResolvedAddress[],
      family?: 4 | 6,
    ) => void,
  ) => {
    if (options?.all) callback(null, addresses);
    else callback(null, first.address, first.family);
  };
  const agent = new Agent({
    connect: { lookup: pinnedLookup as never },
  });
  try {
    const response = (await undiciFetch(url, {
      ...(init as object),
      dispatcher: agent,
    } as never)) as unknown as Response;
    return { response, close: () => agent.close() };
  } catch (error) {
    await agent.close().catch(() => undefined);
    throw error;
  }
}

async function replayRequest(
  verify: PoCEvidence["verify"],
  expect: VerifyExpect,
  opts?: ReplayOptions,
): Promise<HarnessResponseObservation> {
  let url: URL;
  try {
    url = new URL(verify.url);
  } catch {
    return {
      attempted: false,
      url: verify.url,
      note: `verify.url unparseable (${verify.url})`,
    };
  }
  if (!(url.protocol === "http:" || url.protocol === "https:")) {
    return { attempted: false, url: verify.url, note: `verify.url protocol ${url.protocol}` };
  }

  let method = verify.method.toUpperCase();
  let body = method === "GET" || method === "HEAD" ? undefined : verify.body;
  let headers: Headers;
  try {
    headers = new Headers(verify.headers);
  } catch (error) {
    return {
      attempted: false,
      url: verify.url,
      note: `verify.headers invalid: ${(error as Error).message}`,
    };
  }
  const signal = AbortSignal.timeout(opts?.timeoutMs ?? TIMEOUT_MS);
  const lockedHostname = normHost(url.hostname);
  const fetchImpl = opts?.fetchImpl ?? harnessFetchForTest;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const localName =
      url.hostname.toLowerCase() === "localhost" ||
      url.hostname.toLowerCase().endsWith(".localhost");
    if (!opts?.allowPrivate && localName) {
      return {
        attempted: false,
        url: url.toString(),
        note: `${url.hostname} is a private/internal host; operator authorization is required for harness replay`,
      };
    }
    let addresses: ResolvedAddress[] = [];
    if (!fetchImpl) {
      try {
        addresses = await resolveHost(url.hostname);
      } catch (error) {
        return {
          attempted: true,
          url: url.toString(),
          note: `request errored (DNS): ${(error as Error).message}`,
        };
      }
      if (addresses.length === 0) {
        return {
          attempted: true,
          url: url.toString(),
          note: `request errored (DNS): ${url.hostname} resolved to no addresses`,
        };
      }
    } else {
      const host = normHost(url.hostname);
      if (isIP(host)) {
        addresses = [{ address: host, family: isIP(host) as 4 | 6 }];
      }
    }
    if (!opts?.allowPrivate && addresses.some((address) => !isPublicIpAddress(address.address))) {
      return {
        attempted: false,
        url: url.toString(),
        note: `${url.hostname} is a private/internal host; operator authorization is required for harness replay`,
      };
    }

    let closeFetched: (() => Promise<void>) | undefined;
    try {
      const requestInit: RequestInit = {
        method,
        headers,
        body,
        redirect: "manual",
        signal,
      };
      const fetched = fetchImpl
        ? { response: await fetchImpl(url, requestInit), close: async () => undefined }
        : await fetchPinned(url, requestInit, addresses);
      closeFetched = fetched.close;
      const res = fetched.response;
      const location = res.headers.get("location");
      if (location && [301, 302, 303, 307, 308].includes(res.status)) {
        if (redirects === MAX_REDIRECTS) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: url.toString(),
            note: `redirect limit exceeded (${MAX_REDIRECTS})`,
          };
        }
        const next = new URL(location, url);
        if (!(next.protocol === "http:" || next.protocol === "https:")) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: url.toString(),
            note: `redirected to disallowed protocol ${next.protocol}`,
          };
        }
        if (normHost(next.hostname) !== lockedHostname) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: url.toString(),
            note: `redirect left the bound host (${url.hostname} -> ${next.hostname})`,
          };
        }
        if (next.origin !== url.origin) {
          for (const name of ["authorization", "cookie", "proxy-authorization"]) {
            headers.delete(name);
          }
        }
        if (
          res.status === 303 ||
          ((res.status === 301 || res.status === 302) && method === "POST")
        ) {
          method = "GET";
          body = undefined;
          headers.delete("content-length");
          headers.delete("content-type");
        }
        await res.body?.cancel().catch(() => undefined);
        await fetched.close().catch(() => undefined);
        closeFetched = undefined;
        url = next;
        continue;
      }

      const observed = await readBodyCapped(res);
      await fetched.close().catch(() => undefined);
      closeFetched = undefined;
      if (observed.truncated) {
        return {
          attempted: true,
          status: res.status,
          url: url.toString(),
          bodySha256: observed.sha256,
          bodyBytes: observed.bytes,
          note: "response body exceeded the 2 MiB capture limit; matcher result is inconclusive",
        };
      }
      const failures = await evaluateExpect(expect, res.status, observed.text);
      return {
        attempted: true,
        matched: failures.length === 0,
        status: res.status,
        url: url.toString(),
        bodySha256: observed.sha256,
        bodyBytes: observed.bytes,
        note:
          failures.length === 0
            ? `status ${res.status}, all predicates matched`
            : failures.join("; "),
      };
    } catch (e) {
      await closeFetched?.().catch(() => undefined);
      return {
        attempted: true,
        url: url.toString(),
        note: `request errored (DNS/TLS/timeout): ${(e as Error).message}`,
      };
    }
  }

  return { attempted: true, url: url.toString(), note: "unreachable redirect state" };
}

/**
 * Two requests are "the same" when method, URL, header set, and body all match.
 * An intra-target differential whose attack and baseline are identical proves
 * nothing — the discriminating variable must actually differ.
 */
export function sameRequest(
  a: { method: string; url: string; headers?: Record<string, string>; body?: string },
  b: { method: string; url: string; headers?: Record<string, string>; body?: string },
): boolean {
  const norm = (h?: Record<string, string>) =>
    JSON.stringify(
      Object.entries(h ?? {})
        .map(([k, v]) => [k.toLowerCase(), v] as const)
        .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)),
    );
  return (
    a.method.toUpperCase() === b.method.toUpperCase() &&
    a.url === b.url &&
    (a.body ?? "") === (b.body ?? "") &&
    norm(a.headers) === norm(b.headers)
  );
}

/**
 * Combine the two observations into the differential verdict. Shared by the
 * attack-vs-baseline replay: "target" is the attack request, "control" the
 * legitimate baseline request.
 */
function judgeDifferential(
  target: HarnessResponseObservation,
  control: HarnessResponseObservation,
  label: { kind: string; a: string; b: string },
): HarnessVerifyResult {
  const attempted = target.attempted && control.attempted;
  const conclusive = target.matched !== undefined && control.matched !== undefined;
  const differential = conclusive
    ? target.matched === true
      ? control.matched === true
        ? "both"
        : "target_only"
      : control.matched === true
        ? "control_only"
        : "neither"
    : undefined;
  const pass = attempted && conclusive && differential === "target_only";
  return {
    attempted,
    pass,
    status: target.status,
    target,
    control,
    differential,
    note:
      `harness ${label.kind} ${differential ?? "inconclusive"}: ${label.a} (${target.note}); ` +
      `${label.b} (${control.note})`,
  };
}

/**
 * Same-host differential (intra-target). The discriminating variable is the
 * attacker's identity or a request parameter, not the host — the sound
 * baseline is a legitimate request to the SAME target.
 * The harness sends the attack request and the model-declared `evidence.baseline`
 * request to the case target, applies the attack's `verify.expect` predicates to
 * BOTH responses, and passes only when the proof appears on the attack response
 * and is absent from the baseline (`target_only`, where "target" = attack and
 * "control" = baseline). The baseline is bound to the case target so it cannot
 * be redirected to a weaker origin, and it must differ from the attack request.
 */
export async function replayIntraTarget(
  evidence: PoCEvidence,
  caseTarget: string,
  opts?: ReplayOptions,
): Promise<HarnessVerifyResult> {
  const baseline = evidence.baseline;
  if (!baseline) {
    return {
      attempted: false,
      pass: false,
      note: "intra-target differential requires evidence.baseline (a legitimate same-host request)",
    };
  }
  const attackBinding = verifyUrlBindingError(evidence.verify.url, caseTarget);
  if (attackBinding) {
    return { attempted: false, pass: false, note: `attack binding failed: ${attackBinding}` };
  }
  const baselineBinding = verifyUrlBindingError(baseline.url, caseTarget);
  if (baselineBinding) {
    return { attempted: false, pass: false, note: `baseline binding failed: ${baselineBinding}` };
  }
  if (sameRequest(evidence.verify, baseline)) {
    return {
      attempted: false,
      pass: false,
      note: "attack and baseline requests are identical — an intra-target differential must vary identity or a parameter",
    };
  }

  const attack = await replayRequest(evidence.verify, evidence.verify.expect, opts);
  // The baseline carries the attack's predicates: the proof must be ABSENT here.
  const base = await replayRequest(
    {
      ...evidence.verify,
      method: baseline.method,
      url: baseline.url,
      headers: baseline.headers,
      body: baseline.body,
    },
    evidence.verify.expect,
    opts,
  );

  return judgeDifferential(attack, base, {
    kind: "intra-target",
    a: "attack",
    b: "baseline",
  });
}
