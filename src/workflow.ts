/**
 * Recon workflow injected once per session into the agent's system prompt.
 *
 * Scope: RECON only — attack-surface mapping and intel collection, fanned out
 * to recon subagents. Everything after recon (hunting the leads, PoC work, the
 * confirmation gate, reporting) is the main agent's own inline job through the
 * casefile tools; this file does NOT orchestrate a hunt/trace/validate pipeline.
 */

/**
 * Subagent-dispatch conventions per host. Pi (pi-subagents extension) dispatches
 * through `subagent({ workflowScript: runs.run(...) })`; OMP (fork, @oh-my-pi)
 * dispatches through its native `task` tool with a tasks array. The recon body
 * is identical — only the launch mechanics differ.
 */
type DispatchSpec = {
  /** How to launch a recon subagent on this host. */
  reference: string;
  /** The parallel recon fan-out line. */
  fanout: string;
  /** Retry discipline when a recon subagent fails. */
  crash: string;
};

const PI_DISPATCH: DispatchSpec = {
  reference:
    "**Subagent dispatch:** each recon launch uses `subagent({ workflowScript: \"return runs.run('recon-<area>-1', { agent: 'recon', task: '...' })\", context: 'fresh', async: true })`. Fan out a round with ONE workflowScript using `return runs.all([...])`, at most 3 recon tasks. Stable keys include run, recon area, and attempt.",
  fanout:
    "Launch ONE async workflowScript whose `runs.all([...])` dispatches at most 3 recon subagents, one per intel area (surface map, client-side / JS mining, passive intel + fingerprint/CVE).",
  crash:
    "**Subagent failure handling:** a crash, timeout, hung run, or unparseable output is a RETRY, not a result. Re-launch the same recon area with a new attempt key and a stronger model; on repeat failure, record `blocked: recon <area> failed` on the recon case and continue with the areas that returned.",
};

const OMP_DISPATCH: DispatchSpec = {
  reference:
    "**Subagent dispatch (OMP):** each recon launch uses `task({ context: 'fresh', tasks: [{ name: 'recon-<area>-1', agent: 'recon', task: '...' }] })`. Fan out a round with ONE `task` call whose `tasks` array carries at most 3 recon tasks. Stable names include run, recon area, and attempt. Results deliver automatically; steer with `hub`.",
  fanout:
    "Launch ONE async `task` call whose `tasks` array dispatches at most 3 recon subagents, one per intel area (surface map, client-side / JS mining, passive intel + fingerprint/CVE).",
  crash:
    "**Subagent failure handling:** a failed or hung task, timeout, or unparseable output is a RETRY, not a result. Re-dispatch the same recon area with a new attempt name and a stronger model; on repeat failure, record `blocked: recon <area> failed` on the recon case and continue with the areas that returned.",
};

/** Build the recon workflow for a host's dispatch convention. */
function buildReconWorkflow(d: DispatchSpec): string {
  return `
# Recon Workflow (Attack-Surface Mapping & Intel Collection)

Think like a real external attacker, not a code reviewer. This workflow covers ONE job: turn a target into a rich attack-surface map and intel picture that later hunting can act on. Recon fans out to subagents; hunting the leads, validation, the PoC confirmation gate, and reporting are yours to run afterward, inline, through the casefile tools.

## Tool Reference

**Casefile (state tracking):** CaseAdd, CaseUpdate, CaseGet, CaseList, CaseSearch, CaseLink, CaseUnlink, CaseContext, EvidenceAdd

**Scratchpad (recon artifacts):** ScratchpadInit, ScratchpadWrite, ScratchpadRead, ScratchpadResume, ScratchpadCheckpoint, ScratchpadPhaseDone, ScratchpadClear

**Web lookup / intel:** web_search, web_fetch, exploit_search, context7, deepwiki, http_request

${d.reference}

**Delegation boundary:** recon/intel gathering runs as subagents (the \`recon\` agent). You, the main coordinator, own scoping, consolidating recon results into the attack-surface map, filing hypotheses, and every state decision. Everything past recon is your inline job — there is no hunt/trace/validate subagent pipeline.

## Recon — what to gather

Live web target, CTF, or bounty box: gather high-signal intel and turn it into the map hunting will use — entry-point inventory (URL, method, params, auth state), attacker model, auth/role boundaries, trust boundaries, likely vuln-class batches, and known gaps. Aim for the richest useful map, not the largest raw pile.

- **Surface mapping** — routes, endpoints, parameters, auth models; \`robots.txt\`, \`sitemap.xml\`, \`/.well-known/\`, OpenAPI/Swagger, GraphQL introspection.
- **Client-side mining** — pull JS bundles / source maps for SPA or API-heavy apps; bank discovered endpoints, params, and secrets as leads.
- **Passive intel** — public metadata, schemas, passive archives, exposed backup/VCS checks, when scope allows and the result can change target, auth, or class selection.
- **Fingerprint for decisions** — stack + version confidence drives \`exploit_search\` and class selection; record uncertainty instead of guessing.

## Dispatch discipline (recon fans out; consolidation is yours)

Scope the target first, then fan recon out ONCE per round: ${d.fanout} Let the batched call return ALL results, then consolidate them yourself. Do NOT scatter one subagent per URL — group by intel area. Re-enter recon only when a gap actually blocks a decision.

${d.crash}

## Bank the results

- Write the entry-point map, selected class batches, and open gaps to the scratchpad: \`ScratchpadWrite(run_id, "recon", "entry-points.md", ...)\`.
- File high-value leaks (source map, origin IP, exposed schema, leaked creds) as \`EvidenceAdd role=observation\`.
- Turn each credible lead into a hypothesis: \`CaseAdd\` it with its \`disproveIf\` (what would rule it out). Every observed anomaly — an unexpected 200, an error leak, a timing gap, an exposed endpoint — is a HYPOTHESIS, not just a note.

## Hand-off

Recon ends when more collection is unlikely to change the hunt plan. Hand off to yourself: the filed HYPOTHESIS cases are the hunt queue. Investigate them inline through the casefile. Recon does not confirm findings — the PoC confirmation gate (PromoteFinding → ConfirmFinding) is unchanged and stays the main agent's job.
`.trim();
}

/** Recon workflow for Pi Agent (pi-subagents dispatch). */
export const STATIC_RECON_WORKFLOW = buildReconWorkflow(PI_DISPATCH);

/** Recon workflow for OMP (fork of Pi; native `task` dispatch). */
export const STATIC_RECON_WORKFLOW_OMP = buildReconWorkflow(OMP_DISPATCH);
