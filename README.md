<div align="center">

# pi-casefile

**Security case ledger for the [Pi agent](https://github.com/earendil-works/pi-coding-agent)** — evidence tracking with machine-verified PoC gates.

[![npm](https://img.shields.io/npm/v/@xaccefy/pi-casefile?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@xaccefy/pi-casefile)
[![License: MIT](https://img.shields.io/github/license/xaccefy/pi-casefile?style=flat-square&color=blueviolet)](LICENSE)

</div>

## What it is

A structured ledger for offensive-security work — bug bounties, CTFs, audits — built around one idea: **an agent's claim is not evidence until the machine replays it**.

Cases move `hypothesis → investigating → confirmed → reported`. Promotion between phases is gated:

- **Zero exit is necessary but never proof** — direct-response findings require nonce-bound body evidence plus a DNS-pinned, conclusive `target_only` replay against an operator-approved control
- **Differential confirmation** — `inter_host` (attack vs control host) or `intra_target` (attack vs baseline request) so "it worked" means *the discriminator fired*, not "the agent said so"
- **Blind/OOB classes** confirm through an operator-run oracle with per-run tokens and source-separation attestation
- Only the main agent makes the semantic decision and commits phase transitions

Designed for **human + AI workflows**: every confirmed finding carries a reproducible evidence trail a human can audit.

## Tools

| Tool | Purpose |
|---|---|
| `CaseAdd` / `CaseList` / `CaseUpdate` / `CaseContext` | case lifecycle and context retrieval |
| `EvidenceAdd` | attach raw evidence to a case |
| `PromoteFinding` → harness replay → `ConfirmFinding` | gated finding pipeline |
| Scratchpad | phase-scoped working notes, resume-safe |

## Install

```bash
pi install npm:@xaccefy/pi-casefile
```

Peer-depends on a Pi-compatible agent host (`@earendil-works/pi-coding-agent`, `pi-ai`, `pi-tui`, `typebox`). Runtime deps: `@xaccefy/pi-shared`, `undici`.

## Development

```bash
bun install
bun test --isolate   # 302 tests
bun run typecheck
```

The JSON contracts in [`schemas/`](schemas/) are the agent-facing mirror of the `SPECS` table in `src/pipeline-submit.ts`; a drift-guard test fails if they diverge.

## License

MIT
