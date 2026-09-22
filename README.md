<div align="center">

# pi-casefile

**Security case ledger for the [Pi agent](https://github.com/earendil-works/pi-coding-agent)** — evidence tracking with machine-verified PoC gates.

[![npm](https://img.shields.io/npm/v/@xaccefy/pi-casefile?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@xaccefy/pi-casefile)
[![License: MIT](https://img.shields.io/github/license/xaccefy/pi-casefile?style=flat-square&color=blueviolet)](LICENSE)

</div>

## What it is

A structured ledger for offensive-security work — bug bounties, CTFs, audits — built around one idea: **an agent's claim is not evidence until the machine replays it**.

Cases move `hypothesis → investigating → confirmed → reported`. Promotion between phases is gated:

- **Zero exit is necessary but never proof** — direct-response findings require nonce-bound body evidence plus a DNS-pinned, conclusive `target_only` attack-vs-baseline replay against the case target (recorded at promote; the bundle's baseline binding and differential are re-validated at confirm)
- **Differential confirmation** — the attack request must satisfy the claimed predicate while a legitimate same-host baseline request must not, so "it worked" means *the discriminator fired*, not "the agent said so"
- Only the main agent makes the semantic decision and commits phase transitions

Designed for **human + AI workflows**: every confirmed finding carries a reproducible evidence trail a human can audit.

## Tools

| Tool | Purpose |
|---|---|
| `CaseAdd` / `CaseList` / `CaseSearch` / `CaseGet` / `CaseUpdate` / `CaseLink` / `CaseUnlink` / `CaseContext` | case lifecycle, search, links, and report context |
| `EvidenceAdd` | attach raw evidence to a case |
| `CoverageAdd` | record tested (asset × class) cells — found or clean |
| `PromoteFinding` → harness replay → `ConfirmFinding` | gated finding pipeline |
| `ScratchpadWrite` / `ScratchpadRead` / `ScratchpadClear` | working notes, resume-safe (no pipeline orchestration) |

## Install

```bash
pi install npm:@xaccefy/pi-casefile
```

Peer-depends on a Pi-compatible agent host (`@earendil-works/pi-coding-agent`, `pi-ai`, `pi-tui`, `typebox`). Runtime deps: `@xaccefy/pi-shared`, `undici`.

## Development

```bash
bun install
bun test --isolate
bun run typecheck
```

## License

MIT
