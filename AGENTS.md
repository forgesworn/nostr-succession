# AGENTS.md

## Project

nostr-succession is a TypeScript library implementing Nostr key succession:
a pre-committed migration key (kind 1360) and a consenting successor (kind
1361), plus a `decide` function a client applies to tell a genuine handover
from a hijack. Published to npm as `nostr-succession`.

## Commands

- Install: `npm ci`
- Build: `npm run build` (tsc, `tsconfig.build.json`, emits to `dist/`)
- Test: `npm test` (runs `vitest run` over `test/**/*.test.ts`, then
  `node verifier/verify.mjs`, a second implementation checked against the
  same vectors)
- Typecheck: `npm run typecheck` (`tsc --noEmit`)

CI (`.github/workflows/ci.yml`) runs typecheck, build and test on Node 22
and 24.

## Layout

- `src/index.ts`: the entire library (single file).
- `test/`: `succession.test.ts` and `fuzz.test.ts`, run by vitest.
- `vectors/succession.json`: the known-answer file, fourteen cases.
- `verifier/verify.mjs`: an independent implementation of the same rules,
  written from the draft's text, kept apart from `src/index.ts`; `npm test`
  requires it to agree with the library on every vector.

## Conventions

- Single-file library; no framework, no runtime dependencies beyond
  `@noble/curves`, `@noble/hashes`, `nostr-tools` and `nsec-tree`.
- `nostr-tools` is pinned to `2.23.9` via both `dependencies` and
  `overrides`: later versions add an idle-connection ping that closes
  subscriptions early.
- Functions that accept a caller-supplied `NostrEvent` copy it first
  (`bare`) and read only the copy, so a cached verification or an altered
  field on the caller's object cannot speak for the checked one.
- Timestamps are Unix seconds; `decide` and `consentMessage` refuse a
  value that looks like milliseconds.

## Pitfalls

- `decide` is never automatic on consent alone: it also needs seven days'
  evidence, a bond ceremony, a trusted attestation, or a shared root bound
  to the identity seven days earlier.
- The migration key must be derived from the identity's root and never
  stored; the library cannot check this, so callers are responsible for it.
- A root binding to the identity's own key or the migration key is
  refused: either key's holder could sign that proof, so it protects
  nothing.

## Verifying a change

Run `npm run typecheck`, `npm run build` and `npm test`. `npm test` fails
if `src/index.ts` and `verifier/verify.mjs` disagree on any vector in
`vectors/succession.json`; a rule change normally needs both updated.
