# nostr-succession

**A key that can change, with a commitment made before it had to.**

Two regular kinds. `1360` is a pre-commitment: the identity names one
migration key, in advance and in public, so a thief who steals today's key
cannot also invent the move. `1361` is the migration: the migration key
names a successor, the successor signs its consent, and an optional linkage
proof says the two keys share a root.

The migration key is derived from the root (nsec-tree purpose `migration`,
index 0) and never stored. The identity is a child of that root, never the
root itself, or the commitment protects nothing.

```ts
import { buildPrecommit, buildMigration, validateMigration, decide } from 'nostr-succession'

// Day one: commit, and never think about it again.
publish(buildPrecommit(identityPrivateKey, migrationPub))

// The day it must move.
const m = buildMigration({ precommit, migrationPrivateKey, successorPrivateKey, linkage })

// A client deciding whether to follow on its own.
const v = validateMigration(m, precommit)          // consent verified, or a reason
const d = decide(m, precommit, { precommitFirstSeen, migrationFirstSeen, identityRoot, bondedSuccessor })
// d.path is 'automatic' or 'manual', d.because says why, and the words shown come from that
```

`decide` is never automatic on consent alone. It follows when the
pre-commitment demonstrably predates the migration by seven days, measured
against the earlier of the migration's `created_at` and this client's own
first sight of it. "Demonstrably" means this client's own first-seen of the
pre-commitment, or an OpenTimestamps attestation, and the seven-day gap
applies to both: an attestation an hour old proves existence, not
precedence. It also follows when the successor shares a root that was bound
to the identity seven days earlier (the master on the identity's own first
published linkage proof, kept for ever and never replaced), when a bond
ceremony confirmed the named successor, or when someone the user trusts
attested to the named successor. A second pre-commitment or a second
migration by the same key makes everything manual, including the first.

`validateMigration` refuses more than it accepts: the migration key must
differ from the identity, the successor must be a key that is neither, every
tag must appear exactly once, hex must be lower case, `created_at` must be a
safe non-negative integer, and the signature is always re-verified rather
than trusted from a cache.

Vectors in `vectors/succession.json` are the draft's known-answer file:
fourteen cases including a hijack by a holder of the migration key, a second
migration by the same key, an OpenTimestamps attestation both old and fresh,
a future-dated migration, a fresh root binding and a contested identity.
`vectors/verify-succession.mjs` in the profile repo is a second, independent
implementation of the same rules that must agree on every case.

## Licence

MIT. ForgeSworn.
