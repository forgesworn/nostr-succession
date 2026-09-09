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
const d = decide(m, precommit, { precommitFirstSeen, migrationFirstSeen, identityRoot, bondWithSuccessor })
// d.path is 'automatic' or 'manual', d.because says why, and the words shown come from that
```

`decide` is never automatic on consent alone. It follows when the
pre-commitment demonstrably predates the migration (seven days by this
client's own first-seen, or an OpenTimestamps attestation), when the
successor shares a root that was bound to the identity seven days earlier
(the master on the identity's own published linkage proof),
when a bond ceremony with the successor succeeded, or when someone the user
trusts attested to the pair. A second pre-commitment or a second migration
makes everything manual.

Vectors in `vectors/succession.json` are the draft's known-answer file:
ten cases including a hijack by a holder of the migration key, a
future-dated migration, a fresh root binding and a contested identity.

## Licence

MIT. ForgeSworn.
