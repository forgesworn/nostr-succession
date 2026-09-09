import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils.js'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { fromNsec, derive } from 'nsec-tree/core'
import { createFullProof } from 'nsec-tree/proof'
import { buildPrecommit, buildMigration, validateMigration, decide, predecessorKeys, SEVEN_DAYS } from '../src/index.js'

const v = JSON.parse(readFileSync(new URL('../vectors/succession.json', import.meta.url), 'utf8'))

describe('known-answer vectors from the draft', () => {
  for (const c of v.cases) {
    it(c.name, () => {
      const r = validateMigration(c.event, v.precommit)
      const second = c.competesWith !== undefined
      expect(r.valid && !second).toBe(c.expect.valid)
      if (!c.expect.valid) return
      const d = decide(c.event, v.precommit, {
        precommitFirstSeen: c.firstSeen360,
        migrationFirstSeen: c.firstSeen361,
        identityRoot: { masterPubkey: v.testOnlyKeys.masterPubkey, firstSeen: c.rootBoundAt ?? v.rootBoundAt },
        contested: c.contested,
      })
      expect(c.expect.path.startsWith(d.path)).toBe(true)
    })
  }
})

describe('building', () => {
  const root = fromNsec(hexToBytes('4873374aacd9fbbdf073a29078b6cf9f27c137107530c521458d5d83118ae733'))
  const identity = derive(root, 'social', 0), migration = derive(root, 'migration', 0), successor = derive(root, 'successor', 0)
  const T0 = 1_793_577_600, T1 = T0 + 30 * 24 * 3600
  const pre = buildPrecommit(identity.privateKey, getPublicKey(migration.privateKey), T0)
  // What a client binds to the identity: the master on the identity's own linkage proof.
  const master = createFullProof(root, identity).masterPubkey
  it('a built migration validates, and follows automatically with an old pre-commitment or a bound root', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, linkage: createFullProof(root, successor), createdAt: T1 })
    expect(validateMigration(m, pre)).toMatchObject({ valid: true, successor: getPublicKey(successor.privateKey) })
    expect(decide(m, pre, { precommitFirstSeen: T0 }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, identityRoot: { masterPubkey: master, firstSeen: T0 } }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, identityRoot: { masterPubkey: master, firstSeen: T1 - 60 } }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, bondWithSuccessor: true }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T0, contested: true }).path).toBe('manual')
  })
  it('a future-dated migration does not become automatic on its own date', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 + 8 * 24 * 3600 })
    expect(decide(m, pre, { precommitFirstSeen: T1 - 3600, migrationFirstSeen: T1 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 3600, migrationFirstSeen: T1 + 8 * 24 * 3600 }).path).toBe('automatic')
  })
  it('the wrong migration key cannot build, and a stranger cannot consent', () => {
    expect(() => buildMigration({ precommit: pre, migrationPrivateKey: generateSecretKey(), successorPrivateKey: successor.privateKey })).toThrow()
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 })
    const forged = { ...m, tags: m.tags.map((t) => (t[0] === 'p' ? ['p', getPublicKey(generateSecretKey())] : t)) }
    expect(validateMigration(forged, pre).valid).toBe(false)
  })
  it('a pre-commitment with no key means never, and predecessor keys parse', () => {
    const never = buildPrecommit(identity.privateKey, null, T0)
    expect(never.tags.length).toBe(0)
    expect(predecessorKeys(JSON.stringify({ name: 'Ada', predecessor_keys: [getPublicKey(identity.privateKey), 'nope'] }))).toEqual([getPublicKey(identity.privateKey)])
    expect(predecessorKeys('not json')).toEqual([])
    void SEVEN_DAYS
  })
})
