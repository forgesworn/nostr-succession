import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils.js'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { fromNsec, derive } from 'nsec-tree/core'
import { createFullProof } from 'nsec-tree/proof'
import { finalizeEvent } from 'nostr-tools/pure'
import { bytesToHex } from '@noble/hashes/utils.js'
import { schnorr } from '@noble/curves/secp256k1.js'
import { buildPrecommit, buildMigration, validateMigration, decide, predecessorKeys, consentMessage, KIND_MIGRATION, SEVEN_DAYS } from '../src/index.js'

/** A migration built without the library's own refusals, to prove the verifier refuses it too. */
function buildMigrationUnchecked(precommit: any, migrationPriv: Uint8Array, successorPriv: Uint8Array, createdAt: number) {
  const successorPub = getPublicKey(successorPriv)
  const sig = bytesToHex(schnorr.sign(consentMessage(precommit.pubkey, getPublicKey(migrationPriv), successorPub, createdAt), successorPriv))
  return finalizeEvent({ kind: KIND_MIGRATION, created_at: createdAt, tags: [['p', successorPub], ['e', precommit.id], ['successor-sig', sig]], content: '' }, migrationPriv)
}

const v = JSON.parse(readFileSync(new URL('../vectors/succession.json', import.meta.url), 'utf8'))

describe('known-answer vectors from the draft', () => {
  for (const c of v.cases) {
    it(c.name, () => {
      const r = validateMigration(c.event, v.precommit)
      expect(r.valid).toBe(c.expect.valid)
      if (!c.expect.valid) return
      const d = decide(c.event, v.precommit, {
        precommitFirstSeen: c.firstSeen360,
        migrationFirstSeen: c.firstSeen361 ?? c.event.created_at,
        precommitAttestedBefore: c.attestedBefore,
        identityRoot: { masterPubkey: v.testOnlyKeys.masterPubkey, firstSeen: c.rootBoundAt ?? v.rootBoundAt },
        contested: c.contested,
        secondMigration: c.secondMigration,
      })
      expect(d.path).toBe(c.expect.path)
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
    expect(decide(m, pre, { precommitFirstSeen: T0, migrationFirstSeen: T1 }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, identityRoot: { masterPubkey: master, firstSeen: T0 } }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, identityRoot: { masterPubkey: master, firstSeen: T1 - 60 } }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, identityRoot: { masterPubkey: 'ab'.repeat(32), firstSeen: T0 } }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, bondedSuccessor: getPublicKey(successor.privateKey) }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, bondedSuccessor: 'cd'.repeat(32) }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, attestedSuccessor: getPublicKey(successor.privateKey) }).path).toBe('automatic')
    expect(decide(m, pre, { precommitFirstSeen: T0, migrationFirstSeen: T1, contested: true }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T0, migrationFirstSeen: T1, secondMigration: true }).path).toBe('manual')
  })
  it('an OpenTimestamps bound needs the seven-day gap too', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 })
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, precommitAttestedBefore: T1 - 3600 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, precommitAttestedBefore: T0 }).path).toBe('automatic')
  })
  it('a linkage to a sibling that is not a successor key is not enough', () => {
    const sibling = derive(root, 'bot', 3)
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: sibling.privateKey, linkage: createFullProof(root, sibling), createdAt: T1 })
    expect(decide(m, pre, { precommitFirstSeen: T1 - 60, migrationFirstSeen: T1, identityRoot: { masterPubkey: master, firstSeen: T0 } }).path).toBe('manual')
  })
  it('the identity may not be its own migration key, and the successor must be a new key', () => {
    expect(() => buildPrecommit(identity.privateKey, getPublicKey(identity.privateKey), T0)).toThrow(/identity itself/)
    const selfPre = { ...pre, tags: [['p', getPublicKey(identity.privateKey)]] }
    const forged = buildMigrationUnchecked(selfPre, identity.privateKey, successor.privateKey, T1)
    expect(validateMigration(forged, selfPre).valid).toBe(false)
    expect(() => buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: migration.privateKey, createdAt: T1 })).toThrow(/new key/)
  })
  it('duplicate tags, upper-case hex and bad times are refused', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 })
    // Re-sign with the extra tag so the signature is real and the duplicate is what fails.
    const dup = finalizeEvent({ kind: m.kind, created_at: m.created_at, content: m.content, tags: [...m.tags, ['p', getPublicKey(generateSecretKey())]] }, migration.privateKey)
    expect(validateMigration(dup, pre)).toMatchObject({ valid: false, reason: 'duplicate p tag' })
    const upper = { ...m, tags: m.tags.map((t) => (t[0] === 'p' ? ['p', t[1]!.toUpperCase()] : t)) }
    expect(validateMigration(upper, pre).valid).toBe(false)
    expect(() => consentMessage('00'.repeat(32), '00'.repeat(32), '00'.repeat(32), -1)).toThrow(RangeError)
    expect(validateMigration(null as any, pre).valid).toBe(false)
    expect(decide(m, pre, null).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: 0, migrationFirstSeen: T1 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T0, migrationFirstSeen: 0 }).path).toBe('manual')
  })
  it('a tampered event fails its signature even when it was built in this process', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 })
    expect(validateMigration({ ...m, content: 'tampered' }, pre)).toMatchObject({ valid: false, reason: 'not a signed kind 1361' })
  })
  it('a future-dated migration does not become automatic on its own date', () => {
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 + 8 * 24 * 3600 })
    expect(decide(m, pre, { precommitFirstSeen: T1 - 3600, migrationFirstSeen: T1 }).path).toBe('manual')
    expect(decide(m, pre, { precommitFirstSeen: T1 - 3600, migrationFirstSeen: T1 + 8 * 24 * 3600 }).path).toBe('automatic')
  })
  it('the vectors file has a second, different pre-commitment that nothing follows', () => {
    const pre2 = v.precommit2
    expect(pre2.pubkey).toBe(pre.pubkey)
    expect(pre2.id).not.toBe(pre.id)
  })
  it('the wrong migration key cannot build, and a stranger cannot consent', () => {
    expect(() => buildMigration({ precommit: pre, migrationPrivateKey: generateSecretKey(), successorPrivateKey: successor.privateKey })).toThrow()
    const m = buildMigration({ precommit: pre, migrationPrivateKey: migration.privateKey, successorPrivateKey: successor.privateKey, createdAt: T1 })
    const forged = JSON.parse(JSON.stringify({ ...m, tags: m.tags.map((t) => (t[0] === 'p' ? ['p', getPublicKey(generateSecretKey())] : t)) }))
    expect(validateMigration(forged, pre)).toMatchObject({ valid: false, reason: 'not a signed kind 1361' })
  })
  it('a pre-commitment with no key means never, and predecessor keys parse', () => {
    const never = buildPrecommit(identity.privateKey, null, T0)
    expect(never.tags.length).toBe(0)
    expect(predecessorKeys(JSON.stringify({ name: 'Ada', predecessor_keys: [getPublicKey(identity.privateKey), 'nope'] }))).toEqual([getPublicKey(identity.privateKey)])
    expect(predecessorKeys('not json')).toEqual([])
    void SEVEN_DAYS
  })
})
