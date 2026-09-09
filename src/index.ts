import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent } from 'nostr-tools/pure'
import { verifyProof } from 'nsec-tree/proof'
import type { LinkageProof } from 'nsec-tree'

export const KIND_PRECOMMIT = 1360
export const KIND_MIGRATION = 1361
export const DOMAIN = 'nostr-succession/v1'
/** The pre-commitment, or the identity's root binding, must be this much older than the migration for the automatic path. */
export const SEVEN_DAYS = 7 * 24 * 3600

const tag = (e: NostrEvent, n: string) => e.tags.find((t) => t[0] === n)?.[1]

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, BigInt(n))
  return out
}

/** msg = sha256("nostr-succession/v1" || 0x00 || identity || migration || successor || u64be(created_at)) */
export function consentMessage(identityPub: string, migrationPub: string, successorPub: string, createdAt: number): Uint8Array {
  return sha256(concatBytes(utf8ToBytes(DOMAIN), new Uint8Array([0]), hexToBytes(identityPub), hexToBytes(migrationPub), hexToBytes(successorPub), u64be(createdAt)))
}

/** §1: the identity commits to one migration key, or to none. */
export function buildPrecommit(identityPrivateKey: Uint8Array, migrationPub: string | null, createdAt = Math.floor(Date.now() / 1000)): NostrEvent {
  return finalizeEvent({ kind: KIND_PRECOMMIT, created_at: createdAt, tags: migrationPub ? [['p', migrationPub]] : [], content: '' }, identityPrivateKey)
}

export interface MigrationOptions {
  precommit: NostrEvent
  migrationPrivateKey: Uint8Array
  successorPrivateKey: Uint8Array
  /** A full nsec-tree linkage proof whose child is the successor, if the keys share a root. */
  linkage?: LinkageProof
  relayHint?: string
  createdAt?: number
}

/**
 * §2: the migration key names the successor and the successor consents.
 * The consent is signed first, over the created_at the event will carry;
 * a signer that rewrites created_at invalidates it, so callers that sign
 * through NIP-46 must compare and re-sign.
 */
export function buildMigration(o: MigrationOptions): NostrEvent {
  const identityPub = o.precommit.pubkey
  const migrationPub = getPublicKey(o.migrationPrivateKey)
  if (tag(o.precommit, 'p') !== migrationPub) throw new Error('this migration key is not the one the pre-commitment names')
  const successorPub = getPublicKey(o.successorPrivateKey)
  const createdAt = o.createdAt ?? Math.floor(Date.now() / 1000)
  const consent = bytesToHex(schnorr.sign(consentMessage(identityPub, migrationPub, successorPub, createdAt), o.successorPrivateKey))
  const tags: string[][] = [
    ['p', successorPub],
    ['e', o.precommit.id, ...(o.relayHint ? [o.relayHint] : [])],
    ['successor-sig', consent],
  ]
  if (o.linkage) tags.push(['linkage', JSON.stringify(o.linkage)])
  return finalizeEvent({ kind: KIND_MIGRATION, created_at: createdAt, tags, content: '' }, o.migrationPrivateKey)
}

export type Validity = { valid: true; successor: string; identity: string } | { valid: false; reason: string }

/** §2: is this a well-formed migration with the successor's consent for this pre-commitment? */
export function validateMigration(migration: NostrEvent, precommit: NostrEvent): Validity {
  if (migration.kind !== KIND_MIGRATION || !verifyEvent(migration)) return { valid: false, reason: 'not a signed kind 1361' }
  if (precommit.kind !== KIND_PRECOMMIT || !verifyEvent(precommit)) return { valid: false, reason: 'pre-commitment is not a signed kind 1360' }
  if (tag(precommit, 'p') !== migration.pubkey) return { valid: false, reason: 'not signed by the committed migration key' }
  if (tag(migration, 'e') !== precommit.id) return { valid: false, reason: 'e tag does not name the pre-commitment' }
  const successor = tag(migration, 'p'), sig = tag(migration, 'successor-sig')
  if (!successor || !sig) return { valid: false, reason: 'missing p or successor-sig' }
  let ok = false
  try { ok = schnorr.verify(hexToBytes(sig), consentMessage(precommit.pubkey, migration.pubkey, successor, migration.created_at), hexToBytes(successor)) } catch { ok = false }
  if (!ok) return { valid: false, reason: 'successor-sig does not verify' }
  return { valid: true, successor, identity: precommit.pubkey }
}

export interface Evidence {
  /** When this client first saw the pre-commitment. */
  precommitFirstSeen: number
  /** When this client first saw the migration; defaults to its created_at. */
  migrationFirstSeen?: number
  /** A kind 1040 OpenTimestamps attestation of the pre-commitment proves it older than this time. */
  precommitAttestedBefore?: number
  /** The root this client has bound to the identity, and when that binding was first seen. */
  identityRoot?: { masterPubkey: string; firstSeen: number }
  /** A fresh out-of-band bond ceremony with the successor succeeded. */
  bondWithSuccessor?: boolean
  /** Someone the user trusts attested to the pair. */
  trustedAttestation?: boolean
  /** A second, different pre-commitment exists for this identity. */
  contested?: boolean
  /** A second migration by the same migration key exists. */
  secondMigration?: boolean
}

export type Path = { path: 'automatic'; because: string } | { path: 'manual'; because: string }

/** §4: automatic or manual, from the evidence this client holds. Never automatic on consent alone. */
export function decide(migration: NostrEvent, precommit: NostrEvent, ev: Evidence): Path {
  const v = validateMigration(migration, precommit)
  if (!v.valid) return { path: 'manual', because: v.reason }
  if (ev.contested) return { path: 'manual', because: 'a second pre-commitment exists for this identity' }
  if (ev.secondMigration) return { path: 'manual', because: 'a second migration by this migration key exists' }
  const seen = Math.min(migration.created_at, ev.migrationFirstSeen ?? migration.created_at)
  if (ev.precommitAttestedBefore !== undefined && ev.precommitAttestedBefore < migration.created_at) return { path: 'automatic', because: 'the pre-commitment is attested older than the migration' }
  if (ev.precommitFirstSeen + SEVEN_DAYS <= seen) return { path: 'automatic', because: 'the pre-commitment was seen at least seven days before the migration' }
  const linkageRaw = tag(migration, 'linkage')
  if (linkageRaw && ev.identityRoot && ev.identityRoot.firstSeen + SEVEN_DAYS <= seen) {
    try {
      const proof = JSON.parse(linkageRaw) as LinkageProof
      if (verifyProof(proof) && proof.childPubkey === v.successor && proof.masterPubkey === ev.identityRoot.masterPubkey) return { path: 'automatic', because: 'the successor shares a root bound to the identity seven days ago' }
    } catch { /* a linkage the client cannot read is ignored */ }
  }
  if (ev.bondWithSuccessor) return { path: 'automatic', because: 'a bond ceremony with the successor succeeded' }
  if (ev.trustedAttestation) return { path: 'automatic', because: 'someone you trust attested to the pair' }
  return { path: 'manual', because: 'valid, with consent, and not enough evidence to follow on its own' }
}

/** §3: the successor's kind 0 declares its predecessors. */
export function predecessorKeys(profileContent: string): string[] {
  try {
    const p = JSON.parse(profileContent) as { predecessor_keys?: unknown }
    return Array.isArray(p.predecessor_keys) ? p.predecessor_keys.filter((k): k is string => typeof k === 'string' && /^[0-9a-f]{64}$/.test(k)) : []
  } catch { return [] }
}

/** REQ filters a client uses. */
export const filters = {
  precommit: (identity: string) => ({ kinds: [KIND_PRECOMMIT], authors: [identity] }),
  migrationBy: (migrationPub: string) => ({ kinds: [KIND_MIGRATION], authors: [migrationPub] }),
  migrationFor: (precommitId: string) => ({ kinds: [KIND_MIGRATION], '#e': [precommitId] }),
}
