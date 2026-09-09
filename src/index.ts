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

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/

/** The value of a tag that appears exactly once; undefined if absent or duplicated. */
function only(e: NostrEvent, n: string): string | undefined {
  const ts = e.tags.filter((t) => t[0] === n)
  return ts.length === 1 ? ts[0]![1] : undefined
}
function count(e: NostrEvent, n: string): number {
  return e.tags.filter((t) => t[0] === n).length
}
/** A structural copy, so a verification cached on the object by nostr-tools cannot speak for altered fields. */
function bare(e: NostrEvent): NostrEvent {
  return { kind: e.kind, pubkey: e.pubkey, created_at: e.created_at, tags: e.tags, content: e.content, id: e.id, sig: e.sig }
}
function isEvent(e: unknown): e is NostrEvent {
  return !!e && typeof e === 'object' && Array.isArray((e as NostrEvent).tags) && typeof (e as NostrEvent).pubkey === 'string'
}

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, BigInt(n))
  return out
}

/** msg = sha256("nostr-succession/v1" || 0x00 || identity || migration || successor || u64be(created_at)) */
export function consentMessage(identityPub: string, migrationPub: string, successorPub: string, createdAt: number): Uint8Array {
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) throw new RangeError('created_at out of range')
  return sha256(concatBytes(utf8ToBytes(DOMAIN), new Uint8Array([0]), hexToBytes(identityPub), hexToBytes(migrationPub), hexToBytes(successorPub), u64be(createdAt)))
}

/** §1: the identity commits to one migration key, or to none. */
export function buildPrecommit(identityPrivateKey: Uint8Array, migrationPub: string | null, createdAt = Math.floor(Date.now() / 1000)): NostrEvent {
  if (migrationPub !== null) {
    if (!HEX64.test(migrationPub)) throw new Error('migration key must be lowercase x-only hex')
    if (migrationPub === getPublicKey(identityPrivateKey)) throw new Error('the migration key must not be the identity itself')
  }
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
  if (only(o.precommit, 'p') !== migrationPub) throw new Error('this migration key is not the one the pre-commitment names')
  const successorPub = getPublicKey(o.successorPrivateKey)
  if (successorPub === identityPub || successorPub === migrationPub) throw new Error('the successor must be a new key')
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
  if (!isEvent(migration)) return { valid: false, reason: 'no migration' }
  if (!isEvent(precommit)) return { valid: false, reason: 'no pre-commitment' }
  if (migration.kind !== KIND_MIGRATION || !verifyEvent(bare(migration))) return { valid: false, reason: 'not a signed kind 1361' }
  if (precommit.kind !== KIND_PRECOMMIT || !verifyEvent(bare(precommit))) return { valid: false, reason: 'pre-commitment is not a signed kind 1360' }
  if (count(precommit, 'p') > 1) return { valid: false, reason: 'pre-commitment names more than one migration key' }
  for (const n of ['p', 'e', 'successor-sig', 'linkage']) if (count(migration, n) > 1) return { valid: false, reason: `duplicate ${n} tag` }
  if (only(precommit, 'p') !== migration.pubkey) return { valid: false, reason: 'not signed by the committed migration key' }
  if (migration.pubkey === precommit.pubkey) return { valid: false, reason: 'the migration key is the identity itself' }
  if (only(migration, 'e') !== precommit.id) return { valid: false, reason: 'e tag does not name the pre-commitment' }
  const successor = only(migration, 'p'), sig = only(migration, 'successor-sig')
  if (!successor || !sig) return { valid: false, reason: 'missing p or successor-sig' }
  if (!HEX64.test(successor) || !HEX128.test(sig)) return { valid: false, reason: 'p or successor-sig is not lowercase hex' }
  if (successor === precommit.pubkey || successor === migration.pubkey) return { valid: false, reason: 'the successor must be a new key' }
  if (!Number.isSafeInteger(migration.created_at) || migration.created_at < 0) return { valid: false, reason: 'created_at out of range' }
  let ok = false
  try { ok = schnorr.verify(hexToBytes(sig), consentMessage(precommit.pubkey, migration.pubkey, successor, migration.created_at), hexToBytes(successor)) } catch { ok = false }
  if (!ok) return { valid: false, reason: 'successor-sig does not verify' }
  return { valid: true, successor, identity: precommit.pubkey }
}

export interface Evidence {
  /** When this client first saw the pre-commitment, by its own clock. Zero or unknown means no evidence. */
  precommitFirstSeen: number
  /** When this client first saw the migration, by its own clock. Never the event's own created_at, which its signer chose. */
  migrationFirstSeen: number
  /** A kind 1040 OpenTimestamps attestation proves the pre-commitment existed before this time. It still needs the seven-day gap. */
  precommitAttestedBefore?: number
  /** The root this client bound to the identity, the master on the identity's own first published linkage proof, and when. Keep the first ever bound; never replace it. */
  identityRoot?: { masterPubkey: string; firstSeen: number }
  /** The successor key a fresh out-of-band bond ceremony confirmed, if one did. */
  bondedSuccessor?: string
  /** The successor key someone the user trusts attested to, if one did. */
  attestedSuccessor?: string
  /** A second, different pre-commitment exists for this identity. */
  contested?: boolean
  /** A second migration by the same migration key exists. */
  secondMigration?: boolean
}

export type Path = { path: 'automatic'; because: string } | { path: 'manual'; because: string }

/** §4: automatic or manual, from the evidence this client holds. Never automatic on consent alone. */
const goodTime = (t: number | undefined): t is number => t !== undefined && Number.isFinite(t) && t > 0

export function decide(migration: NostrEvent, precommit: NostrEvent, ev: Evidence | null | undefined): Path {
  const v = validateMigration(migration, precommit)
  if (!v.valid) return { path: 'manual', because: v.reason }
  if (!ev || typeof ev !== 'object') return { path: 'manual', because: 'no evidence' }
  if (ev.contested) return { path: 'manual', because: 'a second pre-commitment exists for this identity' }
  if (ev.secondMigration) return { path: 'manual', because: 'a second migration by this migration key exists' }
  if (!goodTime(ev.migrationFirstSeen)) return { path: 'manual', because: 'no first-seen time for the migration' }
  // The earlier of the signer's date and this client's own sighting: a signer can date into the future, not into this client's past.
  const seen = Math.min(migration.created_at, ev.migrationFirstSeen)
  if (goodTime(ev.precommitAttestedBefore) && ev.precommitAttestedBefore + SEVEN_DAYS <= seen) return { path: 'automatic', because: 'the pre-commitment is attested at least seven days older than the migration' }
  if (goodTime(ev.precommitFirstSeen) && ev.precommitFirstSeen + SEVEN_DAYS <= seen) return { path: 'automatic', because: 'the pre-commitment was seen at least seven days before the migration' }
  const linkageRaw = only(migration, 'linkage')
  if (linkageRaw && ev.identityRoot && goodTime(ev.identityRoot.firstSeen) && ev.identityRoot.firstSeen + SEVEN_DAYS <= seen) {
    try {
      const proof = JSON.parse(linkageRaw) as LinkageProof
      if (proof && typeof proof === 'object' && verifyProof(proof) && proof.childPubkey === v.successor && proof.masterPubkey === ev.identityRoot.masterPubkey && proof.purpose === 'successor') return { path: 'automatic', because: 'the successor shares a root bound to the identity seven days ago' }
    } catch { /* a linkage the client cannot read is ignored */ }
  }
  if (ev.bondedSuccessor === v.successor) return { path: 'automatic', because: 'a bond ceremony with the successor succeeded' }
  if (ev.attestedSuccessor === v.successor) return { path: 'automatic', because: 'someone you trust attested to the pair' }
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
