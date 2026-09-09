// A reference verifier for drafts/SUCCESSION.md §2 and §4, run against the
// vectors. Exits non-zero on the first disagreement. Written independently of
// nostr-succession so the two implementations check each other.
import { readFileSync } from 'node:fs'
import { verifyEvent } from 'nostr-tools/pure'
import { verifyProof } from 'nsec-tree/proof'
import { KIND_PRECOMMIT, KIND_MIGRATION, verifySuccessorSig } from './succession-lib.mjs'

const v = JSON.parse(readFileSync(new URL('../vectors/succession.json', import.meta.url), 'utf8'))
const SEVEN_DAYS = 7 * 24 * 3600
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

/** The value of a tag that appears exactly once, else undefined. */
function only(event, name) {
  const ts = event.tags.filter((t) => t[0] === name)
  return ts.length === 1 ? ts[0][1] : undefined
}
function count(event, name) {
  return event.tags.filter((t) => t[0] === name).length
}
/** A copy without nostr-tools' verified marker, so verifyEvent really runs. */
function bare(e) {
  return { kind: e.kind, pubkey: e.pubkey, created_at: e.created_at, tags: e.tags, content: e.content, id: e.id, sig: e.sig }
}

/** §2: is this a well-formed kind 1361 with the successor's consent? */
function validMigration(event, precommit) {
  if (event.kind !== KIND_MIGRATION || !verifyEvent(bare(event))) return { valid: false, reason: 'not a signed kind 1361' }
  if (precommit.kind !== KIND_PRECOMMIT || !verifyEvent(bare(precommit))) return { valid: false, reason: 'precommit invalid' }
  if (count(precommit, 'p') !== 1) return { valid: false, reason: 'precommit must name exactly one migration key' }
  if (!Number.isSafeInteger(event.created_at) || event.created_at < 0) return { valid: false, reason: 'created_at out of range' }
  if (count(event, 'p') !== 1 || count(event, 'e') !== 1 || count(event, 'successor-sig') !== 1 || count(event, 'linkage') > 1) {
    return { valid: false, reason: 'duplicate or missing tag' }
  }
  if (only(precommit, 'p') !== event.pubkey) return { valid: false, reason: 'kind 1361 not signed by the committed migration key' }
  if (event.pubkey === precommit.pubkey) return { valid: false, reason: 'migration key must differ from the identity' }
  if (only(event, 'e') !== precommit.id) return { valid: false, reason: 'e tag does not name the precommit' }
  const successor = only(event, 'p')
  const sig = only(event, 'successor-sig')
  if (!HEX64.test(successor ?? '') || !HEX128.test(sig ?? '')) return { valid: false, reason: 'p or successor-sig malformed' }
  if (successor === precommit.pubkey || successor === event.pubkey) return { valid: false, reason: 'successor must be a new key' }
  if (!verifySuccessorSig(sig, precommit.pubkey, event.pubkey, successor, event.created_at)) return { valid: false, reason: 'successor-sig does not verify' }
  return { valid: true, successor }
}

/**
 * §4: automatic or manual, from the evidence a client holds.
 * Every path needs seven days between the pre-commitment's proven existence
 * and the earlier of the 1361's created_at and the client's first sight of it.
 */
function path(event, successor, c, trustedMaster) {
  if (c.contested || c.secondMigration) return 'manual'
  const seen361 = Math.min(event.created_at, c.firstSeen361)
  const gap = (t) => Number.isFinite(t) && t + SEVEN_DAYS <= seen361
  if (gap(c.attestedBefore)) return 'automatic'
  if (gap(c.firstSeen360)) return 'automatic'
  const linkageRaw = only(event, 'linkage')
  if (linkageRaw && gap(c.rootBoundAt ?? v.rootBoundAt)) {
    try {
      const proof = JSON.parse(linkageRaw)
      if (verifyProof(proof) && proof.purpose === 'successor' && proof.childPubkey === successor && proof.masterPubkey === trustedMaster) return 'automatic'
    } catch { /* malformed linkage is no linkage */ }
  }
  return 'manual'
}

let failures = 0
for (const c of v.cases) {
  const r = validMigration(c.event, v.precommit)
  const got = r.valid
    ? { valid: true, path: path(c.event, r.successor, c, v.testOnlyKeys.masterPubkey) }
    : { valid: false, reason: r.reason }
  const want = c.expect
  const ok = got.valid === want.valid && (!want.valid || want.path === got.path)
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${c.name}: ${JSON.stringify(got)}`)
  if (!ok) failures++
}
if (!verifyProof(v.linkage) || v.linkage.purpose !== 'successor') { console.log('FAIL linkage proof'); failures++ }
if (v.precommit2.pubkey !== v.precommit.pubkey || v.precommit2.id === v.precommit.id) { console.log('FAIL precommit2 must be a second, different 1360 by the identity'); failures++ }
process.exit(failures ? 1 : 0)
