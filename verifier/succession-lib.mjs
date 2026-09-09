// Shared by the generator and the verifier: the one derivation and the one
// digest that drafts/SUCCESSION.md fixes.
import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js'

export const DOMAIN = 'nostr-succession/v1'
export const KIND_PRECOMMIT = 1360
export const KIND_MIGRATION = 1361

function u64be(n) {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, BigInt(n))
  return out
}

/** msg = sha256("nostr-succession/v1" || 0x00 || identity || migration || successor || u64be(created_at)) */
export function successorMessage(identityPub, migrationPub, successorPub, createdAt) {
  return sha256(concatBytes(
    utf8ToBytes(DOMAIN), new Uint8Array([0]),
    hexToBytes(identityPub), hexToBytes(migrationPub), hexToBytes(successorPub),
    u64be(createdAt),
  ))
}

export function signSuccessor(successorPriv, identityPub, migrationPub, successorPub, createdAt) {
  return schnorr.sign(successorMessage(identityPub, migrationPub, successorPub, createdAt), successorPriv)
}

export function verifySuccessorSig(sigHex, identityPub, migrationPub, successorPub, createdAt) {
  try {
    return schnorr.verify(hexToBytes(sigHex), successorMessage(identityPub, migrationPub, successorPub, createdAt), hexToBytes(successorPub))
  } catch {
    return false
  }
}

export function tag(event, name) {
  return event.tags.find((t) => t[0] === name)?.[1]
}
