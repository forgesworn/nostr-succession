import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import type { NostrEvent } from 'nostr-tools/pure'
import { validateMigration, decide, predecessorKeys } from '../src/index.js'

function rng(seed: number) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000 } }
const v = JSON.parse(readFileSync(new URL('../vectors/succession.json', import.meta.url), 'utf8'))
const pre: NostrEvent = v.precommit
const good: NostrEvent = v.cases.find((c: any) => c.name === 'passes').event
const N = 800

function flipString(s: string, r: () => number): string {
  const i = Math.floor(r() * s.length)
  return s.slice(0, i) + String.fromCharCode(s.charCodeAt(i) ^ 1) + s.slice(i + 1)
}

describe('fuzz: validateMigration', () => {
  it('a mutated migration or pre-commitment is never valid and never throws', () => {
    const r = rng(21)
    for (let i = 0; i < N; i++) {
      const m: NostrEvent = { ...good, tags: good.tags.map((t) => [...t]) }
      const p: NostrEvent = { ...pre, tags: pre.tags.map((t) => [...t]) }
      const op = Math.floor(r() * 7)
      if (op === 0) m.sig = flipString(m.sig, r)
      else if (op === 1) m.pubkey = flipString(m.pubkey, r)
      else if (op === 2) m.created_at += 1
      else if (op === 3) { const t = m.tags.find((t) => t[0] === 'successor-sig')!; t[1] = flipString(t[1]!, r) }
      else if (op === 4) { const t = m.tags.find((t) => t[0] === 'p')!; t[1] = flipString(t[1]!, r) }
      else if (op === 5) { const t = p.tags.find((t) => t[0] === 'p')!; t[1] = flipString(t[1]!, r) }
      else m.tags = m.tags.filter((t) => t[0] !== 'e')
      let out
      expect(() => { out = validateMigration(m, p) }).not.toThrow()
      expect((out as any).valid).toBe(false)
    }
  })
  it('garbage events never validate and never throw', () => {
    const r = rng(22)
    for (let i = 0; i < 300; i++) {
      const junk = { kind: Math.floor(r() * 2000), pubkey: 'zz', created_at: r() * 1e10, tags: r() < 0.5 ? [] : [['p'], ['e', 'x'], ['successor-sig', 'nothex']], content: '', id: '', sig: '' } as unknown as NostrEvent
      let out
      expect(() => { out = validateMigration(junk, r() < 0.5 ? pre : junk) }).not.toThrow()
      expect((out as any).valid).toBe(false)
    }
  })
  it('decide never throws on any evidence and is never automatic without evidence', () => {
    const r = rng(23)
    for (let i = 0; i < N; i++) {
      const ev = {
        precommitFirstSeen: Math.floor(r() * 2e9),
        migrationFirstSeen: Math.floor(r() * 2e9),
        precommitAttestedBefore: r() < 0.3 ? Math.floor(r() * 2e9) : undefined,
        identityRoot: r() < 0.3 ? { masterPubkey: v.testOnlyKeys.masterPubkey, firstSeen: Math.floor(r() * 2e9) } : undefined,
        bondedSuccessor: r() < 0.2 ? good.tags.find((t) => t[0] === 'p')![1] : undefined,
        attestedSuccessor: r() < 0.2 ? 'ab'.repeat(32) : undefined,
        contested: r() < 0.2,
        secondMigration: r() < 0.2,
      }
      let d: any
      expect(() => { d = decide(good, pre, ev) }).not.toThrow()
      expect(['automatic', 'manual']).toContain(d.path)
      if (ev.contested || ev.secondMigration) expect(d.path).toBe('manual')
    }
    expect(decide(good, pre, { precommitFirstSeen: good.created_at, migrationFirstSeen: good.created_at }).path).toBe('manual')
  })
  it('predecessorKeys never throws', () => {
    for (const s of ['', '{', '[]', '{"predecessor_keys": 5}', '{"predecessor_keys": ["zz", 3, null]}']) expect(() => predecessorKeys(s)).not.toThrow()
  })
})
