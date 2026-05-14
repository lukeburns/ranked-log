'use strict'

const {
  RankedLog,
  commitmentForEntries,
  hashEntry,
  generator,
  ptEq,
  ptFromBytes,
  ptScale,
  ptToBytes,
  termForEntry,
  termForLayer
} = require('./index')
const b4a = require('b4a')

let passed = 0
let failed = 0

function test (label, fn) {
  try {
    fn()
    console.log(`  ✓ ${label}`)
    passed++
  } catch (err) {
    console.log(`  ✗ ${label}`)
    console.log(`    ${err.message}`)
    failed++
  }
}

function assert (condition, message) {
  if (!condition) throw new Error(message || 'assertion failed')
}

function assertEqual (actual, expected, message) {
  if (actual !== expected) throw new Error(message || `expected ${actual} === ${expected}`)
}

function assertBufferEqual (actual, expected, message) {
  assert(b4a.from(actual).equals(b4a.from(expected)), message || 'buffers differ')
}

function assertBufferNotEqual (actual, expected, message) {
  assert(!b4a.from(actual).equals(b4a.from(expected)), message || 'buffers should differ')
}

function valid (result, message) {
  assert(result.valid, message || result.reason)
}

function invalid (result, message) {
  assert(!result.valid, message || 'verification should fail')
}

function b (value) {
  return b4a.from(value)
}

console.log('\n── Suite 1: Ranked Log Basics ──────────────────────────')

test('empty log has zero state', () => {
  const log = new RankedLog()
  const state = log.state()

  assertEqual(state.maxRank, 0)
  assertEqual(state.entryCount, 0)
  assertEqual(state.byteLength, 0)
  assertEqual(state.commitment.length, 32)
  assert(state.commitment.every(byte => byte === 0), 'empty commitment should be zero point')
})

test('append assigns increasing ranks', () => {
  const log = new RankedLog()
  const a = log.append(b('a'))
  const bEntry = log.append(b('b'))

  assertEqual(a.rank, 1)
  assertEqual(bEntry.rank, 2)
  assertEqual(log.maxRank, 2)
  assertEqual(log.entryCount, 2)
  assertEqual(log.byteLength, 2)
})

test('linear order is rank-sensitive', () => {
  const ab = new RankedLog()
  ab.append(b('a'))
  ab.append(b('b'))

  const ba = new RankedLog()
  ba.append(b('b'))
  ba.append(b('a'))

  assertBufferNotEqual(ab.commitment(), ba.commitment(), 'reordering across ranks changes commitment')
})

test('same-rank layer is commutative', () => {
  const bc = new RankedLog()
  bc.append(b('a'))
  bc.appendLayer([b('b'), b('c')])
  bc.append(b('d'))

  const cb = new RankedLog()
  cb.append(b('a'))
  cb.appendLayer([b('c'), b('b')])
  cb.append(b('d'))

  assertBufferEqual(bc.commitment(), cb.commitment(), '{b,c} and {c,b} should commit the same')
})

test('a | {b,c} | d matches averaged layer construction', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  let expected = termForEntry(1, b('a'))
  expected = expected.add(termForLayer(2, [b('b'), b('c')]))
  expected = expected.add(termForEntry(3, b('d')))

  assert(ptEq(log.commitmentPoint(), expected), 'commitment should use averaged rank layers')
})

test('a | {b,c} | d is homomorphic with branch-wise construction', () => {
  const segmentWise = new RankedLog()
  segmentWise.append(b('a'))
  segmentWise.appendLayer([b('b'), b('c')])
  segmentWise.append(b('d'))

  const branchB = new RankedLog()
  branchB.addAtRank(1, b('a'))
  branchB.addAtRank(2, b('b'))
  branchB.addAtRank(3, b('d'))

  const branchC = new RankedLog()
  branchC.addAtRank(1, b('a'))
  branchC.addAtRank(2, b('c'))
  branchC.addAtRank(3, b('d'))

  const branchWise = branchB.clone().merge(branchC)

  assertBufferEqual(segmentWise.commitment(), branchWise.commitment())
  assertEqual(branchWise.entryCount, 4, 'shared prefix and suffix should dedupe')
})

test('manual commitment helper matches log state', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])

  const expected = commitmentForEntries(log.entries())
  assertBufferEqual(log.commitment(), ptToBytes(expected))
})

console.log('\n── Suite 2: Layers, Deduping, and Merge ────────────────')

test('duplicate entries at the same rank are deduped', () => {
  const withDupes = new RankedLog()
  withDupes.appendLayer([b('b'), b('b'), b('c')])

  const deduped = new RankedLog()
  deduped.appendLayer([b('b'), b('c')])

  assertEqual(withDupes.entryCount, 2)
  assertBufferEqual(withDupes.commitment(), deduped.commitment())
})

test('same bytes at different ranks are distinct entries', () => {
  const log = new RankedLog()
  log.append(b('x'))
  log.append(b('x'))

  assertEqual(log.entryCount, 2)
  assertEqual(log.layer(1).length, 1)
  assertEqual(log.layer(2).length, 1)
})

test('merge is order-independent for disjoint ranked entries', () => {
  const left = new RankedLog()
  left.addAtRank(1, b('a'))
  left.addAtRank(2, b('b'))

  const right = new RankedLog()
  right.addAtRank(2, b('c'))
  right.addAtRank(3, b('d'))

  const lr = left.clone().merge(right)
  const rl = right.clone().merge(left)

  assertBufferEqual(lr.commitment(), rl.commitment())
  assertEqual(lr.entryCount, 4)
  assertEqual(rl.entryCount, 4)
})

test('merge dedupes shared entries', () => {
  const left = new RankedLog()
  left.addAtRank(1, b('a'))
  left.addAtRank(2, b('b'))

  const right = new RankedLog()
  right.addAtRank(1, b('a'))
  right.addAtRank(2, b('c'))

  const merged = left.clone().merge(right)

  assertEqual(merged.entryCount, 3)
  assertEqual(merged.layer(1).length, 1)
  assertEqual(merged.layer(2).length, 2)
})

test('layer inspection is deterministic', () => {
  const log = new RankedLog()
  log.appendLayer([b('c'), b('a'), b('b')])

  assertEqual(log.layer(1).map(value => value.toString()).join(','), 'a,b,c')
})

console.log('\n── Suite 3: Unsigned Entry Verification ────────────────')

test('valid entry proof verifies against expected state', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))
  log.append(b('d'))

  const proof = log.proveEntry({ rank: 2, value: b('b') })
  valid(RankedLog.verifyEntry(log.state(), proof))
  valid(log.verifyEntry(proof))
})

test('entry proofs reject non-linear layers for now', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])

  let threw = false
  try {
    log.proveEntry({ rank: 2, value: b('b') })
  } catch {
    threw = true
  }

  assert(threw, 'degenerate layer membership proofs are not implemented yet')
})

test('proof does not verify against a different commitment', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const other = new RankedLog()
  other.append(b('x'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  invalid(RankedLog.verifyEntry(other.state(), proof))
})

test('proof does not trust its embedded state', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const other = new RankedLog()
  other.append(b('x'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  proof.state = other.state()

  invalid(RankedLog.verifyEntry(other.state(), proof))
})

test('mutated proof rank fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  proof.rank = 2

  invalid(RankedLog.verifyEntry(log.state(), proof))
})

test('mutated proof value fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  proof.value = b('x')

  invalid(RankedLog.verifyEntry(log.state(), proof))
})

test('mutated IPA opening fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  proof.opening.finalScalar = proof.opening.finalScalar + 1n

  invalid(RankedLog.verifyEntry(log.state(), proof))
})

test('stale proof fails after expected state advances', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  log.append(b('b'))

  invalid(RankedLog.verifyEntry(log.state(), proof))
})

test('commitment-only state is enough to verify inclusion witness', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveEntry({ rank: 1, value: b('a') })
  valid(RankedLog.verifyEntry(log.commitment(), proof))
})

console.log('\n── Suite 4: Serialization and Helpers ──────────────────')

test('toJSON / fromJSON round trip preserves state', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  const restored = RankedLog.fromJSON(log.toJSON())

  assertBufferEqual(restored.commitment(), log.commitment())
  assertEqual(restored.maxRank, log.maxRank)
  assertEqual(restored.entryCount, log.entryCount)
  assertEqual(restored.byteLength, log.byteLength)
})

test('restored log verifies original proof', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveEntry({ rank: 2, value: b('b') })
  const restored = RankedLog.fromJSON(log.toJSON())

  valid(restored.verifyEntry(proof))
})

test('fromJSON rejects mismatched commitment', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const json = log.toJSON()
  json.commitment = b4a.from(generator(1).toBytes()).toString('hex')

  let threw = false
  try {
    RankedLog.fromJSON(json)
  } catch {
    threw = true
  }

  assert(threw, 'fromJSON should reject tampered commitment')
})

test('point byte round trip works for commitments', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const point = ptFromBytes(log.commitment())
  assert(ptEq(point, log.commitmentPoint()))
})

test('rank generator binds rank, not append position', () => {
  const s = hashEntry(b('x'))
  const rank1 = ptScale(s, generator(1))
  const rank2 = ptScale(s, generator(2))

  assert(!ptEq(rank1, rank2), 'same bytes at different ranks should use different generators')
})

console.log(`\n${'─'.repeat(50)}`)
console.log(`Results: ${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
