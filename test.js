'use strict'

const {
  RankedLog,
  bucketDigest,
  commitmentForEdges,
  commitmentForEntries,
  edgeBucketCommitment,
  elementScalarForEdge,
  elementScalarForVertex,
  evaluatePolynomial,
  fmod,
  generator,
  hashEntry,
  ipaProvePolynomialEvaluation,
  ipaVerifyPolynomialEvaluation,
  polyCommitment,
  ptEq,
  ptFromBytes,
  ptScale,
  ptToBytes,
  rootPolynomial,
  termForEntry,
  termForLayer,
  termForEdgeBucket,
  vertexBucketCommitment
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

test('a | {b,c} | d matches set-bucket layer construction', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  let expected = termForEntry(1, b('a'))
  expected = expected.add(termForLayer(2, [b('b'), b('c')]))
  expected = expected.add(termForEntry(3, b('d')))

  assert(ptEq(log.rankCommitmentPoint(), expected), 'rank commitment should use diagonal set buckets')
})

test('a | {b,c} | d is deterministic with branch-wise union', () => {
  const segmentWise = new RankedLog()
  segmentWise.append(b('a'))
  segmentWise.appendLayer([b('b'), b('c')])
  segmentWise.append(b('d'))

  const branchB = new RankedLog()
  branchB.addBranch([b('a'), b('b'), b('d')])

  const branchC = new RankedLog()
  branchC.addBranch([b('a'), b('c'), b('d')])

  const branchWise = branchB.clone().merge(branchC)

  assertBufferEqual(segmentWise.commitment(), branchWise.commitment())
  assertEqual(branchWise.entryCount, 4, 'shared prefix and suffix should dedupe')
})

test('manual commitment helper matches log state', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])

  const expected = commitmentForEntries(log.entries())
  assertBufferEqual(log.rankCommitment(), ptToBytes(expected))
})

test('edge commitment distinguishes branch continuation', () => {
  const terminated = new RankedLog()
  terminated.addBranch([b('a'), b('b')])
  terminated.addBranch([b('a'), b('c'), b('d')])

  const sharedTail = new RankedLog()
  sharedTail.addBranch([b('a'), b('b'), b('d')])
  sharedTail.addBranch([b('a'), b('c'), b('d')])

  assertBufferEqual(terminated.rankCommitment(), sharedTail.rankCommitment())
  assertBufferNotEqual(terminated.edgeCommitment(), sharedTail.edgeCommitment())
  assertBufferNotEqual(terminated.commitment(), sharedTail.commitment())
})

test('edge commitment matches set-bucket coordinate terms', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  let expected = termForEdgeBucket(1, 2, [
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') },
    { fromRank: 1, from: b('a'), toRank: 2, to: b('c') }
  ])
  expected = expected.add(termForEdgeBucket(2, 3, [
    { fromRank: 2, from: b('b'), toRank: 3, to: b('d') },
    { fromRank: 2, from: b('c'), toRank: 3, to: b('d') }
  ]))

  assertBufferEqual(log.edgeCommitment(), ptToBytes(expected))
  assertBufferEqual(log.edgeCommitment(), ptToBytes(commitmentForEdges(log.edges())))
})

test('explicit edges can occupy non-adjacent coordinate buckets', () => {
  const log = new RankedLog()
  log.addEdge(1, b('a'), 3, b('d'))

  const expected = termForEdgeBucket(1, 3, [
    { fromRank: 1, from: b('a'), toRank: 3, to: b('d') }
  ])

  assertBufferEqual(log.edgeCommitment(), ptToBytes(expected))
})

test('edge bucket helper rejects edges from another coordinate', () => {
  let threw = false

  try {
    termForEdgeBucket(1, 2, [
      { fromRank: 2, from: b('b'), toRank: 3, to: b('d') }
    ])
  } catch (err) {
    threw = true
  }

  assert(threw, 'edge bucket helper should reject mismatched edge coordinates')
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

console.log('\n── Suite 3: Polynomial Set Buckets ─────────────────────')

test('root polynomial evaluates to zero for members', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)

  assertEqual(evaluatePolynomial(coeffs, roots[0]), 0n)
  assertEqual(evaluatePolynomial(coeffs, roots[1]), 0n)
})

test('root polynomial does not evaluate to zero for non-members', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)
  const outsider = elementScalarForVertex(1, b('x'))

  assert(evaluatePolynomial(coeffs, outsider) !== 0n, 'non-member should not be a root')
})

test('polynomial commitment opens validly at a member root', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)
  const commitment = polyCommitment(1, 1, coeffs)
  const proof = ipaProvePolynomialEvaluation(1, 1, coeffs, roots[0], 0n)

  valid(ipaVerifyPolynomialEvaluation(1, 1, commitment, roots[0], 0n, proof))
})

test('polynomial opening fails for a mutated root', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)
  const commitment = polyCommitment(1, 1, coeffs)
  const proof = ipaProvePolynomialEvaluation(1, 1, coeffs, roots[0], 0n)
  const outsider = elementScalarForVertex(1, b('x'))

  invalid(ipaVerifyPolynomialEvaluation(1, 1, commitment, outsider, 0n, proof))
})

test('polynomial opening fails for a wrong claimed value', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)
  const commitment = polyCommitment(1, 1, coeffs)
  const proof = ipaProvePolynomialEvaluation(1, 1, coeffs, roots[0], 0n)

  invalid(ipaVerifyPolynomialEvaluation(1, 1, commitment, roots[0], 1n, proof))
})

test('polynomial opening fails for a mutated proof', () => {
  const roots = [elementScalarForVertex(1, b('a')), elementScalarForVertex(1, b('b'))]
  const coeffs = rootPolynomial(roots)
  const commitment = polyCommitment(1, 1, coeffs)
  const proof = ipaProvePolynomialEvaluation(1, 1, coeffs, roots[0], 0n)
  proof.finalScalar = fmod(proof.finalScalar + 1n)

  invalid(ipaVerifyPolynomialEvaluation(1, 1, commitment, roots[0], 0n, proof))
})

test('bucket digest is derived from bucket commitment', () => {
  const commitment = vertexBucketCommitment(1, [b('a'), b('b')])
  const digest = bucketDigest(commitment)

  assertEqual(typeof digest, 'bigint')
  assert(digest !== 0n, 'bucket digest should be a non-zero-looking scalar')
})

test('vertex bucket commitment dedupes duplicate elements', () => {
  const withDupes = vertexBucketCommitment(1, [b('a'), b('a'), b('b')])
  const deduped = vertexBucketCommitment(1, [b('a'), b('b')])

  assert(ptEq(withDupes, deduped), 'duplicate vertices should not change the set bucket')
})

test('edge bucket commitment is commutative', () => {
  const left = edgeBucketCommitment(1, 2, [
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') },
    { fromRank: 1, from: b('a'), toRank: 2, to: b('c') }
  ])
  const right = edgeBucketCommitment(1, 2, [
    { fromRank: 1, from: b('a'), toRank: 2, to: b('c') },
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') }
  ])

  assert(ptEq(left, right), 'edge bucket commitment should ignore set ordering')
})

test('edge bucket commitment dedupes duplicate edges', () => {
  const withDupes = edgeBucketCommitment(1, 2, [
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') },
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') }
  ])
  const deduped = edgeBucketCommitment(1, 2, [
    { fromRank: 1, from: b('a'), toRank: 2, to: b('b') }
  ])

  assert(ptEq(withDupes, deduped), 'duplicate edges should not change the set bucket')
})

console.log('\n── Suite 4: Unsigned Membership Verification ───────────')

test('valid vertex proof verifies against expected state', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))
  log.append(b('d'))

  const proof = log.proveVertex({ rank: 2, value: b('b') })
  valid(RankedLog.verifyVertex(log.state(), proof))
  valid(log.verifyVertex(proof))
  valid(RankedLog.verifyEntry(log.state(), proof))
})

test('vertex proof for a degenerate layer verifies without complements', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  const proof = log.proveVertex({ rank: 2, value: b('b') })

  assertEqual(proof.type, 'hyperdag-vertex-membership-proof-v1')
  assertEqual(proof.degree, 2)
  assert(proof.bucketCommitment.length === 32, 'proof should carry bucket commitment')
  valid(RankedLog.verifyVertex(log.state(), proof))
})

test('valid edge proof verifies against expected state', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b'), b('d')])
  log.addBranch([b('a'), b('c'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })

  assertEqual(proof.type, 'hyperdag-edge-membership-proof-v1')
  assertEqual(proof.degree, 2)
  valid(RankedLog.verifyEdge(log.state(), proof))
  valid(log.verifyEdge(proof))
})

test('non-adjacent edge proof verifies against expected state', () => {
  const log = new RankedLog()
  log.addEdge(1, b('a'), 3, b('d'))

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 3, to: b('d') })

  assertEqual(proof.coordinate.toRank, 3)
  valid(RankedLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong edge', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.edge.from = b('x')

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong target value', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.edge.to = b('x')

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong coordinate', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.coordinate.fromRank = 1

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong bucket commitment', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.bucketCommitment = ptToBytes(vertexBucketCommitment(1, [b('x')]))

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('vertex proof rejects wrong bucket commitment', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.bucketCommitment = ptToBytes(vertexBucketCommitment(1, [b('x')]))

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('vertex proof rejects tampered bucket digest', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.bucketDigest = fmod(proof.bucketDigest + 1n)

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('edge proof rejects tampered bucket digest', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  proof.bucketDigest = fmod(proof.bucketDigest + 1n)

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('vertex proof rejects tampered outer opening', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.outerOpening.finalScalar = fmod(proof.outerOpening.finalScalar + 1n)

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('edge proof rejects tampered outer opening', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  proof.outerOpening.finalScalar = fmod(proof.outerOpening.finalScalar + 1n)

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('proof rejects inconsistent state commitment slices', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  const state = log.state()
  state.edgeCommitment = log.rankCommitment()

  invalid(RankedLog.verifyVertex(state, proof))
})

test('proof does not verify against a different commitment', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const other = new RankedLog()
  other.append(b('x'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  invalid(RankedLog.verifyVertex(other.state(), proof))
})

test('proof does not trust its embedded state', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const other = new RankedLog()
  other.append(b('x'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.state = other.state()

  invalid(RankedLog.verifyVertex(other.state(), proof))
})

test('mutated proof rank fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.rank = 2

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('mutated proof value fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.value = b('x')

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('mutated IPA opening fails', () => {
  const log = new RankedLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.innerOpening.finalScalar = fmod(proof.innerOpening.finalScalar + 1n)

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('stale vertex proof fails after expected state advances', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  log.append(b('b'))

  invalid(RankedLog.verifyVertex(log.state(), proof))
})

test('stale edge proof fails after expected state advances', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  log.append(b('c'))

  invalid(RankedLog.verifyEdge(log.state(), proof))
})

test('commitment-only state is enough to verify vertex membership', () => {
  const log = new RankedLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  valid(RankedLog.verifyVertex(log.commitment(), proof))
})

test('commitment-only state is enough to verify edge membership', () => {
  const log = new RankedLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  valid(RankedLog.verifyEdge(log.commitment(), proof))
})

console.log('\n── Suite 5: Serialization and Helpers ──────────────────')

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

  const proof = log.proveVertex({ rank: 2, value: b('b') })
  const restored = RankedLog.fromJSON(log.toJSON())

  valid(restored.verifyVertex(proof))
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

console.log('\n──────────────────────────────────────────────────')
console.log(`Results: ${passed} passed, ${failed} failed`)

if (failed > 0) process.exit(1)
