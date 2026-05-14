'use strict'

const { CausalLog, _internals } = require('./index')
const {
  bucketDigest,
  commitmentForEdges,
  commitmentForVertices,
  coordinateRootFromEntries,
  edgeBucketCommitment,
  elementScalarForEdge,
  elementScalarForVertex,
  evaluatePolynomial,
  fmod,
  generator,
  hashToScalar,
  ipaProvePolynomialEvaluation,
  ipaVerifyPolynomialEvaluation,
  polyCommitment,
  ptEq,
  ptFromBytes,
  ptScale,
  ptToBytes,
  rootPolynomial,
  termForVertexBucket,
  termForEdgeBucket,
  vertexBucketCommitment
} = _internals
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

function expectedCoordinateRoot (log) {
  const entries = []
  const ranks = new Set(log.vertices().map(vertex => vertex.rank))

  for (const rank of ranks) {
    entries.push({
      i: rank,
      j: rank,
      digest: bucketDigest(vertexBucketCommitment(rank, log.layer(rank)))
    })
  }

  const coordinates = new Set(log.edges().map(edge => `${edge.fromRank},${edge.toRank}`))
  for (const coordinate of coordinates) {
    const [fromRank, toRank] = coordinate.split(',').map(Number)
    entries.push({
      i: fromRank,
      j: toRank,
      digest: bucketDigest(edgeBucketCommitment(fromRank, toRank, log.edgeBucket(fromRank, toRank)))
    })
  }

  return coordinateRootFromEntries(entries)
}

function tamperCoordinateOpening (proof) {
  if (proof.coordinateOpening.siblings.length > 0) {
    proof.coordinateOpening.siblings[0].hash = b4a.alloc(32, 1)
  } else {
    proof.coordinateOpening.leafCount = 0
  }
}

console.log('\n── Suite 1: Causal Log Basics ──────────────────────────')

test('empty log has zero state', () => {
  const log = new CausalLog()
  const state = log.state()

  assertEqual(state.maxRank, 0)
  assertEqual(state.vertexCount, 0)
  assertEqual(state.byteLength, 0)
  assertEqual(state.commitment.length, 32)
  assertEqual(state.coordinateRoot.length, 32)
  assert(state.commitment.every(byte => byte === 0), 'empty commitment should be zero point')
})

test('append assigns increasing ranks', () => {
  const log = new CausalLog()
  const a = log.append(b('a'))
  const bVertex = log.append(b('b'))

  assertEqual(a.rank, 1)
  assertEqual(bVertex.rank, 2)
  assertEqual(log.maxRank, 2)
  assertEqual(log.vertexCount, 2)
  assertEqual(log.byteLength, 2)
})

test('linear order is rank-sensitive', () => {
  const ab = new CausalLog()
  ab.append(b('a'))
  ab.append(b('b'))

  const ba = new CausalLog()
  ba.append(b('b'))
  ba.append(b('a'))

  assertBufferNotEqual(ab.commitment(), ba.commitment(), 'reordering across ranks changes commitment')
})

test('same-rank layer is commutative', () => {
  const bc = new CausalLog()
  bc.append(b('a'))
  bc.appendLayer([b('b'), b('c')])
  bc.append(b('d'))

  const cb = new CausalLog()
  cb.append(b('a'))
  cb.appendLayer([b('c'), b('b')])
  cb.append(b('d'))

  assertBufferEqual(bc.commitment(), cb.commitment(), '{b,c} and {c,b} should commit the same')
})

test('a | {b,c} | d matches set-bucket layer construction', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  let expected = termForVertexBucket(1, [b('a')])
  expected = expected.add(termForVertexBucket(2, [b('b'), b('c')]))
  expected = expected.add(termForVertexBucket(3, [b('d')]))

  assert(ptEq(log.vertexCommitmentPoint(), expected), 'vertex commitment should use diagonal set buckets')
})

test('a | {b,c} | d is deterministic with branch-wise union', () => {
  const segmentWise = new CausalLog()
  segmentWise.append(b('a'))
  segmentWise.appendLayer([b('b'), b('c')])
  segmentWise.append(b('d'))

  const branchB = new CausalLog()
  branchB.addBranch([b('a'), b('b'), b('d')])

  const branchC = new CausalLog()
  branchC.addBranch([b('a'), b('c'), b('d')])

  const branchWise = branchB.clone().merge(branchC)

  assertBufferEqual(segmentWise.commitment(), branchWise.commitment())
  assertEqual(branchWise.vertexCount, 4, 'shared prefix and suffix should dedupe')
})

test('manual commitment helper matches log state', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])

  const expected = commitmentForVertices(log.vertices())
  assertBufferEqual(log.vertexCommitment(), ptToBytes(expected))
})

test('edge commitment distinguishes branch continuation', () => {
  const terminated = new CausalLog()
  terminated.addBranch([b('a'), b('b')])
  terminated.addBranch([b('a'), b('c'), b('d')])

  const sharedTail = new CausalLog()
  sharedTail.addBranch([b('a'), b('b'), b('d')])
  sharedTail.addBranch([b('a'), b('c'), b('d')])

  assertBufferEqual(terminated.vertexCommitment(), sharedTail.vertexCommitment())
  assertBufferNotEqual(terminated.edgeCommitment(), sharedTail.edgeCommitment())
  assertBufferNotEqual(terminated.commitment(), sharedTail.commitment())
})

test('edge commitment matches set-bucket coordinate terms', () => {
  const log = new CausalLog()
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

test('incremental commitments match full recomputation after mixed mutations', () => {
  const log = new CausalLog()

  for (let rank = 1; rank <= 6; rank++) {
    for (let i = 0; i < rank + 1; i++) {
      log.addVertex(rank, b(`r${rank}:v${i}`))
    }
  }

  for (let rank = 1; rank < 6; rank++) {
    for (const from of log.layer(rank)) {
      for (const to of log.layer(rank + 1)) {
        if ((from[0] + to[0] + rank) % 3 === 0) log.addEdge(rank, from, rank + 1, to)
      }
    }
  }

  log.addEdge(1, b('r1:v0'), 4, b('r4:v2'))
  log.addEdge(2, b('r2:v1'), 6, b('r6:v3'))

  assertBufferEqual(log.vertexCommitment(), ptToBytes(commitmentForVertices(log.vertices())))
  assertBufferEqual(log.edgeCommitment(), ptToBytes(commitmentForEdges(log.edges())))
  assertBufferEqual(log.coordinateRoot(), expectedCoordinateRoot(log))
})

test('explicit edges can occupy non-adjacent coordinate buckets', () => {
  const log = new CausalLog()
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

test('duplicate vertices at the same rank are deduped', () => {
  const withDupes = new CausalLog()
  withDupes.appendLayer([b('b'), b('b'), b('c')])

  const deduped = new CausalLog()
  deduped.appendLayer([b('b'), b('c')])

  assertEqual(withDupes.vertexCount, 2)
  assertBufferEqual(withDupes.commitment(), deduped.commitment())
})

test('same bytes at different ranks are distinct vertices', () => {
  const log = new CausalLog()
  log.append(b('x'))
  log.append(b('x'))

  assertEqual(log.vertexCount, 2)
  assertEqual(log.layer(1).length, 1)
  assertEqual(log.layer(2).length, 1)
})

test('merge is order-independent for disjoint ranked vertices', () => {
  const left = new CausalLog()
  left.addVertex(1, b('a'))
  left.addVertex(2, b('b'))

  const right = new CausalLog()
  right.addVertex(2, b('c'))
  right.addVertex(3, b('d'))

  const lr = left.clone().merge(right)
  const rl = right.clone().merge(left)

  assertBufferEqual(lr.commitment(), rl.commitment())
  assertEqual(lr.vertexCount, 4)
  assertEqual(rl.vertexCount, 4)
})

test('merge dedupes shared vertices', () => {
  const left = new CausalLog()
  left.addVertex(1, b('a'))
  left.addVertex(2, b('b'))

  const right = new CausalLog()
  right.addVertex(1, b('a'))
  right.addVertex(2, b('c'))

  const merged = left.clone().merge(right)

  assertEqual(merged.vertexCount, 3)
  assertEqual(merged.layer(1).length, 1)
  assertEqual(merged.layer(2).length, 2)
})

test('layer inspection is deterministic', () => {
  const log = new CausalLog()
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
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))
  log.append(b('d'))

  const proof = log.proveVertex({ rank: 2, value: b('b') })
  valid(CausalLog.verifyVertex(log.state(), proof))
  valid(log.verifyVertex(proof))
})

test('vertex proof for a degenerate layer verifies without complements', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  const proof = log.proveVertex({ rank: 2, value: b('b') })

  assertEqual(proof.type, 'hyperdag-vertex-membership-proof-v1')
  assertEqual(proof.degree, 2)
  assert(proof.bucketCommitment.length === 32, 'proof should carry bucket commitment')
  assertEqual(proof.coordinateOpening.type, 'hyperdag-coordinate-opening-v1')
  valid(CausalLog.verifyVertex(log.state(), proof))
})

test('valid edge proof verifies against expected state', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('d')])
  log.addBranch([b('a'), b('c'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })

  assertEqual(proof.type, 'hyperdag-edge-membership-proof-v1')
  assertEqual(proof.degree, 2)
  valid(CausalLog.verifyEdge(log.state(), proof))
  valid(log.verifyEdge(proof))
})

test('non-adjacent edge proof verifies against expected state', () => {
  const log = new CausalLog()
  log.addEdge(1, b('a'), 3, b('d'))

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 3, to: b('d') })

  assertEqual(proof.coordinate.toRank, 3)
  valid(CausalLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong edge', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.edge.from = b('x')

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong target value', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.edge.to = b('x')

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong coordinate', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.coordinate.fromRank = 1

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('edge proof rejects wrong bucket commitment', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('d')])

  const proof = log.proveEdge({ fromRank: 2, from: b('b'), toRank: 3, to: b('d') })
  proof.bucketCommitment = ptToBytes(vertexBucketCommitment(1, [b('x')]))

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('vertex proof rejects wrong bucket commitment', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.bucketCommitment = ptToBytes(vertexBucketCommitment(1, [b('x')]))

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('vertex proof rejects tampered bucket digest', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.bucketDigest = fmod(proof.bucketDigest + 1n)

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('edge proof rejects tampered bucket digest', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  proof.bucketDigest = fmod(proof.bucketDigest + 1n)

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('vertex proof rejects tampered coordinate opening', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  tamperCoordinateOpening(proof)

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('edge proof rejects tampered coordinate opening', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b'), b('c')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  tamperCoordinateOpening(proof)

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('proof rejects inconsistent state coordinate root', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  const state = log.state()
  state.coordinateRoot = b4a.alloc(32, 1)

  invalid(CausalLog.verifyVertex(state, proof))
})

test('proof rejects inconsistent state commitment slices', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  const state = log.state()
  state.edgeCommitment = log.vertexCommitment()

  invalid(CausalLog.verifyVertex(state, proof))
})

test('proof does not verify against a different commitment', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const other = new CausalLog()
  other.append(b('x'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  invalid(CausalLog.verifyVertex(other.state(), proof))
})

test('proof does not trust its embedded state', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const other = new CausalLog()
  other.append(b('x'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.state = other.state()

  invalid(CausalLog.verifyVertex(other.state(), proof))
})

test('mutated proof rank fails', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.rank = 2

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('mutated proof value fails', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.value = b('x')

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('mutated IPA opening fails', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  proof.innerOpening.finalScalar = fmod(proof.innerOpening.finalScalar + 1n)

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('stale vertex proof fails after expected state advances', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  log.append(b('b'))

  invalid(CausalLog.verifyVertex(log.state(), proof))
})

test('stale edge proof fails after expected state advances', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  log.append(b('c'))

  invalid(CausalLog.verifyEdge(log.state(), proof))
})

test('commitment-only state is not enough to verify vertex membership', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const proof = log.proveVertex({ rank: 1, value: b('a') })
  invalid(CausalLog.verifyVertex(log.commitment(), proof))
})

test('commitment-only state is not enough to verify edge membership', () => {
  const log = new CausalLog()
  log.addBranch([b('a'), b('b')])

  const proof = log.proveEdge({ fromRank: 1, from: b('a'), toRank: 2, to: b('b') })
  invalid(CausalLog.verifyEdge(log.commitment(), proof))
})

console.log('\n── Suite 5: Serialization and Helpers ──────────────────')

test('toJSON / fromJSON round trip preserves state', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.appendLayer([b('b'), b('c')])
  log.append(b('d'))

  const restored = CausalLog.fromJSON(log.toJSON())

  assertBufferEqual(restored.commitment(), log.commitment())
  assertBufferEqual(restored.coordinateRoot(), log.coordinateRoot())
  assertEqual(restored.maxRank, log.maxRank)
  assertEqual(restored.vertexCount, log.vertexCount)
  assertEqual(restored.byteLength, log.byteLength)
})

test('restored log verifies original proof', () => {
  const log = new CausalLog()
  log.append(b('a'))
  log.append(b('b'))

  const proof = log.proveVertex({ rank: 2, value: b('b') })
  const restored = CausalLog.fromJSON(log.toJSON())

  valid(restored.verifyVertex(proof))
})

test('fromJSON rejects mismatched commitment', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const json = log.toJSON()
  json.commitment = b4a.from(generator(1).toBytes()).toString('hex')

  let threw = false
  try {
    CausalLog.fromJSON(json)
  } catch {
    threw = true
  }

  assert(threw, 'fromJSON should reject tampered commitment')
})

test('fromJSON rejects mismatched coordinate root', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const json = log.toJSON()
  json.coordinateRoot = b4a.alloc(32, 1).toString('hex')

  let threw = false
  try {
    CausalLog.fromJSON(json)
  } catch {
    threw = true
  }

  assert(threw, 'fromJSON should reject tampered coordinate root')
})

test('point byte round trip works for commitments', () => {
  const log = new CausalLog()
  log.append(b('a'))

  const point = ptFromBytes(log.commitment())
  assert(ptEq(point, log.commitmentPoint()))
})

test('rank generator binds rank, not append position', () => {
  const s = hashToScalar(b('x'))
  const rank1 = ptScale(s, generator(1))
  const rank2 = ptScale(s, generator(2))

  assert(!ptEq(rank1, rank2), 'same bytes at different ranks should use different generators')
})

console.log('\n──────────────────────────────────────────────────')
console.log(`Results: ${passed} passed, ${failed} failed`)

if (failed > 0) process.exit(1)
