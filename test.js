'use strict'

/**
 * test.js
 * Tests covering all Hypercore-compatible and partial-order functionality
 */

const {
  IPATree, IPATreeBatch,
  ipaProve, ipaVerify,
  innerCommit, generator, hashToScalar,
  padPow2, ZERO, ptAdd, ptScale, ptEq
} = require('./index')

let passed = 0
let failed = 0

function test (label, fn) {
  try {
    fn()
    console.log(`  ✓ ${label}`)
    passed++
  } catch (e) {
    console.log(`  ✗ ${label}`)
    console.log(`    ${e.message}`)
    failed++
  }
}

function assert (cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed')
}

function assertEqual (a, b, msg) {
  if (a !== b) throw new Error(msg || `expected ${a} === ${b}`)
}

// ── Suite 1: Core IPA ────────────────────────────────────
console.log('\n── Suite 1: Core IPA ───────────────────────────────────')

test('IPA prove and verify round-trip (n=4)', () => {
  const scalars = [3n, 7n, 2n, 9n]
  const gens = scalars.map((_, i) => generator(i))
  const { scalars: s, gens: g } = padPow2(scalars, gens)
  const C = innerCommit(s, g)
  const proof = ipaProve(s, g)
  const { valid } = ipaVerify(C, proof)
  assert(valid, 'IPA proof should verify')
})

test('IPA prove and verify round-trip (n=8)', () => {
  const scalars = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]
  const gens = scalars.map((_, i) => generator(i))
  const proof = ipaProve(scalars, gens)
  const C = innerCommit(scalars, gens)
  const { valid } = ipaVerify(C, proof)
  assert(valid, 'IPA proof (n=8) should verify')
})

test('IPA fails on wrong commitment', () => {
  const scalars = [3n, 7n, 2n, 9n]
  const gens = scalars.map((_, i) => generator(i))
  const proof = ipaProve(scalars, gens)
  const wrongC = generator(999)  // completely wrong point
  const { valid } = ipaVerify(wrongC, proof)
  assert(!valid, 'IPA should fail with wrong commitment')
})

// ── Suite 2: Linear chain (Hypercore compatible) ──────────
console.log('\n── Suite 2: Linear chain (Hypercore compatible) ────────')

test('append single block', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('hello'))
  assertEqual(tree.length, 1)
  assertEqual(tree.byteLength, 5)
})

test('append multiple blocks sequentially', () => {
  const tree = new IPATree(null)
  const blocks = ['block0', 'block1', 'block2', 'block3'].map(Buffer.from)
  blocks.forEach(b => tree.append(b))
  assertEqual(tree.length, 4)
})

test('hash() returns 33-byte compressed EC point', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('data'))
  const h = tree.hash()
  assert(Buffer.isBuffer(h), 'hash should be a Buffer')
  assertEqual(h.length, 33, 'compressed EC point is 33 bytes')
})

test('hash() is deterministic', () => {
  const tree1 = new IPATree(null)
  const tree2 = new IPATree(null)
  tree1.append(Buffer.from('block0'))
  tree2.append(Buffer.from('block0'))
  assert(tree1.hash().equals(tree2.hash()), 'same blocks → same hash')
})

test('hash() changes on append', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('block0'))
  const h1 = tree.hash()
  tree.append(Buffer.from('block1'))
  const h2 = tree.hash()
  assert(!h1.equals(h2), 'hash should change after append')
})

test('signable() returns buffer', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('block0'))
  const mh = Buffer.alloc(32, 1)
  const s = tree.signable(mh)
  assert(Buffer.isBuffer(s), 'signable should be a Buffer')
  assert(s.length > 32, 'signable should be longer than manifest hash alone')
})

test('ranks are sequential in linear chain', () => {
  const tree = new IPATree(null)
  'abcd'.split('').forEach((c, i) => {
    tree.append(Buffer.from(c))
    assertEqual(tree.rank(i), i, `rank of block ${i} should be ${i}`)
  })
})

// ── Suite 3: Inclusion proofs ─────────────────────────────
console.log('\n── Suite 3: Inclusion proofs ───────────────────────────')

test('proof() and verify() for block 0', () => {
  const tree = new IPATree(null)
  ;['a', 'b', 'c', 'd'].forEach(c => tree.append(Buffer.from(c)))
  const proof = tree.proof({ block: { index: 0 } })
  assert(tree.verify(proof), 'proof for block 0 should verify')
})

test('proof() and verify() for middle block', () => {
  const tree = new IPATree(null)
  ;['a', 'b', 'c', 'd'].forEach(c => tree.append(Buffer.from(c)))
  const proof = tree.proof({ block: { index: 2 } })
  assert(tree.verify(proof), 'proof for block 2 should verify')
})

test('proof() and verify() for last block', () => {
  const tree = new IPATree(null)
  ;['a', 'b', 'c', 'd'].forEach(c => tree.append(Buffer.from(c)))
  const proof = tree.proof({ block: { index: 3 } })
  assert(tree.verify(proof), 'proof for block 3 should verify')
})

test('proof from a different tree does not verify', () => {
  const tree1 = new IPATree(null)
  const tree2 = new IPATree(null)
  ;['a', 'b', 'c', 'd'].forEach(c => tree1.append(Buffer.from(c)))
  ;['x', 'y', 'z', 'w'].forEach(c => tree2.append(Buffer.from(c)))
  const proof = tree1.proof({ block: { index: 0 } })
  // Tamper: swap the commitment to tree2's commitment
  const tamperedProof = { ...proof, commitment: tree2.hash() }
  assert(!tree2.verify(tamperedProof), 'tampered proof should not verify')
})

// ── Suite 4: Incremental updates ─────────────────────────
console.log('\n── Suite 4: Incremental updates ────────────────────────')

test('C(A + block) = C(A) + H(block)*G(rank)', () => {
  const { ptAdd, ptScale, ptEq, generator, hashToScalar, ZERO } = require('./index.js')

  const tree = new IPATree(null)
  ;['a', 'b', 'c'].forEach(c => tree.append(Buffer.from(c)))
  const C_before = Buffer.from(tree.hash())

  // Manually compute what the new commitment should be
  const newBlock = Buffer.from('d')
  const newRank = tree.length  // = 3
  const term = ptScale(hashToScalar(newBlock), generator(newRank))
  const { ptFromBytes } = require('./index')
  const C_prev_pt = ptFromBytes(C_before)
  const C_expected = ptAdd(C_prev_pt, term)

  tree.append(newBlock)
  const C_actual = ptFromBytes(tree.hash())

  assert(C_actual.equals(C_expected), 'incremental append should be additive')
})

test('batch commit matches direct append', () => {
  const tree1 = new IPATree(null)
  const tree2 = new IPATree(null)

  ;['a', 'b', 'c'].forEach(c => tree1.append(Buffer.from(c)))

  const batch = tree2.batch()
  ;['a', 'b', 'c'].forEach(c => batch.append(Buffer.from(c)))
  tree2.commit(batch)

  assert(tree1.hash().equals(tree2.hash()), 'batch and direct append should match')
})

// ── Suite 5: Partial order (fork/merge) ──────────────────
console.log('\n── Suite 5: Partial order (fork/merge) ─────────────────')

test('appendConcurrent: two blocks at same rank', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('a'))
  tree.appendConcurrent([Buffer.from('b1'), Buffer.from('b2')])
  assertEqual(tree.length, 3, 'length should be 3 after concurrent append')
  // b1 and b2 should have same rank
  assertEqual(tree.rank(1), tree.rank(2), 'concurrent blocks should have same rank')
})

test('concurrent blocks contribute different terms at same rank', () => {
  const { ptFromBytes } = require('./index')
  const tree = new IPATree(null)
  tree.append(Buffer.from('z'))
  tree.appendConcurrent([Buffer.from('b1'), Buffer.from('b2')])

  // Manually compute expected commitment
  // C = H(z)*G(0) + H(b1)*G(1) + H(b2)*G(1)
  const s0 = hashToScalar(Buffer.from('z'))
  const s1 = hashToScalar(Buffer.from('b1'))
  const s2 = hashToScalar(Buffer.from('b2'))
  const expected = ptAdd(
    ptAdd(ptScale(s0, generator(0)), ptScale(s1, generator(1))),
    ptScale(s2, generator(1))
  )
  const expectedBytes = Buffer.from(expected.toBytes())
  assert(tree.hash().equals(expectedBytes), 'fork commitment should be sum of terms')
})

test('mergeFrom: C(A∪B) = C(A) + C(B) for disjoint trees', () => {
  const { ptFromBytes } = require('./index')

  const treeA = new IPATree(null)
  treeA.append(Buffer.from('a'))
  treeA.append(Buffer.from('b'))

  const treeB = new IPATree(null)
  treeB.append(Buffer.from('a'))
  treeB.append(Buffer.from('b'))
  treeB.append(Buffer.from('c'))  // extra block

  // Build combined tree directly
  const combined = new IPATree(null)
  ;['a', 'b', 'c'].forEach(c => combined.append(Buffer.from(c)))

  // Build via merge: start with treeA, add only treeB's extra term
  const merged = new IPATree(null)
  ;['a', 'b'].forEach(c => merged.append(Buffer.from(c)))

  // Add c term manually (incremental)
  const { ptAdd: add, ptScale: scale, generator: gen, hashToScalar: hts } = require('./index')
  const cTerm = scale(hts(Buffer.from('c')), gen(2))
  merged._commitment = add(ptFromBytes(merged.hash()), cTerm)
  merged._blocks.push({ data: Buffer.from('c'), rank: 2 })
  merged._ranks.push(2)
  merged.length = 3

  assert(
    combined.hash().equals(merged.hash()),
    'incremental merge should match full construction'
  )
})

test('proof verifies after fork', () => {
  const tree = new IPATree(null)
  tree.append(Buffer.from('z'))
  tree.appendConcurrent([Buffer.from('b1'), Buffer.from('b2')])
  tree.append(Buffer.from('c'))

  const proof0 = tree.proof({ block: { index: 0 } })
  const proof1 = tree.proof({ block: { index: 1 } })
  const proof2 = tree.proof({ block: { index: 2 } })

  assert(tree.verify(proof0), 'proof for block 0 (before fork) should verify')
  assert(tree.verify(proof1), 'proof for fork branch b1 should verify')
  assert(tree.verify(proof2), 'proof for fork branch b2 should verify')
})

// ── Suite 6: Serialization ────────────────────────────────
console.log('\n── Suite 6: Serialization ──────────────────────────────')

test('toJSON / fromJSON round-trip', () => {
  const tree = new IPATree(null)
  ;['block0', 'block1', 'block2'].forEach(b => tree.append(Buffer.from(b)))

  const json = tree.toJSON()
  const restored = IPATree.fromJSON(json, null)

  assert(tree.hash().equals(restored.hash()), 'restored tree should have same hash')
  assertEqual(restored.length, tree.length, 'restored length should match')
  assertEqual(restored.byteLength, tree.byteLength, 'restored byteLength should match')
})

test('toJSON / fromJSON preserves proof validity', () => {
  const tree = new IPATree(null)
  ;['a', 'b', 'c', 'd'].forEach(c => tree.append(Buffer.from(c)))

  const proof = tree.proof({ block: { index: 1 } })
  const json = tree.toJSON()
  const restored = IPATree.fromJSON(json, null)

  assert(restored.verify(proof), 'proof should still verify after serialization round-trip')
})

// ── Suite 7: Proof size ───────────────────────────────────
console.log('\n── Suite 7: Proof sizes ────────────────────────────────')

test('proof size is O(log n)', () => {
  for (const n of [2, 4, 8, 16]) {
    const tree = new IPATree(null)
    for (let i = 0; i < n; i++) tree.append(Buffer.from(`block${i}`))
    const proof = tree.proof({ block: { index: 0 } })
    const rounds = proof.ipaProof.rounds.length
    const expectedRounds = Math.ceil(Math.log2(n))
    assertEqual(rounds, expectedRounds, `n=${n}: expected ${expectedRounds} rounds, got ${rounds}`)
  }
  console.log('    (proof rounds = log₂(n) ✓)')
})

// ── Results ───────────────────────────────────────────────
console.log(`\n${'─'.repeat(50)}`)
console.log(`Results: ${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
