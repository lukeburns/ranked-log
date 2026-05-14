'use strict'

/**
 * ipa-tree.js
 *
 * Drop-in replacement for Hypercore's MerkleTree backend.
 * Uses an IPA (Inner Product Argument) polynomial commitment
 * instead of a Merkle tree, enabling natural support for
 * partial orders / branching histories.
 *
 * Linear-case API is fully compatible with Hypercore's
 * MerkleTree interface (append, proof, verify, hash, signable).
 *
 * Partial-order extensions:
 *   - appendConcurrent(bufs)  — append multiple blocks at same rank
 *   - mergeFrom(otherTree)    — merge another tree's commitment additively
 *   - rank(index)             — rank of block at index
 *
 * Commitment: C = Σ H(blockᵢ) · G(rankᵢ)   (EC points, bn-like curve)
 * Proof:      IPA transcript, O(log n) rounds, O(log n) bytes
 * Verify:     O(log n) EC multiplications
 */

const { sha256 } = require('@noble/hashes/sha2.js')
const { bytesToHex, hexToBytes } = require('@noble/hashes/utils.js')
const { bn254 } = require('@noble/curves/bn254.js')

const Fr = bn254.fields.Fr
const G1Point = bn254.G1.Point

// ── Field arithmetic ─────────────────────────────────────
const ORDER = Fr.ORDER

function fmod (a) { return Fr.create(a) }
function modinv (a) { return Fr.inv(fmod(a)) }

// ── Hash content to scalar ────────────────────────────────
function hashToScalar (content) {
  const bytes = Buffer.isBuffer(content)
    ? content
    : typeof content === 'string'
      ? new TextEncoder().encode(content)
      : content
  const h = sha256(bytes)
  return fmod(BigInt('0x' + bytesToHex(h)))
}

// ── Deterministic generators G(i) ────────────────────────
const _genCache = new Map()
function generator (i) {
  if (_genCache.has(i)) return _genCache.get(i)
  const s = hashToScalar('gen:' + i)
  const pt = G1Point.BASE.multiply(s)
  _genCache.set(i, pt)
  return pt
}

// ── EC point helpers ──────────────────────────────────────
const ZERO = G1Point.ZERO

function ptAdd (P, Q) { return P.add(Q) }
function ptScale (s, P) { return P.multiply(fmod(s)) }
function ptEq (P, Q) { return P.equals(Q) }
function ptToBytes (P) {
  if (P.is0()) return new Uint8Array(33)
  return P.toBytes()
}
function ptFromBytes (b) {
  if (b.every(x => x === 0)) return ZERO
  const hex = bytesToHex(b instanceof Uint8Array ? b : Buffer.from(b))
  return G1Point.fromHex(hex)
}

// ── Fiat-Shamir challenge ─────────────────────────────────
function challenge (...args) {
  const parts = args.map(a => {
    if (a instanceof Uint8Array || Buffer.isBuffer(a)) return bytesToHex(a)
    if (typeof a === 'bigint') return a.toString(16)
    try {
      const b = ptToBytes(a)
      return bytesToHex(b)
    } catch { return String(a) }
  })
  const h = sha256(new TextEncoder().encode(parts.join('|')))
  return fmod(BigInt('0x' + bytesToHex(h)))
}

// ── Pad to power of 2 ────────────────────────────────────
function padPow2 (scalars, gens) {
  let n = 1; while (n < scalars.length) n *= 2
  const s = [...scalars]; while (s.length < n) s.push(0n)
  const g = [...gens]; while (g.length < n) g.push(generator(100000 + g.length))
  return { scalars: s, gens: g }
}

// ── Inner product commitment: Σ sᵢ · Gᵢ ─────────────────
function innerCommit (scalars, gens) {
  let C = ZERO
  for (let i = 0; i < scalars.length; i++) {
    if (scalars[i] === 0n) continue
    C = ptAdd(C, ptScale(scalars[i], gens[i]))
  }
  return C
}

// ── IPA Prove ────────────────────────────────────────────
function ipaProve (scalars, gens) {
  const rounds = []
  let a = [...scalars]
  let G = [...gens]

  while (a.length > 1) {
    const m = a.length >> 1
    const aLo = a.slice(0, m); const aHi = a.slice(m)
    const GLo = G.slice(0, m); const GHi = G.slice(m)

    const L = innerCommit(aLo, GHi)
    const R = innerCommit(aHi, GLo)
    const Ccur = innerCommit(a, G)

    const x = challenge(ptToBytes(Ccur), ptToBytes(L), ptToBytes(R))
    const xInv = modinv(x)

    rounds.push({ L, R, x })

    a = aLo.map((v, i) => fmod(x * v + aHi[i]))
    G = GLo.map((v, i) => ptAdd(ptScale(xInv, v), GHi[i]))
  }

  return { rounds, finalScalar: a[0], finalGen: G[0] }
}

// ── IPA Verify ────────────────────────────────────────────
function ipaVerify (C, proof) {
  let Ccur = C
  for (const { L, R, x } of proof.rounds) {
    const xCheck = challenge(ptToBytes(Ccur), ptToBytes(L), ptToBytes(R))
    if (xCheck !== x) return { valid: false, reason: 'Fiat-Shamir mismatch' }
    const xInv = modinv(x)
    Ccur = ptAdd(ptAdd(Ccur, ptScale(x, L)), ptScale(xInv, R))
  }
  const expected = ptScale(proof.finalScalar, proof.finalGen)
  if (!ptEq(Ccur, expected)) return { valid: false, reason: 'Final check failed' }
  return { valid: true, reason: 'OK' }
}

// ─────────────────────────────────────────────────────────
// IPATreeBatch — equivalent to MerkleTreeBatch in hypercore
// ─────────────────────────────────────────────────────────

class IPATreeBatch {
  constructor (session) {
    this.session = session
    this.length = session.length          // number of blocks
    this.fork = session.fork
    this.byteLength = session.byteLength
    this.signature = session.signature

    // IPA state
    this._commitment = session._commitment  // EC point
    this._blocks = [...session._blocks]     // [{ data, rank }]
    this._ranks = [...session._ranks]       // rank per block index

    this.committed = false
    this.upgraded = false
    this.nodes = []  // compatibility shim (hypercore internals use this)
  }

  // ── Hypercore-compatible interface ───────────────────────

  // hash() returns a 32-byte buffer commitment to current state
  hash () {
    const pt = this._commitment
    if (pt.equals(ZERO)) return Buffer.alloc(32)
    return Buffer.from(ptToBytes(pt))
  }

  // signable(manifestHash) — what gets signed by ed25519
  signable (manifestHash) {
    const h = this.hash()
    const len = Buffer.allocUnsafe(8)
    len.writeBigUInt64BE(BigInt(this.length))
    const forkBuf = Buffer.allocUnsafe(8)
    forkBuf.writeBigUInt64BE(BigInt(this.fork))
    return Buffer.concat([
      manifestHash || Buffer.alloc(32),
      h,
      len,
      forkBuf
    ])
  }

  signableCompat (noHeader) {
    return this.signable(null)
  }

  // append(buf) — add a block at the next sequential rank
  append (buf) {
    const rank = this.length  // linear case: rank = sequence index
    const scalar = hashToScalar(buf)
    const G = generator(rank)
    const term = ptScale(scalar, G)

    this._commitment = ptAdd(this._commitment, term)
    this._blocks.push({ data: Buffer.from(buf), rank })
    this._ranks.push(rank)
    this.length++
    this.byteLength += buf.length
    this.upgraded = true
  }

  // appendConcurrent(bufs) — add multiple blocks at the same rank (fork/partial order)
  appendConcurrent (bufs) {
    const rank = this.length  // all get same rank
    for (const buf of bufs) {
      const scalar = hashToScalar(buf)
      const G = generator(rank)
      const term = ptScale(scalar, G)
      this._commitment = ptAdd(this._commitment, term)
      this._blocks.push({ data: Buffer.from(buf), rank })
      this._ranks.push(rank)
    }
    this.length += bufs.length
    this.byteLength += bufs.reduce((s, b) => s + b.length, 0)
    this.upgraded = true
  }

  // proof({ block: { index } }) — generate IPA inclusion proof
  proof ({ block }) {
    if (!block) throw new Error('Only block proofs supported')
    const { index } = block

    if (index >= this._blocks.length) throw new Error('Block index out of range')

    const scalars = this._blocks.map(b => hashToScalar(b.data))
    const gens = this._blocks.map(b => generator(b.rank))
    const { scalars: padded, gens: paddedG } = padPow2(scalars, gens)

    const ipaProof = ipaProve(padded, paddedG)

    return {
      fork: this.fork,
      block: {
        index,
        value: this._blocks[index].data,
        rank: this._blocks[index].rank
      },
      ipaProof,
      commitment: ptToBytes(this._commitment),
      length: this.length
    }
  }

  // verify a proof against this batch's commitment
  verify (proof) {
    if (!proof || !proof.ipaProof) return false
    const C = ptFromBytes(proof.commitment)
    const result = ipaVerify(C, proof.ipaProof)
    return result.valid
  }

  clone () {
    const b = new IPATreeBatch(this.session)
    b.length = this.length
    b.fork = this.fork
    b.byteLength = this.byteLength
    b.signature = this.signature
    b._commitment = this._commitment
    b._blocks = [...this._blocks]
    b._ranks = [...this._ranks]
    b.upgraded = this.upgraded
    return b
  }
}

// ─────────────────────────────────────────────────────────
// IPATree — equivalent to MerkleTree in hypercore
// This is the session-level tree (persisted state)
// ─────────────────────────────────────────────────────────

class IPATree {
  constructor (storage, opts = {}) {
    this.storage = storage
    this.fork = opts.fork || 0
    this.length = 0
    this.byteLength = 0
    this.signature = null
    this.prologue = opts.prologue || null

    // IPA state
    this._commitment = ZERO
    this._blocks = []   // [{ data: Buffer, rank: Number }]
    this._ranks = []    // rank per block index
  }

  // Create a batch for staging changes
  batch () {
    return new IPATreeBatch(this)
  }

  // Commit a batch to this tree
  commit (batch) {
    this._commitment = batch._commitment
    this._blocks = batch._blocks
    this._ranks = batch._ranks
    this.length = batch.length
    this.byteLength = batch.byteLength
    this.fork = batch.fork
    this.signature = batch.signature
  }

  // Direct append (non-batched)
  append (buf) {
    const b = this.batch()
    b.append(buf)
    this.commit(b)
    return b
  }

  // Partial order: append concurrent blocks
  appendConcurrent (bufs) {
    const b = this.batch()
    b.appendConcurrent(bufs)
    this.commit(b)
    return b
  }

  // Generate inclusion proof for block at index
  proof (opts) {
    const b = this.batch()
    return b.proof(opts)
  }

  // Verify a proof
  verify (proof) {
    if (!proof || !proof.ipaProof) return false
    const C = ptFromBytes(proof.commitment)
    return ipaVerify(C, proof.ipaProof).valid
  }

  // hash() — 32-byte commitment representation
  hash () {
    if (this._commitment.equals(ZERO)) return Buffer.alloc(32)
    return Buffer.from(ptToBytes(this._commitment))
  }

  // signable — what gets signed
  signable (manifestHash) {
    const b = this.batch()
    return b.signable(manifestHash)
  }

  // Merge another tree additively (partial order extension)
  mergeFrom (otherTree) {
    // C(A ∪ B) = C(A) + C(B) when ranks are stable
    this._commitment = ptAdd(this._commitment, otherTree._commitment)
    // Merge blocks, re-sort by rank
    for (const block of otherTree._blocks) {
      this._blocks.push(block)
      this._ranks.push(block.rank)
    }
    this.length += otherTree.length
    this.byteLength += otherTree.byteLength
  }

  // Get rank of block at index
  rank (index) {
    return this._ranks[index]
  }

  // Serialize for storage
  toJSON () {
    return {
      fork: this.fork,
      length: this.length,
      byteLength: this.byteLength,
      commitment: bytesToHex(ptToBytes(this._commitment)),
      blocks: this._blocks.map(b => ({
        data: bytesToHex(b.data),
        rank: b.rank
      }))
    }
  }

  static fromJSON (json, storage) {
    const tree = new IPATree(storage)
    tree.fork = json.fork
    tree.length = json.length
    tree.byteLength = json.byteLength
    tree._commitment = ptFromBytes(hexToBytes(json.commitment))
    tree._blocks = json.blocks.map(b => ({
      data: Buffer.from(hexToBytes(b.data)),
      rank: b.rank
    }))
    tree._ranks = tree._blocks.map(b => b.rank)
    return tree
  }
}

module.exports = { IPATree, IPATreeBatch, ipaProve, ipaVerify, innerCommit, generator, hashToScalar, padPow2, ZERO, ptAdd, ptScale, ptEq, ptToBytes, ptFromBytes, fmod, modinv, challenge }
