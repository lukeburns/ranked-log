'use strict'

const { sha256 } = require('@noble/hashes/sha2.js')
const { bytesToHex, hexToBytes } = require('@noble/hashes/utils.js')
const { ristretto255 } = require('@noble/curves/ed25519.js')
const b4a = require('b4a')

const Point = ristretto255.Point
const Fr = Point.Fn
const ZERO = Point.ZERO
const POINT_SIZE = 32

const DOMAIN_ENTRY = b4a.from('hyperdag:entry:v1')
const DOMAIN_GENERATOR = b4a.from('hyperdag:coordinate-generator:v1')
const DOMAIN_INNER_PRODUCT = b4a.from('hyperdag:inner-product-generator:v1')
const DOMAIN_SCALAR = b4a.from('hyperdag:scalar:v1')
const DOMAIN_CHALLENGE = b4a.from('hyperdag:challenge:v1')
const DOMAIN_EDGE = b4a.from('hyperdag:edge:v1')

function uint64be (n) {
  const b = b4a.allocUnsafe(8)
  b.writeBigUInt64BE(BigInt(n))
  return b
}

function normalizeBytes (value, name = 'value') {
  if (b4a.isBuffer(value)) return b4a.from(value)
  if (value instanceof Uint8Array) return b4a.from(value)
  if (typeof value === 'string') return b4a.from(value)
  throw new TypeError(`${name} must be a Buffer, Uint8Array, or string`)
}

function validateRank (rank) {
  if (!Number.isSafeInteger(rank) || rank <= 0) {
    throw new RangeError('rank must be a positive safe integer')
  }
  return rank
}

function fmod (a) {
  return Fr.create(a)
}

function modinv (a) {
  return Fr.inv(fmod(a))
}

function hashToScalar (value, domain = DOMAIN_SCALAR) {
  const bytes = normalizeBytes(value)
  const input = b4a.concat([domain, uint64be(bytes.length), bytes])
  return fmod(BigInt('0x' + bytesToHex(sha256(input))))
}

function hashEntry (value) {
  return hashToScalar(value, DOMAIN_ENTRY)
}

const genCache = new Map()
let innerProductGenerator = null

function coordinateKey (i, j) {
  return `${i},${j}`
}

function coordinateGenerator (i, j) {
  i = validateRank(i)
  j = validateRank(j)

  const key = coordinateKey(i, j)
  const cached = genCache.get(key)
  if (cached) return cached

  const seed = hashToScalar(b4a.concat([uint64be(i), uint64be(j)]), DOMAIN_GENERATOR)
  const point = Point.BASE.multiply(seed)
  genCache.set(key, point)
  return point
}

function generator (rank) {
  validateRank(rank)
  return coordinateGenerator(rank, rank)
}

function ipaGenerator () {
  if (innerProductGenerator) return innerProductGenerator
  innerProductGenerator = Point.BASE.multiply(hashToScalar('u', DOMAIN_INNER_PRODUCT))
  return innerProductGenerator
}

function ptAdd (P, Q) {
  return P.add(Q)
}

function ptScale (s, P) {
  const scalar = fmod(s)
  return scalar === 0n ? ZERO : P.multiply(scalar)
}

function ptEq (P, Q) {
  return P.equals(Q)
}

function ptToBytes (P) {
  if (P.equals(ZERO)) return new Uint8Array(POINT_SIZE)
  return P.toBytes()
}

function ptFromBytes (bytes) {
  const b = normalizeBytes(bytes, 'point')
  if (b.length !== POINT_SIZE) throw new Error(`point must be ${POINT_SIZE} bytes`)
  if (b.every(byte => byte === 0)) return ZERO
  return Point.fromHex(bytesToHex(b))
}

function entryKey (bytes) {
  return bytesToHex(bytes)
}

function edgeKey (fromRank, from, toRank, to) {
  return `${fromRank}:${entryKey(from)}>${toRank}:${entryKey(to)}`
}

function challenge (...args) {
  const parts = [DOMAIN_CHALLENGE]

  for (const arg of args) {
    if (typeof arg === 'bigint') {
      parts.push(b4a.from('bigint'))
      parts.push(b4a.from(arg.toString(16)))
    } else if (typeof arg === 'number') {
      parts.push(b4a.from('number'))
      parts.push(uint64be(arg))
    } else if (arg && typeof arg.toBytes === 'function') {
      const bytes = b4a.from(ptToBytes(arg))
      parts.push(b4a.from('point'))
      parts.push(uint64be(bytes.length))
      parts.push(bytes)
    } else {
      const bytes = normalizeBytes(arg, 'challenge argument')
      parts.push(b4a.from('bytes'))
      parts.push(uint64be(bytes.length))
      parts.push(bytes)
    }
  }

  const scalar = fmod(BigInt('0x' + bytesToHex(sha256(b4a.concat(parts)))))
  return scalar === 0n ? 1n : scalar
}

function stateCommitment (state) {
  if (b4a.isBuffer(state) || state instanceof Uint8Array) {
    return { commitment: b4a.from(state) }
  }
  if (!state || !state.commitment) throw new Error('expected state must include a commitment')
  return {
    commitment: b4a.from(state.commitment),
    rankCommitment: state.rankCommitment && b4a.from(state.rankCommitment),
    vertexCommitment: state.vertexCommitment && b4a.from(state.vertexCommitment),
    edgeCommitment: state.edgeCommitment && b4a.from(state.edgeCommitment),
    transitionCommitment: state.transitionCommitment && b4a.from(state.transitionCommitment),
    maxRank: state.maxRank,
    entryCount: state.entryCount,
    byteLength: state.byteLength
  }
}

function sameBytes (a, b) {
  return b4a.from(a).equals(b4a.from(b))
}

function termForEntry (rank, value) {
  return ptScale(hashEntry(value), generator(rank))
}

function layerScalar (values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error('layer must contain at least one entry')
  }

  const unique = new Map()
  for (const value of values) {
    const bytes = normalizeBytes(value)
    unique.set(entryKey(bytes), bytes)
  }

  let sum = 0n
  for (const value of unique.values()) {
    sum = fmod(sum + hashEntry(value))
  }

  return fmod(sum * modinv(BigInt(unique.size)))
}

function termForLayer (rank, values) {
  return ptScale(layerScalar(values), generator(rank))
}

function edgeScalar ({ fromRank, from, toRank, to }) {
  fromRank = validateRank(fromRank)
  toRank = validateRank(toRank)
  if (toRank <= fromRank) throw new Error('edge must point to a later rank')
  from = normalizeBytes(from, 'from')
  to = normalizeBytes(to, 'to')

  return hashToScalar(
    b4a.concat([
      uint64be(fromRank),
      uint64be(from.length),
      from,
      uint64be(toRank),
      uint64be(to.length),
      to
    ]),
    DOMAIN_EDGE
  )
}

function edgeLayerScalar (edges) {
  if (!Array.isArray(edges) || edges.length === 0) {
    throw new Error('edge bucket must contain at least one edge')
  }

  const unique = new Map()
  for (const edge of edges) {
    const from = normalizeBytes(edge.from, 'from')
    const to = normalizeBytes(edge.to, 'to')
    const fromRank = validateRank(edge.fromRank)
    const toRank = validateRank(edge.toRank)
    unique.set(edgeKey(fromRank, from, toRank, to), { fromRank, from, toRank, to })
  }

  let sum = 0n
  for (const edge of unique.values()) {
    sum = fmod(sum + edgeScalar(edge))
  }

  return fmod(sum * modinv(BigInt(unique.size)))
}

function termForEdgeBucket (fromRank, toRank, edges) {
  fromRank = validateRank(fromRank)
  toRank = validateRank(toRank)
  if (toRank <= fromRank) throw new Error('edge bucket must point to a later rank')
  if (!Array.isArray(edges)) throw new Error('edge bucket must contain at least one edge')
  for (const edge of edges) {
    if (validateRank(edge.fromRank) !== fromRank || validateRank(edge.toRank) !== toRank) {
      throw new Error('edge does not belong to bucket')
    }
  }
  return ptScale(edgeLayerScalar(edges), coordinateGenerator(fromRank, toRank))
}

function layerAdjustment (rank, selected, complements) {
  selected = normalizeBytes(selected, 'selected')
  if (!Array.isArray(complements)) throw new TypeError('complements must be an array')

  const values = [selected]
  for (const complement of complements) values.push(normalizeBytes(complement, 'complement'))

  const unique = new Map()
  for (const value of values) unique.set(entryKey(value), value)

  if (!unique.has(entryKey(selected))) throw new Error('selected value missing from layer')
  if (unique.size !== values.length) throw new Error('layer adjustment contains duplicate entries')

  const avg = layerScalar([...unique.values()])
  const delta = fmod(avg - hashEntry(selected))

  return {
    rank: validateRank(rank),
    multiplicity: unique.size,
    delta,
    term: ptScale(delta, generator(rank))
  }
}

function innerProduct (a, b) {
  let sum = 0n
  for (let i = 0; i < a.length; i++) {
    sum = fmod(sum + fmod(a[i]) * fmod(b[i]))
  }
  return sum
}

function innerCommit (scalars, gens) {
  let commitment = ZERO
  for (let i = 0; i < scalars.length; i++) {
    if (scalars[i] === 0n) continue
    commitment = ptAdd(commitment, ptScale(scalars[i], gens[i]))
  }
  return commitment
}

function nextPow2 (n) {
  let p = 1
  while (p < n) p *= 2
  return p
}

function vectorLength (maxRank) {
  return nextPow2(Math.max(1, maxRank))
}

function rankGenerators (length) {
  const gens = []
  for (let rank = 1; rank <= length; rank++) gens.push(generator(rank))
  return gens
}

function rankBasis (rank, length) {
  const basis = new Array(length).fill(0n)
  basis[rank - 1] = 1n
  return basis
}

function vectorScalarsFromLayers (layers, maxRank) {
  const scalars = new Array(vectorLength(maxRank)).fill(0n)

  for (const [rank, layer] of layers) {
    scalars[rank - 1] = layerScalar([...layer.values()])
  }

  return scalars
}

function ipaProveOpening (commitment, scalars, rank, valueScalar) {
  const length = scalars.length
  let a = scalars.slice()
  let b = rankBasis(rank, length)
  let G = rankGenerators(length)
  let P = ptAdd(commitment, ptScale(valueScalar, ipaGenerator()))
  const rounds = []

  while (a.length > 1) {
    const half = a.length >> 1
    const aLo = a.slice(0, half)
    const aHi = a.slice(half)
    const bLo = b.slice(0, half)
    const bHi = b.slice(half)
    const GLo = G.slice(0, half)
    const GHi = G.slice(half)
    const U = ipaGenerator()

    const L = ptAdd(innerCommit(aLo, GHi), ptScale(innerProduct(aLo, bHi), U))
    const R = ptAdd(innerCommit(aHi, GLo), ptScale(innerProduct(aHi, bLo), U))
    const x = challenge(P, L, R)
    const xInv = modinv(x)

    rounds.push({ L, R })

    P = ptAdd(ptAdd(P, ptScale(x, L)), ptScale(xInv, R))
    a = aLo.map((v, i) => fmod(x * v + aHi[i]))
    b = bLo.map((v, i) => fmod(xInv * v + bHi[i]))
    G = GLo.map((v, i) => ptAdd(ptScale(xInv, v), GHi[i]))
  }

  return {
    length,
    rounds,
    finalScalar: a[0]
  }
}

function ipaVerifyOpening (commitment, rank, valueScalar, proof) {
  if (!proof || !Number.isSafeInteger(proof.length) || proof.length < 1) {
    return { valid: false, reason: 'invalid IPA proof length' }
  }
  if (proof.length !== vectorLength(proof.maxRank)) {
    return { valid: false, reason: 'invalid IPA proof dimension' }
  }
  if (rank > proof.maxRank || rank < 1) {
    return { valid: false, reason: 'rank outside proof dimension' }
  }

  let b = rankBasis(rank, proof.length)
  let G = rankGenerators(proof.length)
  let P = ptAdd(commitment, ptScale(valueScalar, ipaGenerator()))

  for (const round of proof.rounds) {
    if (G.length <= 1 || G.length % 2 !== 0) {
      return { valid: false, reason: 'invalid IPA round count' }
    }

    const half = G.length >> 1
    const bLo = b.slice(0, half)
    const bHi = b.slice(half)
    const GLo = G.slice(0, half)
    const GHi = G.slice(half)
    const x = challenge(P, round.L, round.R)
    const xInv = modinv(x)

    P = ptAdd(ptAdd(P, ptScale(x, round.L)), ptScale(xInv, round.R))
    b = bLo.map((v, i) => fmod(xInv * v + bHi[i]))
    G = GLo.map((v, i) => ptAdd(ptScale(xInv, v), GHi[i]))
  }

  if (G.length !== 1) return { valid: false, reason: 'incomplete IPA proof' }

  const expected = ptAdd(
    ptScale(proof.finalScalar, G[0]),
    ptScale(fmod(proof.finalScalar * b[0]), ipaGenerator())
  )

  if (!ptEq(P, expected)) return { valid: false, reason: 'IPA final check failed' }

  return { valid: true, reason: 'OK' }
}

function commitmentForEntries (entries) {
  const layers = new Map()

  for (const entry of entries) {
    const rank = validateRank(entry.rank)
    const bytes = normalizeBytes(entry.value)
    const key = entryKey(bytes)
    let layer = layers.get(rank)

    if (!layer) {
      layer = new Map()
      layers.set(rank, layer)
    }

    layer.set(key, bytes)
  }

  let commitment = ZERO

  for (const rank of [...layers.keys()].sort((a, b) => a - b)) {
    commitment = ptAdd(commitment, termForLayer(rank, [...layers.get(rank).values()]))
  }

  return commitment
}

function commitmentForEdges (edges) {
  const buckets = new Map()

  for (const edge of edges) {
    const from = normalizeBytes(edge.from, 'from')
    const to = normalizeBytes(edge.to, 'to')
    const fromRank = validateRank(edge.fromRank)
    const toRank = validateRank(edge.toRank)
    if (toRank <= fromRank) throw new Error('edge must point to a later rank')

    const bucketKey = coordinateKey(fromRank, toRank)
    let bucket = buckets.get(bucketKey)
    if (!bucket) {
      bucket = { fromRank, toRank, edges: new Map() }
      buckets.set(bucketKey, bucket)
    }

    bucket.edges.set(edgeKey(fromRank, from, toRank, to), { fromRank, from, toRank, to })
  }

  let commitment = ZERO

  for (const bucket of [...buckets.values()].sort((a, b) => {
    if (a.fromRank !== b.fromRank) return a.fromRank - b.fromRank
    return a.toRank - b.toRank
  })) {
    commitment = ptAdd(commitment, termForEdgeBucket(bucket.fromRank, bucket.toRank, [...bucket.edges.values()]))
  }

  return commitment
}

class RankedLog {
  constructor (opts = {}) {
    this._layers = new Map()
    this._vertexCommitment = ZERO
    this._edgeCommitment = ZERO
    this._edges = new Map()
    this._frontier = []
    this.maxRank = 0
    this.entryCount = 0
    this.byteLength = 0

    if (opts.entries) {
      for (const entry of opts.entries) {
        this.addAtRank(entry.rank, entry.value)
      }
    }
    const edges = opts.edges || opts.transitions
    if (edges) {
      for (const edge of edges) {
        this.addEdge(edge.fromRank, edge.from, edge.toRank, edge.to)
      }
    }
  }

  append (value) {
    const previous = this._frontier
    const rank = this.maxRank + 1
    const entry = this.addAtRank(rank, value)

    this._connect(previous, [entry])
    this._frontier = [{ rank, value: b4a.from(entry.value) }]

    return entry
  }

  appendLayer (values) {
    if (!Array.isArray(values)) throw new TypeError('values must be an array')
    const previous = this._frontier
    const rank = this.maxRank + 1
    const added = []

    for (const value of values) {
      const entry = this.addAtRank(rank, value)
      if (entry.added) added.push(entry)
    }

    this._connect(previous, added)
    this._frontier = this.layer(rank).map(value => ({ rank, value }))

    return { rank, added }
  }

  addBranch (values, startRank = 1) {
    if (!Array.isArray(values)) throw new TypeError('values must be an array')
    startRank = validateRank(startRank)

    const entries = values.map((value, i) => {
      const rank = startRank + i
      return this.addAtRank(rank, value)
    })

    for (let i = 1; i < entries.length; i++) {
      this.addEdge(entries[i - 1].rank, entries[i - 1].value, entries[i].rank, entries[i].value)
    }

    return entries
  }

  addAtRank (rank, value) {
    rank = validateRank(rank)
    const bytes = normalizeBytes(value)
    const key = entryKey(bytes)
    let layer = this._layers.get(rank)

    if (!layer) {
      layer = new Map()
      this._layers.set(rank, layer)
    }

    if (layer.has(key)) {
      return { rank, value: b4a.from(layer.get(key)), added: false }
    }

    layer.set(key, bytes)
    this.maxRank = Math.max(this.maxRank, rank)
    this.entryCount++
    this.byteLength += bytes.length
    this._recomputeCommitments()

    return { rank, value: b4a.from(bytes), added: true }
  }

  addVertex (rank, value) {
    return this.addAtRank(rank, value)
  }

  addEdge (fromRank, from, toRank, to) {
    fromRank = validateRank(fromRank)
    toRank = validateRank(toRank)
    if (toRank <= fromRank) throw new Error('edge must point to a later rank')

    from = normalizeBytes(from, 'from')
    to = normalizeBytes(to, 'to')

    if (!this.has(fromRank, from)) this.addAtRank(fromRank, from)
    if (!this.has(toRank, to)) this.addAtRank(toRank, to)

    const bucketKey = coordinateKey(fromRank, toRank)
    let bucket = this._edges.get(bucketKey)
    if (!bucket) {
      bucket = { fromRank, toRank, edges: new Map() }
      this._edges.set(bucketKey, bucket)
    }

    const key = edgeKey(fromRank, from, toRank, to)
    if (bucket.edges.has(key)) return { ...bucket.edges.get(key), added: false }

    const edge = { fromRank, from: b4a.from(from), toRank, to: b4a.from(to) }
    bucket.edges.set(key, edge)
    this._recomputeCommitments()

    return { ...edge, added: true }
  }

  addTransition (fromRank, from, toRank, to) {
    return this.addEdge(fromRank, from, toRank, to)
  }

  has (rank, value) {
    rank = validateRank(rank)
    const layer = this._layers.get(rank)
    return !!layer && layer.has(entryKey(normalizeBytes(value)))
  }

  layer (rank) {
    rank = validateRank(rank)
    const layer = this._layers.get(rank)
    if (!layer) return []
    return [...layer.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([, value]) => b4a.from(value))
  }

  entries () {
    return [...this._layers.keys()]
      .sort((a, b) => a - b)
      .flatMap(rank => this.layer(rank).map(value => ({ rank, value })))
  }

  vertices () {
    return this.entries()
  }

  edges () {
    return [...this._edges.values()]
      .sort((a, b) => {
        if (a.fromRank !== b.fromRank) return a.fromRank - b.fromRank
        return a.toRank - b.toRank
      })
      .flatMap(bucket => [...bucket.edges.values()]
        .sort((a, b) => edgeKey(a.fromRank, a.from, a.toRank, a.to)
          .localeCompare(edgeKey(b.fromRank, b.from, b.toRank, b.to)))
        .map(edge => ({
          fromRank: edge.fromRank,
          from: b4a.from(edge.from),
          toRank: edge.toRank,
          to: b4a.from(edge.to)
        })))
  }

  transitions () {
    return this.edges()
  }

  merge (other) {
    const entries = other instanceof RankedLog ? other.entries() : other.entries
    if (!Array.isArray(entries)) throw new TypeError('merge target must expose entries')

    for (const entry of entries) {
      this.addAtRank(entry.rank, entry.value)
    }

    const edges = other instanceof RankedLog ? other.edges() : (other.edges || other.transitions)
    if (edges) {
      if (!Array.isArray(edges)) throw new TypeError('merge edges must be an array')
      for (const edge of edges) {
        this.addEdge(edge.fromRank, edge.from, edge.toRank, edge.to)
      }
    }

    return this
  }

  clone () {
    return new RankedLog({ entries: this.entries(), edges: this.edges() })
  }

  commitmentPoint () {
    return ptAdd(this._vertexCommitment, this._edgeCommitment)
  }

  vertexCommitmentPoint () {
    return this._vertexCommitment
  }

  rankCommitmentPoint () {
    return this.vertexCommitmentPoint()
  }

  edgeCommitmentPoint () {
    return this._edgeCommitment
  }

  transitionCommitmentPoint () {
    return this.edgeCommitmentPoint()
  }

  commitment () {
    return b4a.from(ptToBytes(this.commitmentPoint()))
  }

  vertexCommitment () {
    return b4a.from(ptToBytes(this._vertexCommitment))
  }

  rankCommitment () {
    return this.vertexCommitment()
  }

  edgeCommitment () {
    return b4a.from(ptToBytes(this._edgeCommitment))
  }

  transitionCommitment () {
    return this.edgeCommitment()
  }

  state () {
    return {
      commitment: this.commitment(),
      rankCommitment: this.rankCommitment(),
      vertexCommitment: this.vertexCommitment(),
      edgeCommitment: this.edgeCommitment(),
      transitionCommitment: this.edgeCommitment(),
      maxRank: this.maxRank,
      entryCount: this.entryCount,
      byteLength: this.byteLength
    }
  }

  proveEntry ({ rank, value, bytes }) {
    const target = normalizeBytes(value === undefined ? bytes : value)
    rank = validateRank(rank)

    if (!this.has(rank, target)) {
      throw new Error('entry is not present in ranked log')
    }

    const valueScalar = hashEntry(target)
    const scalars = vectorScalarsFromLayers(this._layers, this.maxRank)
    const layer = this.layer(rank)
    const complements = layer.filter(entry => !sameBytes(entry, target))
    const adjustments = []

    if (complements.length > 0) {
      const adjustment = layerAdjustment(rank, target, complements)
      scalars[rank - 1] = valueScalar
      adjustments.push({
        rank,
        selected: b4a.from(target),
        complements,
        multiplicity: adjustment.multiplicity
      })
    }

    const branchCommitment = innerCommit(scalars, rankGenerators(scalars.length))
    const opening = ipaProveOpening(branchCommitment, scalars, rank, valueScalar)

    return {
      type: 'hyperdag-entry-proof-v1',
      rank,
      value: b4a.from(target),
      maxRank: this.maxRank,
      adjustments,
      opening,
      state: this.state()
    }
  }

  verifyEntry (proof) {
    return RankedLog.verifyEntry(this.state(), proof)
  }

  toJSON () {
    return {
      maxRank: this.maxRank,
      entryCount: this.entryCount,
      byteLength: this.byteLength,
      commitment: bytesToHex(this.commitment()),
      entries: this.entries().map(entry => ({
        rank: entry.rank,
        value: bytesToHex(entry.value)
      })),
      edges: this.edges().map(edge => ({
        fromRank: edge.fromRank,
        from: bytesToHex(edge.from),
        toRank: edge.toRank,
        to: bytesToHex(edge.to)
      }))
    }
  }

  _connect (fromEntries, toEntries) {
    if (!fromEntries.length || !toEntries.length) return

    for (const from of fromEntries) {
      for (const to of toEntries) {
        this.addEdge(from.rank, from.value, to.rank, to.value)
      }
    }
  }

  _recomputeCommitments () {
    this._vertexCommitment = commitmentForEntries(this.entries())
    this._edgeCommitment = commitmentForEdges(this.edges())
  }

  static fromJSON (json) {
    const log = new RankedLog({
      entries: json.entries.map(entry => ({
        rank: entry.rank,
        value: b4a.from(hexToBytes(entry.value))
      })),
      edges: (json.edges || json.transitions || []).map(edge => ({
        fromRank: edge.fromRank,
        from: b4a.from(hexToBytes(edge.from)),
        toRank: edge.toRank,
        to: b4a.from(hexToBytes(edge.to))
      }))
    })

    const expected = json.commitment && b4a.from(hexToBytes(json.commitment))
    if (expected && !log.commitment().equals(expected)) {
      throw new Error('serialized commitment does not match entries')
    }

    return log
  }

  static fromProof (proof) {
    throw new Error('proof witnesses are not materialized by linear IPA proofs')
  }

  static verifyEntry (expectedState, proof) {
    try {
      const expected = stateCommitment(expectedState)
      if (!proof || proof.type !== 'hyperdag-entry-proof-v1') {
        return { valid: false, reason: 'unsupported proof' }
      }

      const rank = validateRank(proof.rank)
      const value = normalizeBytes(proof.value)
      const maxRank = proof.maxRank

      if (!Number.isSafeInteger(maxRank) || maxRank < 1) {
        return { valid: false, reason: 'invalid proof maxRank' }
      }

      if (expected.maxRank !== undefined && maxRank !== expected.maxRank) {
        return { valid: false, reason: 'maxRank mismatch' }
      }

      const vertexCommitment = expected.vertexCommitment || expected.rankCommitment
      const edgeCommitment = expected.edgeCommitment || expected.transitionCommitment

      if (vertexCommitment && edgeCommitment) {
        const combined = ptAdd(ptFromBytes(vertexCommitment), ptFromBytes(edgeCommitment))
        if (!b4a.from(ptToBytes(combined)).equals(expected.commitment)) {
          return { valid: false, reason: 'state commitment mismatch' }
        }
      }

      let branchCommitment = ptFromBytes(vertexCommitment || expected.commitment)
      const adjustments = proof.adjustments || []
      if (!Array.isArray(adjustments)) return { valid: false, reason: 'invalid adjustments' }

      for (const adjustment of adjustments) {
        const adjustmentRank = validateRank(adjustment.rank)
        const selected = normalizeBytes(adjustment.selected, 'selected')
        const complements = adjustment.complements || []
        const computed = layerAdjustment(adjustmentRank, selected, complements)

        if (computed.multiplicity !== adjustment.multiplicity) {
          return { valid: false, reason: 'multiplicity mismatch' }
        }
        if (adjustmentRank === rank && !sameBytes(selected, value)) {
          return { valid: false, reason: 'target adjustment mismatch' }
        }

        branchCommitment = ptAdd(branchCommitment, ptScale(-1n, computed.term))
      }

      return ipaVerifyOpening(
        branchCommitment,
        rank,
        hashEntry(value),
        { ...proof.opening, maxRank }
      )
    } catch (err) {
      return { valid: false, reason: err.message }
    }
  }
}

module.exports = {
  RankedLog,
  ZERO,
  POINT_SIZE,
  commitmentForEntries,
  commitmentForEdges,
  challenge,
  coordinateGenerator,
  entryKey,
  edgeKey,
  edgeScalar,
  edgeLayerScalar,
  fmod,
  generator,
  hashEntry,
  hashToScalar,
  innerCommit,
  innerProduct,
  ipaProveOpening,
  ipaVerifyOpening,
  modinv,
  normalizeBytes,
  ptAdd,
  ptEq,
  ptFromBytes,
  ptScale,
  ptToBytes,
  sameBytes,
  layerScalar,
  layerAdjustment,
  termForEntry,
  termForLayer,
  termForEdgeBucket,
  transitionKey: edgeKey,
  transitionScalar: edgeScalar,
  transitionLayerScalar: edgeLayerScalar,
  termForTransitionLayer: termForEdgeBucket
}
