'use strict'

const { sha256 } = require('@noble/hashes/sha2.js')
const { bytesToHex, hexToBytes } = require('@noble/hashes/utils.js')
const { bn254 } = require('@noble/curves/bn254.js')

const Fr = bn254.fields.Fr
const G1Point = bn254.G1.Point
const ZERO = G1Point.ZERO
const POINT_SIZE = 33

const DOMAIN_ENTRY = Buffer.from('hyperdag:entry:v1')
const DOMAIN_GENERATOR = Buffer.from('hyperdag:rank-generator:v1')
const DOMAIN_SCALAR = Buffer.from('hyperdag:scalar:v1')

function uint64be (n) {
  const b = Buffer.allocUnsafe(8)
  b.writeBigUInt64BE(BigInt(n))
  return b
}

function normalizeBytes (value, name = 'value') {
  if (Buffer.isBuffer(value)) return Buffer.from(value)
  if (value instanceof Uint8Array) return Buffer.from(value)
  if (typeof value === 'string') return Buffer.from(value)
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
  const input = Buffer.concat([domain, uint64be(bytes.length), bytes])
  return fmod(BigInt('0x' + bytesToHex(sha256(input))))
}

function hashEntry (value) {
  return hashToScalar(value, DOMAIN_ENTRY)
}

const genCache = new Map()

function generator (rank) {
  validateRank(rank)
  const cached = genCache.get(rank)
  if (cached) return cached

  const seed = hashToScalar(uint64be(rank), DOMAIN_GENERATOR)
  const point = G1Point.BASE.multiply(seed)
  genCache.set(rank, point)
  return point
}

function ptAdd (P, Q) {
  return P.add(Q)
}

function ptScale (s, P) {
  return P.multiply(fmod(s))
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
  return G1Point.fromHex(bytesToHex(b))
}

function entryKey (bytes) {
  return bytesToHex(bytes)
}

function stateCommitment (state) {
  if (Buffer.isBuffer(state) || state instanceof Uint8Array) {
    return { commitment: Buffer.from(state) }
  }
  if (!state || !state.commitment) throw new Error('expected state must include a commitment')
  return {
    commitment: Buffer.from(state.commitment),
    maxRank: state.maxRank,
    entryCount: state.entryCount,
    byteLength: state.byteLength
  }
}

function sameBytes (a, b) {
  return Buffer.from(a).equals(Buffer.from(b))
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

class RankedLog {
  constructor (opts = {}) {
    this._layers = new Map()
    this._commitment = ZERO
    this.maxRank = 0
    this.entryCount = 0
    this.byteLength = 0

    if (opts.entries) {
      for (const entry of opts.entries) {
        this.addAtRank(entry.rank, entry.value)
      }
    }
  }

  append (value) {
    return this.addAtRank(this.maxRank + 1, value)
  }

  appendLayer (values) {
    if (!Array.isArray(values)) throw new TypeError('values must be an array')
    const rank = this.maxRank + 1
    const added = []

    for (const value of values) {
      const entry = this.addAtRank(rank, value)
      if (entry.added) added.push(entry)
    }

    return { rank, added }
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
      return { rank, value: Buffer.from(layer.get(key)), added: false }
    }

    layer.set(key, bytes)
    this.maxRank = Math.max(this.maxRank, rank)
    this.entryCount++
    this.byteLength += bytes.length
    this._commitment = commitmentForEntries(this.entries())

    return { rank, value: Buffer.from(bytes), added: true }
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
      .map(([, value]) => Buffer.from(value))
  }

  entries () {
    return [...this._layers.keys()]
      .sort((a, b) => a - b)
      .flatMap(rank => this.layer(rank).map(value => ({ rank, value })))
  }

  merge (other) {
    const entries = other instanceof RankedLog ? other.entries() : other.entries
    if (!Array.isArray(entries)) throw new TypeError('merge target must expose entries')

    for (const entry of entries) {
      this.addAtRank(entry.rank, entry.value)
    }

    return this
  }

  clone () {
    return new RankedLog({ entries: this.entries() })
  }

  commitmentPoint () {
    return this._commitment
  }

  commitment () {
    return Buffer.from(ptToBytes(this._commitment))
  }

  state () {
    return {
      commitment: this.commitment(),
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

    return {
      type: 'hyperdag-entry-proof-v1',
      rank,
      value: Buffer.from(target),
      layers: this._proofLayers(),
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
      }))
    }
  }

  _proofLayers () {
    return [...this._layers.keys()]
      .sort((a, b) => a - b)
      .map(rank => ({
        rank,
        values: this.layer(rank)
      }))
  }

  static fromJSON (json) {
    const log = new RankedLog({
      entries: json.entries.map(entry => ({
        rank: entry.rank,
        value: Buffer.from(hexToBytes(entry.value))
      }))
    })

    const expected = json.commitment && Buffer.from(hexToBytes(json.commitment))
    if (expected && !log.commitment().equals(expected)) {
      throw new Error('serialized commitment does not match entries')
    }

    return log
  }

  static fromProof (proof) {
    if (!proof || proof.type !== 'hyperdag-entry-proof-v1') {
      throw new Error('unsupported proof')
    }

    const log = new RankedLog()

    if (!Array.isArray(proof.layers)) throw new Error('proof layers must be an array')

    for (const layer of proof.layers) {
      const rank = validateRank(layer.rank)
      if (!Array.isArray(layer.values)) throw new Error('proof layer values must be an array')

      for (const value of layer.values) {
        log.addAtRank(rank, value)
      }
    }

    return log
  }

  static verifyEntry (expectedState, proof) {
    try {
      const expected = stateCommitment(expectedState)
      const rank = validateRank(proof.rank)
      const value = normalizeBytes(proof.value)
      const log = RankedLog.fromProof(proof)
      const actual = log.state()

      if (!actual.commitment.equals(expected.commitment)) {
        return { valid: false, reason: 'commitment mismatch' }
      }
      if (expected.maxRank !== undefined && actual.maxRank !== expected.maxRank) {
        return { valid: false, reason: 'maxRank mismatch' }
      }
      if (expected.entryCount !== undefined && actual.entryCount !== expected.entryCount) {
        return { valid: false, reason: 'entryCount mismatch' }
      }
      if (expected.byteLength !== undefined && actual.byteLength !== expected.byteLength) {
        return { valid: false, reason: 'byteLength mismatch' }
      }
      if (!log.has(rank, value)) {
        return { valid: false, reason: 'entry missing from proof witness' }
      }

      return { valid: true, reason: 'OK' }
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
  entryKey,
  fmod,
  generator,
  hashEntry,
  hashToScalar,
  modinv,
  normalizeBytes,
  ptAdd,
  ptEq,
  ptFromBytes,
  ptScale,
  ptToBytes,
  sameBytes,
  layerScalar,
  termForEntry,
  termForLayer
}
