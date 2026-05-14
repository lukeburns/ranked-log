'use strict'

const assert = require('assert')
const { CausalLog } = require('.')

function rng (seed) {
  let state = seed >>> 0
  return function random () {
    state = (1664525 * state + 1013904223) >>> 0
    return state / 0x100000000
  }
}

function sample (random, values) {
  return values[Math.floor(random() * values.length)]
}

function generateCausalLog ({
  seed = 0xdecafbad,
  ranks = 24,
  minWidth = 3,
  maxWidth = 9,
  parentWindow = 4,
  parentsPerVertex = 2,
  extraEdgeProbability = 0.08
} = {}) {
  const random = rng(seed)
  const log = new CausalLog()
  const layers = []

  for (let rank = 1; rank <= ranks; rank++) {
    const width = minWidth + Math.floor(random() * (maxWidth - minWidth + 1))
    const layer = []

    for (let i = 0; i < width; i++) {
      const value = `r${rank}:v${i}:${Math.floor(random() * 1e9).toString(36)}`
      const vertex = log.addVertex(rank, value)
      layer.push(vertex)
    }

    layers.push(layer)
  }

  for (let rank = 2; rank <= ranks; rank++) {
    const layer = layers[rank - 1]
    const candidateParents = layers
      .slice(Math.max(0, rank - parentWindow - 1), rank - 1)
      .flat()

    for (const vertex of layer) {
      const selected = new Set()
      while (selected.size < parentsPerVertex && selected.size < candidateParents.length) {
        selected.add(sample(random, candidateParents))
      }

      for (const parent of selected) {
        log.addEdge(parent.rank, parent.value, vertex.rank, vertex.value)
      }
    }
  }

  for (let fromRank = 1; fromRank < ranks; fromRank++) {
    for (let toRank = fromRank + 1; toRank <= Math.min(ranks, fromRank + parentWindow); toRank++) {
      for (const from of layers[fromRank - 1]) {
        for (const to of layers[toRank - 1]) {
          if (random() < extraEdgeProbability) log.addEdge(from.rank, from.value, to.rank, to.value)
        }
      }
    }
  }

  return { log, layers }
}

const log = new CausalLog()

log.append('a')
log.appendLayer(['b', 'c'])
log.append('d')

const vertexProof = log.proveVertex({ rank: 2, value: 'b' })
const edgeProof = log.proveEdge({ fromRank: 2, from: 'b', toRank: 3, to: 'd' })

assert.deepEqual(CausalLog.verifyVertex(log.state(), vertexProof), { valid: true, reason: 'OK' })
assert.deepEqual(CausalLog.verifyEdge(log.state(), edgeProof), { valid: true, reason: 'OK' })

const branchB = new CausalLog()
branchB.addBranch(['a', 'b', 'd'])

const branchC = new CausalLog()
branchC.addBranch(['a', 'c', 'd'])

const merged = branchB.clone().merge(branchC)

assert(merged.commitment().equals(log.commitment()))

console.log('commitment:', log.commitment().toString('hex'))
console.log('vertices:', log.vertices().map(vertex => `${vertex.rank}:${vertex.value.toString()}`))
console.log('edges:', log.edges().map(edge => `${edge.from.toString()} -> ${edge.to.toString()}`))
const vertexVerification = CausalLog.verifyVertex(log.state(), vertexProof)
const edgeVerification = CausalLog.verifyEdge(log.state(), edgeProof)
console.log('vertex proof:', vertexVerification)
console.log('edge proof:', edgeVerification)

console.log('\nlarge random causal log')
console.time('generate')
const { log: largeLog, layers } = generateCausalLog()
console.timeEnd('generate')
const vertices = largeLog.vertices()
const edges = largeLog.edges()
const selectedVertex = sample(rng(1), layers[Math.floor(layers.length / 2)])
const selectedEdge = sample(rng(2), edges)

console.time('prove vertex')
const largeVertexProof = largeLog.proveVertex({
  rank: selectedVertex.rank,
  value: selectedVertex.value
})
console.timeEnd('prove vertex')

console.time('prove edge')
const largeEdgeProof = largeLog.proveEdge({
  fromRank: selectedEdge.fromRank,
  from: selectedEdge.from,
  toRank: selectedEdge.toRank,
  to: selectedEdge.to
})
console.timeEnd('prove edge')

console.time('verify vertex')
const largeVertexVerification = CausalLog.verifyVertex(largeLog.state(), largeVertexProof)
console.timeEnd('verify vertex')

console.time('verify edge')
const largeEdgeVerification = CausalLog.verifyEdge(largeLog.state(), largeEdgeProof)
console.timeEnd('verify edge')

assert.deepEqual(largeVertexVerification, { valid: true, reason: 'OK' })
assert.deepEqual(largeEdgeVerification, { valid: true, reason: 'OK' })

console.log('ranks:', largeLog.maxRank)
console.log('vertices:', vertices.length)
console.log('edges:', edges.length)
console.log('commitment:', largeLog.commitment().toString('hex'))
console.log('coordinate root:', largeLog.coordinateRoot().toString('hex'))
console.log('sample vertex:', `${selectedVertex.rank}:${selectedVertex.value.toString()}`)
console.log('sample edge:', `${selectedEdge.from.toString()} -> ${selectedEdge.to.toString()}`)
console.log('vertex proof:', largeVertexVerification)
console.log('edge proof:', largeEdgeVerification)
