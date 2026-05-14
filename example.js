'use strict'

const assert = require('assert')
const path = require('path')
const { execFileSync } = require('child_process')
const { CausalLog } = require('.')

function sample (values) {
  return values[Math.floor(values.length / 2)]
}

function generateFromGitRepo (repo) {
  const output = execFileSync('git', [
    '-C',
    repo,
    'rev-list',
    '--parents',
    '--topo-order',
    '--reverse',
    '--all'
  ], { encoding: 'utf8' })

  const log = new CausalLog()
  const layers = []
  const vertices = new Map()
  const childCounts = new Map()
  let rootCount = 0
  let mergeCount = 0

  for (const line of output.trim().split('\n')) {
    if (!line) continue

    const [sha, ...parents] = line.split(' ')
    let rank = 1
    if (parents.length === 0) rootCount++

    for (const parent of parents) {
      const parentVertex = vertices.get(parent)
      if (parentVertex) rank = Math.max(rank, parentVertex.rank + 1)
    }

    const vertex = log.addVertex(rank, sha)
    vertices.set(sha, vertex)
    if (!layers[rank - 1]) layers[rank - 1] = []
    layers[rank - 1].push(vertex)
    if (parents.length > 1) mergeCount++

    for (const parent of parents) {
      childCounts.set(parent, (childCounts.get(parent) || 0) + 1)
      const parentVertex = vertices.get(parent)
      if (parentVertex) {
        log.addEdge(parentVertex.rank, parentVertex.value, vertex.rank, vertex.value)
      }
    }
  }

  return {
    label: `${path.basename(repo)}`,
    log,
    layers: layers.filter(Boolean),
    meta: {
      repo,
      rootCount,
      mergeCount,
      forkCount: [...childCounts.values()].filter(count => count > 1).length
    }
  }
}

function generateLargeExample () {
  const repo = path.resolve(process.argv[2] || process.cwd())
  return generateFromGitRepo(repo)
}

console.log('causal log from git DAG')
console.time('generate')
const largeExample = generateLargeExample()
console.timeEnd('generate')
if (largeExample.meta.repo) console.log('repo:', largeExample.meta.repo)
const { log: largeLog, layers } = largeExample
const vertices = largeLog.vertices()
const edges = largeLog.edges()
const selectedVertex = sample(layers[Math.floor(layers.length / 2)])
const selectedEdge = sample(edges)

console.time('finalize')
const largeState = largeLog.state()
console.timeEnd('finalize')

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
const largeVertexVerification = CausalLog.verifyVertex(largeState, largeVertexProof)
console.timeEnd('verify vertex')

console.time('verify edge')
const largeEdgeVerification = CausalLog.verifyEdge(largeState, largeEdgeProof)
console.timeEnd('verify edge')

assert.deepEqual(largeVertexVerification, { valid: true, reason: 'OK' })
assert.deepEqual(largeEdgeVerification, { valid: true, reason: 'OK' })

console.log('ranks:', largeLog.maxRank)
console.log('vertices:', vertices.length)
console.log('edges:', edges.length)
console.log('roots:', largeExample.meta.rootCount)
console.log('forks:', largeExample.meta.forkCount)
if (largeExample.meta.mergeCount !== null) console.log('merges:', largeExample.meta.mergeCount)
console.log('commitment:', largeState.commitment.toString('hex'))
console.log('coordinate root:', largeState.coordinateRoot.toString('hex'))
console.log('sample vertex:', `${selectedVertex.rank}:${selectedVertex.value.toString()}`)
console.log('sample edge:', `${selectedEdge.from.toString()} -> ${selectedEdge.to.toString()}`)
console.log('vertex proof:', largeVertexVerification)
console.log('edge proof:', largeEdgeVerification)
