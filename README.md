# Causal Log

An append-only, multiply-branched log with sparse verification.

## Example

```js
const { CausalLog } = require('.')

const log = new CausalLog()

log.append('a')
log.appendLayer(['b', 'c'])
log.append('d')

const vertexProof = log.proveVertex({ rank: 2, value: 'b' })
const edgeProof = log.proveEdge({ fromRank: 2, from: 'b', toRank: 3, to: 'd' })

console.log(CausalLog.verifyVertex(log.state(), vertexProof)) // { valid: true, reason: 'OK' }
console.log(CausalLog.verifyEdge(log.state(), edgeProof)) // { valid: true, reason: 'OK' }
```

Branch-wise construction commits to the same state because vertices and edges are unioned as sets:

```js
const left = new CausalLog()
left.addBranch(['a', 'b', 'd'])

const right = new CausalLog()
right.addBranch(['a', 'c', 'd'])

const merged = left.clone().merge(right)

console.log(merged.commitment().equals(log.commitment())) // true
```

## API

#### `const log = new CausalLog([options])`

Create a causal log.

`options.vertices` and `options.edges` may be used to reconstruct a log:

```js
const log = new CausalLog({
  vertices: [
    { rank: 1, value: Buffer.from('a') },
    { rank: 2, value: Buffer.from('b') }
  ],
  edges: [
    { fromRank: 1, from: Buffer.from('a'), toRank: 2, to: Buffer.from('b') }
  ]
})
```

#### `const vertex = log.append(bytes)`

Append one vertex at `log.maxRank + 1`.

#### `const layer = log.appendLayer(bytesArray)`

Append multiple vertices at `log.maxRank + 1`. Vertices in a layer are deduped by byte value.

#### `const vertex = log.addVertex(rank, bytes)`

Add a vertex at an explicit rank.

#### `const edge = log.addEdge(fromRank, from, toRank, to)`

Add an explicit graph edge. Edges must point to a later rank, but they do not need to be adjacent.

#### `const vertices = log.addBranch(bytesArray, [startRank])`

Add a linear branch and its edges.

#### `log.merge(other)`

Merge another causal log or `{ vertices, edges }` object. Vertices are unioned by `(rank, bytes)`, and edges are unioned by `(fromRank, from, toRank, to)`.

#### `const commitment = log.commitment()`

Return the compressed full graph commitment as a `Buffer`.

#### `const commitment = log.vertexCommitment()`

Return the compressed diagonal vertex-set commitment.

#### `const commitment = log.edgeCommitment()`

Return the compressed edge-set commitment.

#### `const state = log.state()`

Return:

```js
{
  commitment,
  vertexCommitment,
  edgeCommitment,
  maxRank,
  vertexCount,
  byteLength
}
```

#### `const values = log.layer(rank)`

Return vertex byte values at `rank`, sorted deterministically.

#### `const vertices = log.vertices()`

Return all vertices as `{ rank, value }` objects.

#### `const edges = log.edges()`

Return graph edges as `{ fromRank, from, toRank, to }` objects.

#### `const proof = log.proveVertex({ rank, value })`

Create an unsigned IPA set-membership proof for a vertex.

#### `const proof = log.proveEdge({ fromRank, from, toRank, to })`

Create an unsigned IPA set-membership proof for an edge.

#### `const result = CausalLog.verifyVertex(state, proof)`

Verify a vertex proof against an expected state or commitment.

#### `const result = CausalLog.verifyEdge(state, proof)`

Verify an edge proof against an expected state or commitment.

#### `const json = log.toJSON()`

Serialize a causal log.

#### `const log = CausalLog.fromJSON(json)`

Restore a causal log and check that the serialized commitment matches the vertices and edges.

## Commitment

Let `V_i` be the vertices at rank `i`, and let `E_i,j` be the directed causal
edges from rank `i` to rank `j`. Since rank is causal depth, edge buckets are
only populated for `i < j`; the diagonal is reserved for vertex buckets.

```text
C = sum_i H(CommitSet(V_i)) * G(i, i)
  + sum_{i<j} H(CommitSet(E_i,j)) * G(i, j)
```

Each `CommitSet(S)` is an IPA polynomial commitment to the root polynomial:

```text
P_S(x) = product_{s in S} (x - h(s))
```

Membership is verified by opening:

```text
P_S(h(s)) = 0
```

Each membership proof has two IPA openings:

```text
outer opening: H(bucketCommitment) is opened at graph coordinate G(i,j)
inner opening: P_bucket(h(element)) = 0 is opened against bucketCommitment
```

Merging is deterministic by unioning bucket elements and recomputing bucket polynomial commitments. This gives compact IPA membership openings, but it is not an additive accumulator for set union.
