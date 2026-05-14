# Ranked Log

An append-only, multiply-branched log.

## Example

```js
const { RankedLog } = require('.')

const log = new RankedLog()

log.append('a')
log.append('b')
log.append('d')

const state = log.state()
const proof = log.proveEntry({ rank: 2, value: 'b' })

console.log(state.commitment.toString('hex'))
console.log(RankedLog.verifyEntry(state, proof)) // { valid: true, reason: 'OK' }
```

The same proof API also works for a forked rank. The rank bucket is committed as
an IPA polynomial set, so membership is opened without sending complement
entries:

```js
const forked = new RankedLog()
forked.append('a')
forked.appendLayer(['b', 'c'])
forked.append('d')

const proof = forked.proveEntry({ rank: 2, value: 'b' })

console.log(proof.degree) // 2
console.log(RankedLog.verifyEntry(forked.state(), proof)) // { valid: true, reason: 'OK' }
```

Edges have the same membership proof shape:

```js
const proof = forked.proveEdge({ fromRank: 2, from: 'b', toRank: 3, to: 'd' })

console.log(RankedLog.verifyEdge(forked.state(), proof)) // { valid: true, reason: 'OK' }
```

Branch-wise construction commits to the same state:

```js
const left = new RankedLog()
left.addBranch(['a', 'b', 'd'])

const right = new RankedLog()
right.addBranch(['a', 'c', 'd'])

const merged = left.clone().merge(right)

console.log(merged.commitment().equals(forked.commitment())) // true
```

## API

#### `const log = new RankedLog([options])`

Make a new ranked log.

`options.entries` may be used to reconstruct a log from entries:

```js
const log = new RankedLog({
  entries: [
    { rank: 1, value: Buffer.from('a') },
    { rank: 2, value: Buffer.from('b') }
  ]
})
```

#### `const entry = log.append(bytes)`

Append one entry at `log.maxRank + 1`.

Returns `{ rank, value, added }`.

#### `const layer = log.appendLayer(bytesArray)`

Append multiple entries at `log.maxRank + 1`.

Entries in a layer are deduped by byte value. The layer contribution is:

```text
H(CommitSet(V_rank)) * G(rank, rank)
```

#### `const entry = log.addAtRank(rank, bytes)`

Add an entry at an explicit rank. This is useful for importing, reconstructing, or
building custom ranked layers.

#### `const entries = log.addBranch(bytesArray, [startRank])`

Add a linear branch and its graph edges. This is useful when branch continuity
matters.

#### `const edge = log.addEdge(fromRank, from, toRank, to)`

Add an explicit graph edge. The edge contributes to bucket `E_fromRank,toRank`
and uses generator `G(fromRank, toRank)`.

#### `log.merge(other)`

Merge another ranked log or `{ entries, edges }` object into this log.

Entries are unioned by `(rank, bytes)` and edges are unioned by `(from, to)`, so
shared prefixes and suffixes dedupe.

#### `const commitment = log.commitment()`

Return the compressed full commitment as a `Buffer`.

The full commitment is the sum of `log.rankCommitment()` and
`log.edgeCommitment()`.

#### `const commitment = log.vertexCommitment()`

Return the compressed diagonal vertex commitment as a `Buffer`.

`log.rankCommitment()` is an alias for this diagonal commitment.

#### `const commitment = log.edgeCommitment()`

Return the compressed edge/continuity commitment as a `Buffer`.

#### `const state = log.state()`

Return:

```js
{
  commitment,
  rankCommitment,
  vertexCommitment,
  edgeCommitment,
  maxRank,
  entryCount,
  byteLength
}
```

#### `const values = log.layer(rank)`

Return the byte values at `rank`, sorted deterministically.

#### `const vertices = log.vertices()`

Return all vertices as `{ rank, value }` objects, sorted by rank and then value.

`log.entries()` is an alias for this vertex list.

#### `const edges = log.edges()`

Return graph edges as `{ fromRank, from, toRank, to }` objects.

#### `const proof = log.proveVertex({ rank, value })`

Create an unsigned IPA set-membership proof for a vertex.

`log.proveEntry()` is an alias for vertex proofs.

#### `const proof = log.proveEdge({ fromRank, from, toRank, to })`

Create an unsigned IPA set-membership proof for an edge.

Each membership proof has two openings:

```text
outer opening: H(bucketCommitment) is opened at graph coordinate G(i,j)
inner opening: P_bucket(h(element)) = 0 is opened against bucketCommitment
```

#### `const result = RankedLog.verifyVertex(state, proof)`

Verify a vertex proof against an expected state or commitment.

`RankedLog.verifyEntry()` is an alias for vertex verification.

#### `const result = RankedLog.verifyEdge(state, proof)`

Verify an edge proof against an expected state or commitment.

Returns `{ valid, reason }`.

#### `const json = log.toJSON()`

Serialize a ranked log.

#### `const log = RankedLog.fromJSON(json)`

Restore a ranked log and check that the serialized commitment matches the entries.

## Commitment

We use a graph-specific double sum over IPA set buckets.

Let `V_i` be the vertices at rank `i`, and let `E_i,j` be the edges from rank
`i` to rank `j`.

```text
C = sum_i H(CommitSet(V_i)) * G(i, i)
  + sum_i sum_j H(CommitSet(E_i,j)) * G(i, j)
```

Each `CommitSet(S)` is an IPA polynomial commitment to the root polynomial:

```text
P_S(x) = product_{s in S} (x - h(s))
```

Membership is verified by opening:

```text
P_S(h(s)) = 0
```

The diagonal terms `G(i, i)` commit to vertex sets. Off-diagonal terms `G(i, j)`
commit to edge sets and graph continuity.

The implementation exposes these slices as:

```text
commitment = rankCommitment + edgeCommitment
```

The rank commitment alone cannot distinguish these two histories:

```text
a | b | d
a | c | d
```

and

```text
a | b
a | c | d
```

The edge commitment distinguishes them because the first has both `b -> d` and
`c -> d`, while the second only has `c -> d`.

Merging is deterministic by unioning bucket elements and recomputing the bucket
polynomial commitment. This gives compact IPA membership openings, but it is not
an additive accumulator for set union.