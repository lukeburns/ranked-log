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

The same proof API also works for a forked rank by carrying the complement and
multiplicity for that rank:

```js
const forked = new RankedLog()
forked.append('a')
forked.appendLayer(['b', 'c'])
forked.append('d')

const proof = forked.proveEntry({ rank: 2, value: 'b' })

console.log(proof.adjustments[0].multiplicity) // 2
console.log(RankedLog.verifyEntry(forked.state(), proof)) // { valid: true, reason: 'OK' }
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
(1 / layer size) * sum h(vertex.bytes) * G(rank, rank)
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

#### `const proof = log.proveEntry({ rank, value })`

Create an unsigned IPA opening proof for an entry.

For linear ranks, the IPA proof opens the rank commitment directly. For forked
ranks, the proof includes the complement entries and multiplicity for that rank,
derives the branch commitment where the claim is true, and opens that branch
commitment.

#### `const result = RankedLog.verifyEntry(state, proof)`

Verify a proof against an expected state or commitment.

Returns `{ valid, reason }`.

#### `const json = log.toJSON()`

Serialize a ranked log.

#### `const log = RankedLog.fromJSON(json)`

Restore a ranked log and check that the serialized commitment matches the entries.

## Commitment

We use a graph-specific double sum.

Let `V_i` be the vertices at rank `i`, and let `E_i,j` be the edges from rank
`i` to rank `j`.

```text
C = sum_i avg(V_i) * G(i, i)
  + sum_i sum_j avg(E_i,j) * G(i, j)
```

where:

```text
avg(V_i) = (1 / |V_i|) * sum h(vertex.bytes)
avg(E_i,j) = (1 / |E_i,j|) * sum h(from, to)
```

The diagonal terms `G(i, i)` are the original rank/layer commitment. Off-diagonal
terms `G(i, j)` commit to graph continuity.

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