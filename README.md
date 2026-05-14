# HyperDAG

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

Branch-wise construction commits to the same state:

```js
const forked = new RankedLog()
forked.append('a')
forked.appendLayer(['b', 'c'])
forked.append('d')

const left = new RankedLog()
left.addAtRank(1, 'a')
left.addAtRank(2, 'b')
left.addAtRank(3, 'd')

const right = new RankedLog()
right.addAtRank(1, 'a')
right.addAtRank(2, 'c')
right.addAtRank(3, 'd')

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
(1 / layer size) * sum h(entry.bytes) * G(rank)
```

#### `const entry = log.addAtRank(rank, bytes)`

Add an entry at an explicit rank. This is useful for importing, reconstructing, or
building branch-wise logs.

#### `log.merge(other)`

Merge another ranked log or `{ entries }` object into this log.

Entries are unioned by `(rank, bytes)`, so shared prefixes and suffixes dedupe.

#### `const commitment = log.commitment()`

Return the compressed EC commitment as a `Buffer`.

#### `const state = log.state()`

Return:

```js
{
  commitment,
  maxRank,
  entryCount,
  byteLength
}
```

#### `const values = log.layer(rank)`

Return the byte values at `rank`, sorted deterministically.

#### `const entries = log.entries()`

Return all entries as `{ rank, value }` objects, sorted by rank and then value.

#### `const proof = log.proveEntry({ rank, value })`

Create an unsigned IPA opening proof for an entry in a linear rank.

For now, this only works when `layer(rank)` contains exactly one value. Membership
proofs for degenerate layers such as `{ b, c }` are not implemented yet.

#### `const result = RankedLog.verifyEntry(state, proof)`

Verify a proof against an expected state or commitment.

Returns `{ valid, reason }`.

#### `const json = log.toJSON()`

Serialize a ranked log.

#### `const log = RankedLog.fromJSON(json)`

Restore a ranked log and check that the serialized commitment matches the entries.

## Commitment

For each rank, HyperDAG commits to the average scalar of the entries in that rank:

```text
C = sum_r layer(r) * G(r)
layer(r) = (1 / |entries_r|) * sum h(entry.bytes)
```

This preserves linear order when there is one entry per rank, while making same-rank
forks commutative.
