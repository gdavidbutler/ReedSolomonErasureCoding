# ReedSolomonErasureCoding
A small C implementation of Reed-Solomon erasure coding

Generated with Claude Code (https://claude.ai/code)

[Reed-Solomon](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction) is an error-correcting code that enables recovery of lost data from redundant parity information. Given k data shards and m parity shards, any k of the k+m shards can reconstruct the original data.

This implementation was created to provide small, portable code for memory constrained 32 bit microcontrollers. It uses systematic encoding over GF(2^8) with a Cauchy matrix for parity generation.

## Features

- Pure C89, no compiler extensions
- No dynamic memory allocation
- No recursion
- No dependencies beyond standard C
- Maximum 256 total shards (k + m <= 256)
- XOR fast path for single parity (m=1)

## API

### Encode

```c
int rsecEncode(
  const unsigned char *const *d,  /* k data shard pointers */
  unsigned char *const *p,        /* m parity shard pointers (output) */
  unsigned int l,                 /* shard length in bytes */
  unsigned int k,                 /* number of data shards */
  unsigned int m                  /* number of parity shards */
);
```

Returns 0 on success, -1 on invalid parameters.

### Decode

```c
int rsecDecode(
  const unsigned char *const *s,  /* k received shard pointers */
  const unsigned char *x,         /* k shard indices (0..k-1 data, k..k+m-1 parity) */
  unsigned char *const *d,        /* k data shard pointers (output) */
  unsigned int l,                 /* shard length in bytes */
  unsigned int k,                 /* number of data shards */
  unsigned int m,                 /* number of parity shards */
  unsigned char *w                /* work area, RS_WORK_SIZE(k) bytes */
);
```

Returns 0 on success, -1 on error. If all k data shards are present, simply copies them to the output without matrix inversion.

## Usage

```c
#include "rsec.h"

unsigned char data[4][64];     /* 4 data shards, 64 bytes each */
unsigned char parity[2][64];   /* 2 parity shards */
unsigned char *dp[4] = { data[0], data[1], data[2], data[3] };
unsigned char *pp[2] = { parity[0], parity[1] };

/* Encode: generate parity from data */
rsecEncode(dp, pp, 64, 4, 2);

/* Later: recover from any 4 of 6 shards */
unsigned char *received[4];    /* any 4 shards */
unsigned char indices[4];      /* their indices */
unsigned char recovered[4][64];
unsigned char *rp[4] = { recovered[0], recovered[1], recovered[2], recovered[3] };
unsigned char work[RS_WORK_SIZE(4)];

rsecDecode(received, indices, rp, 64, 4, 2, work);
```

## Implementation

Uses GF(2^8) arithmetic with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d). The encoding matrix is a Cauchy matrix where entry (i,j) = 1/((k+i) XOR j), which guarantees any k rows form an invertible submatrix.

Decoding uses Gaussian elimination with O(k^3) complexity for matrix inversion, then O(k * l) for reconstruction.

The lookup tables in rsec.c were generated with genGfTables.c.

### Data Padding

RS encoding requires data to be split into k equal-length shards. If the original data length is not a multiple of k, it must be padded. After decoding, the original length is not preserved by RS itself. The application is responsible for recovering the original length, for example by using a self-describing format (e.g., compression with an embedded length), a length prefix, or out-of-band metadata.

## Merkle Tree Authentication

`rsecMk.h` provides Merkle tree operations for authenticating individual shards. Each shard can be independently verified against a root hash using a compact proof, without needing all other shards.

The hash function is pluggable via `rsecMkHsh_t`, which provides allocate, initialize, update, finalize, and deallocate callbacks plus a hash size parameter h (hash is 2^h bytes).

The root hash commits to `n` (shard count) so proofs cannot be replayed between trees of different sizes. Tag-byte domain separation is used: leaves are `H(0x00 || shard)`, internal nodes are `H(0x01 || L || R)`, and the root is `H(0x02 || n_hi || n_lo || inner_root)`.

### Build Tree

```c
unsigned char *rsecMkHash(
  const rsecMkHsh_t *h,
  const unsigned char *const *s,  /* n shard data pointers */
  unsigned int l,                 /* shard length in bytes */
  unsigned int n,                 /* number of shards (1..256) */
  unsigned char *w                /* work area (rsecMkWaSz bytes) */
);
```

Returns pointer to root hash in work area, 0 on error. Internally pads to next power of 2 with zero hashes.

### Extract Proof

```c
unsigned char *rsecMkProof(
  const rsecMkHsh_t *h,
  unsigned int n,                 /* number of shards */
  unsigned int i,                 /* shard index (0..n-1) */
  const unsigned char *w,         /* work area (from rsecMkHash) */
  unsigned char *pf               /* proof output (rsecMkPfSz bytes) */
);
```

Returns pointer past proof, 0 on error. Proof size is ceil(log2(n)) hashes.

### Verify Shard

```c
unsigned char *rsecMkExtract(
  const rsecMkHsh_t *h,
  const unsigned char *s,         /* shard data */
  unsigned int l,                 /* shard length */
  unsigned int i,                 /* shard index */
  unsigned int n,                 /* total shards */
  const unsigned char *pf,        /* proof (rsecMkPfSz bytes) */
  unsigned char *w                /* work area (rsecMkVfSz bytes) */
);
```

Returns pointer to computed root hash in work area, 0 on error. Caller compares returned hash with the expected root.

### Size Functions

- `rsecMkWaSz(h, n)` - work area for tree construction
- `rsecMkPfSz(h, n)` - proof size per shard
- `rsecMkVfSz(h)` - work area for verification

## Applications

- UDP fragment recovery
- Distributed storage
- Streaming media
- Backup systems
- Any scenario requiring erasure tolerance

## Build

```bash
make
```

## License

GNU Lesser General Public License v3.0 or later
