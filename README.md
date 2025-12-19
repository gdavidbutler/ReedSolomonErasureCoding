# ReedSolomonErasureCoding
A small C implementation of Reed-Solomon erasure coding

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
