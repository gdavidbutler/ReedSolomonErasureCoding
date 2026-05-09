/*
 * ReedSolomonErasureCoding - Merkle tree authentication for erasure coded shards
 * Copyright (C) 2025 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of ReedSolomonErasureCoding
 *
 * ReedSolomonErasureCoding is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ReedSolomonErasureCoding is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* Generated with Claude Code (https://claude.ai/code) */

#ifndef RSECMK_H
#define RSECMK_H

/*
 * Merkle tree for authenticating Reed-Solomon erasure coded shards.
 *
 * Arbitrary shard count n (1..256), internally padded to next power of 2.
 * Proof size is ceil(log2(n)) hashes.
 *
 * Leaf hash:  H(0x00 || shard_data)
 * Node hash:  H(0x01 || left_child || right_child)
 * Root hash:  H(0x02 || n_hi || n_lo || inner_root)
 * The tag byte prefix prevents leaf/node/root confusion. The root commits
 * to n: a proof valid for (i, n) is not valid for (i, n') when n != n',
 * so shards cannot be replayed between trees of different sizes that
 * happen to share a padded-tree structure.
 *
 * Caller should zero the tree work area when done; it retains leaf hashes
 * H(0x00 || shard) for every shard.
 */

/* Hash context for Merkle tree operations */
typedef struct {
  void *(*a)(void);                                       /* hashContext allocate */
  void (*i)(void *);                                      /* hashContext initialize */
  void (*u)(void *, const unsigned char *, unsigned int); /* hashContext update */
  void (*f)(void *, unsigned char *);                     /* hashContext finalize */
  void (*d)(void *);                                      /* hashContext deallocate */
  unsigned char h;                                        /* (2^h) bytes per hash */
} rsecMkHsh_t;

/*
 * Return size, in bytes, of Merkle tree work area, 0 on error.
 * h: (2^h) bytes per hash
 * n: number of shards (1..256)
 */
unsigned int
rsecMkWaSz(
  unsigned char h
 ,unsigned int n
);

/*
 * Return size, in bytes, of Merkle proof, 0 on error.
 * h: (2^h) bytes per hash
 * n: number of shards (1..256)
 */
unsigned int
rsecMkPfSz(
  unsigned char h
 ,unsigned int n
);

/*
 * Return size, in bytes, of verify work area.
 * h: (2^h) bytes per hash
 */
unsigned int
rsecMkVfSz(
  unsigned char h
);

/*
 * Build Merkle tree over n shards, return pointer to root hash in
 * work area, 0 on error.
 */
unsigned char *
rsecMkHash(
  const rsecMkHsh_t *h
 ,const unsigned char *const *s /* n shard data pointers */
 ,unsigned int l                /* shard length in bytes */
 ,unsigned int n                /* number of shards (1..256) */
 ,unsigned char *w              /* work area (rsecMkWaSz) */
);

/*
 * Extract Merkle proof for shard i from built tree.
 * Return pointer past proof, 0 on error.
 */
unsigned char *
rsecMkProof(
  const rsecMkHsh_t *h
 ,unsigned int n                /* number of shards */
 ,unsigned int i                /* shard index (0..n-1) */
 ,const unsigned char *w        /* work area (from rsecMkHash) */
 ,unsigned char *pf             /* proof output (rsecMkPfSz) */
);

/*
 * Extract root hash from shard and Merkle proof.
 * n must equal the value passed to rsecMkHash and rsecMkProof.
 * Return pointer to root hash in work area, 0 on error.
 * Caller compares returned hash with expected root (use a constant-time
 * compare if the comparison is security-sensitive).
 */
unsigned char *
rsecMkExtract(
  const rsecMkHsh_t *h
 ,const unsigned char *s        /* shard data */
 ,unsigned int l                /* shard length */
 ,unsigned int i                /* shard index */
 ,unsigned int n                /* total shards */
 ,const unsigned char *pf       /* proof (rsecMkPfSz) */
 ,unsigned char *w              /* work area (rsecMkVfSz) */
);

#endif /* RSECMK_H */
