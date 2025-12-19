/*
 * ReedSolomonErasureCoding - A small C implementation of Reed-Solomon erasure coding
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

#ifndef RSEC_H
#define RSEC_H

/*
 * Reed-Solomon erasure coding over GF(2^8)
 *
 * Maximum shards (k + m <= 256 for GF(2^8))
 * Systematic encoding: k data shards + m parity shards
 * Any k of (k+m) shards can reconstruct original data
 */

/*
 * Encode k data shards into m parity shards
 * d: array of k data shard pointers
 * p: array of m parity shard pointers (output)
 * l: length of each shard in bytes
 * k: number of data shards
 * m: number of parity shards
 * Returns 0 on success, -1 on invalid parameters
 */
int
rsecEncode(
  const unsigned char *const *d
 ,unsigned char *const *p
 ,unsigned int l
 ,unsigned int k
 ,unsigned int m
);

/* Work area size needed for rsecDecode */
#define RS_WORK_SIZE(k) (2 * (k) * (k))

/*
 * Decode/reconstruct data from any k shards
 * s: array of k shard pointers (any k of k+m shards)
 * x: array of k shard indices (0..k-1 are data, k..k+m-1 are parity)
 * d: array of k data shard pointers (output)
 * l: length of each shard in bytes
 * k: number of data shards
 * m: number of parity shards
 * w: work area, RS_WORK_SIZE(k) bytes
 * Returns 0 on success, -1 on error
 *
 * Note: if all k data shards are present (x[i] < k for all i),
 * simply copy s to d; no decode needed
 */
int
rsecDecode(
  const unsigned char *const *s
 ,const unsigned char *x
 ,unsigned char *const *d
 ,unsigned int l
 ,unsigned int k
 ,unsigned int m
 ,unsigned char *w
);

#endif
