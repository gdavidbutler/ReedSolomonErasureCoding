/*
 * asynchronousByzantineAgreementProtocols - thrDsp Reed-Solomon adapter
 * Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of asynchronousByzantineAgreementProtocols
 *
 * asynchronousByzantineAgreementProtocols is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * asynchronousByzantineAgreementProtocols is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef THRDSPRSEC_H
#define THRDSPRSEC_H

#include "thrDsp.h"
#include "rsecMk.h"

/*
 * Reed-Solomon adapter for thrDsp.
 *
 * Pieces are RS shards: pieces[0..k-1] are systematic data, pieces[k..n-1]
 * are parity, with k = n - 2t and m = 2t. Merkle tree is built over all
 * n shards in piece-index order.
 *
 * Constraints:
 *   k >= 1, m >= 1, k + m <= 256 (per rsec.c). So n >= 2 and t >= 1.
 *   payloadLen >= 1; shardSz = ceil(payloadLen / k), padded with zeros.
 *
 * Caller-owned cfg outlives the struct thrDsp.
 */

struct thrDspRsecCfg {
  const rsecMkHsh_t *h;   /* Merkle hash vtable */
};

/* Wire the vtable and stash cfg in d->opaque. Returns 0 on success,
 * -1 on invalid args. */
int
thrDspRsecInit(
  struct thrDsp *d
 ,const struct thrDspRsecCfg *cfg
);

/* Scrub d. cfg lifetime is the caller's. */
void
thrDspRsecFini(
  struct thrDsp *d
);

#endif /* THRDSPRSEC_H */
