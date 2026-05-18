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

#include <string.h>
#include "thrDspRsec.h"
#include "rsec.h"
#include "rsecMk.h"

#define CFG(d) ((const struct thrDspRsecCfg *)((d)->opaque))

static unsigned int
rMaxN(
  const struct thrDsp *d
){
  (void)d;
  return (256);
}

static unsigned int
rThreshold(
  unsigned int n
 ,unsigned int t
){
  if (2 * t >= n)
    return (0);
  return (n - 2 * t);
}

static unsigned int
rPieceSz(
  const struct thrDsp *d
 ,unsigned int payloadLen
 ,unsigned int n
 ,unsigned int t
){
  unsigned int k;

  (void)d;
  k = rThreshold(n, t);
  if (!k || !payloadLen)
    return (0);
  return ((payloadLen + k - 1) / k);
}

static unsigned int
rRootSz(
  const struct thrDsp *d
){
  return (1U << CFG(d)->h->h);
}

static unsigned int
rProofSz(
  const struct thrDsp *d
 ,unsigned int n
){
  return (rsecMkPfSz(CFG(d)->h->h, n));
}

static unsigned int
rEncWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  (void)t;
  (void)payloadLen;
  return (rsecMkWaSz(CFG(d)->h->h, n));
}

static unsigned int
rVfWaSz(
  const struct thrDsp *d
){
  return (rsecMkVfSz(CFG(d)->h->h));
}

static unsigned int
rDecWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int k;
  unsigned int shardSz;

  (void)d;
  k = rThreshold(n, t);
  if (!k || !payloadLen)
    return (0);
  shardSz = (payloadLen + k - 1) / k;
  /* sp[k] + rp[k] (pointers, aligned first) + idx[k] + recBuf[k*shardSz]
   * + RS decode work area */
  return (2 * k * sizeof (unsigned char *)
        + k
        + k * shardSz
        + RS_WORK_SIZE(k));
}

static unsigned int
rDerivedRootWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int k;
  unsigned int m;
  unsigned int shardSz;

  k = rThreshold(n, t);
  if (!k || !payloadLen)
    return (0);
  m = n - k;
  shardSz = (payloadLen + k - 1) / k;
  /* sp[k] + rp[k] + pp[m] + leaves[n] (pointers, aligned first)
   * + idx[k] + scratch[n*shardSz] + RS decode work + Merkle tree work */
  return ((2 * k + m + n) * sizeof (unsigned char *)
        + k
        + n * shardSz
        + RS_WORK_SIZE(k)
        + rsecMkWaSz(CFG(d)->h->h, n));
}

static int
rEncode(
  const struct thrDsp *d
 ,const unsigned char *payload
 ,unsigned int payloadLen
 ,unsigned int n
 ,unsigned int t
 ,unsigned char *const *pieces
 ,unsigned char *const *proofs
 ,unsigned char *root
 ,unsigned char *work
){
  unsigned int k;
  unsigned int m;
  unsigned int shardSz;
  unsigned int i;
  unsigned int off;
  unsigned int copyLen;
  unsigned char *r;

  if (!d || !payload || !payloadLen || !pieces || !proofs || !root || !work)
    return (-1);
  k = rThreshold(n, t);
  if (!k)
    return (-1);
  m = n - k;
  shardSz = (payloadLen + k - 1) / k;

  /* copy payload into pieces[0..k-1], zero-padding the last shard */
  off = 0;
  for (i = 0; i < k; ++i) {
    copyLen = payloadLen - off;
    if (copyLen > shardSz)
      copyLen = shardSz;
    if (copyLen)
      memcpy(pieces[i], payload + off, copyLen);
    if (copyLen < shardSz)
      memset(pieces[i] + copyLen, 0, shardSz - copyLen);
    off += copyLen;
  }

  if (rsecEncode((const unsigned char *const *)pieces, pieces + k,
   shardSz, k, m))
    return (-1);

  r = rsecMkHash(CFG(d)->h, (const unsigned char *const *)pieces,
   shardSz, n, work);
  if (!r)
    return (-1);
  memcpy(root, r, 1U << CFG(d)->h->h);

  for (i = 0; i < n; ++i)
    if (!rsecMkProof(CFG(d)->h, n, i, work, proofs[i]))
      return (-1);
  return (0);
}

static int
rVerify(
  const struct thrDsp *d
 ,unsigned int i
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *piece
 ,const unsigned char *proof
 ,const unsigned char *root
 ,unsigned char *work
){
  unsigned int shardSz;
  unsigned char *r;

  if (!d || !piece || !proof || !root || !work)
    return (-1);
  shardSz = rPieceSz(d, payloadLen, n, t);
  if (!shardSz)
    return (-1);
  r = rsecMkExtract(CFG(d)->h, piece, shardSz, i, n, proof, work);
  if (!r)
    return (-1);
  if (memcmp(r, root, 1U << CFG(d)->h->h) != 0)
    return (-1);
  return (0);
}

static int
rDecode(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *indices
 ,const unsigned char *const *pieces
 ,unsigned char *payload
 ,unsigned char *work
){
  unsigned int k;
  unsigned int m;
  unsigned int shardSz;
  unsigned int i;
  unsigned int off;
  unsigned int copyLen;
  const unsigned char **sp;
  unsigned char **rp;
  unsigned char *idx;
  unsigned char *recBuf;
  unsigned char *rsWa;

  if (!d || !indices || !pieces || !payload || !work)
    return (-1);
  k = rThreshold(n, t);
  if (!k || !payloadLen)
    return (-1);
  m = n - k;
  shardSz = (payloadLen + k - 1) / k;

  /* layout: sp[k], rp[k] (pointers, aligned), idx[k], recBuf, rsWa */
  sp = (const unsigned char **)work;
  rp = (unsigned char **)(sp + k);
  idx = (unsigned char *)(rp + k);
  recBuf = idx + k;
  rsWa = recBuf + k * shardSz;

  for (i = 0; i < k; ++i) {
    if (indices[i] >= k + m)
      return (-1);
    sp[i] = pieces[i];
    rp[i] = recBuf + i * shardSz;
    idx[i] = indices[i];
  }

  if (rsecDecode(sp, idx, rp, shardSz, k, m, rsWa))
    return (-1);

  off = 0;
  for (i = 0; i < k; ++i) {
    copyLen = payloadLen - off;
    if (copyLen > shardSz)
      copyLen = shardSz;
    if (copyLen)
      memcpy(payload + off, rp[i], copyLen);
    off += copyLen;
  }
  return (0);
}

static int
rDerivedRoot(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *indices
 ,const unsigned char *const *pieces
 ,unsigned char *root
 ,unsigned int idxOut
 ,unsigned char *proof
 ,unsigned char *piece
 ,unsigned char *work
){
  unsigned int k;
  unsigned int m;
  unsigned int shardSz;
  unsigned int i;
  const unsigned char **sp;
  unsigned char **rp;
  unsigned char **pp;
  const unsigned char **leaves;
  unsigned char *idx;
  unsigned char *scratch;
  unsigned char *rsWa;
  unsigned char *treeWa;
  unsigned char *r;

  if (!d || !indices || !pieces || !root || !work)
    return (-1);
  if ((proof || piece) && idxOut >= n)
    return (-1);
  k = rThreshold(n, t);
  if (!k || !payloadLen)
    return (-1);
  m = n - k;
  shardSz = (payloadLen + k - 1) / k;

  /* pointer arrays first (aligned), then byte arrays */
  sp = (const unsigned char **)work;
  rp = (unsigned char **)(sp + k);
  pp = (unsigned char **)(rp + k);
  leaves = (const unsigned char **)(pp + m);
  idx = (unsigned char *)(leaves + n);
  scratch = idx + k;
  rsWa = scratch + n * shardSz;
  treeWa = rsWa + RS_WORK_SIZE(k);

  /* decode any threshold pieces into scratch[0..k-1]; this yields the
   * systematic data shards regardless of which subset was provided */
  for (i = 0; i < k; ++i) {
    if (indices[i] >= n)
      return (-1);
    sp[i] = pieces[i];
    rp[i] = scratch + i * shardSz;
    idx[i] = indices[i];
  }
  if (rsecDecode(sp, idx, rp, shardSz, k, m, rsWa))
    return (-1);

  /* re-encode parity from recovered data into scratch[k..n-1] */
  for (i = 0; i < m; ++i)
    pp[i] = scratch + (k + i) * shardSz;
  if (rsecEncode((const unsigned char *const *)rp, pp, shardSz, k, m))
    return (-1);

  /* Merkle root over all n re-derived shards in piece-index order */
  for (i = 0; i < n; ++i)
    leaves[i] = scratch + i * shardSz;
  r = rsecMkHash(CFG(d)->h, leaves, shardSz, n, treeWa);
  if (!r)
    return (-1);
  memcpy(root, r, 1U << CFG(d)->h->h);
  if (proof && !rsecMkProof(CFG(d)->h, n, idxOut, treeWa, proof))
    return (-1);
  if (piece)
    memcpy(piece, scratch + (unsigned long)idxOut * shardSz, shardSz);
  return (0);
}

static const struct thrDspVt Vt = {
  rMaxN
 ,rThreshold
 ,rPieceSz
 ,rRootSz
 ,rProofSz
 ,rEncWaSz
 ,rVfWaSz
 ,rDecWaSz
 ,rDerivedRootWaSz
 ,rEncode
 ,rVerify
 ,rDecode
 ,rDerivedRoot
};

int
thrDspRsecInit(
  struct thrDsp *d
 ,const struct thrDspRsecCfg *cfg
){
  if (!d || !cfg || !cfg->h)
    return (-1);
  d->vt = &Vt;
  d->opaque = cfg;
  return (0);
}

void
thrDspRsecFini(
  struct thrDsp *d
){
  if (!d)
    return;
  d->vt = 0;
  d->opaque = 0;
}
