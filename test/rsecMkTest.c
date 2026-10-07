/*
 * ReedSolomonErasureCoding - Merkle tree authentication test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsec.h"
#include "rsecMk.h"
#include "rmd128.h"
#include "sha256.h"
#include "huf.h"

static void *
rmd128Allocate(
  void
){
  return (malloc(rmd128tsize()));
}

static void *
sha256Allocate(
  void
){
  return (malloc(sha256tsize()));
}

/* Parametric test over (hash vtable, shard count).
 * Builds a tree of n synthetic shards, verifies every shard, then runs
 * four negative tests: bit-flip corruption, wrong-index substitution,
 * wrong-n substitution (larger), wrong-n substitution (smaller when valid).
 * Returns 0 on success, non-zero on any failure. */
static int
parametricTest(
  const rsecMkHsh_t *h
 ,const char *hashName
 ,unsigned int n
){
  enum { ShardLen = 64 };
  unsigned int b;
  unsigned int waSz;
  unsigned int pfSz;
  unsigned int i;
  unsigned int j;
  unsigned char **shards;
  const unsigned char **cShards;
  unsigned char **proofs;
  unsigned char *work;
  unsigned char *root;
  unsigned char *savedRoot;
  unsigned char *vWork;
  unsigned char *extracted;
  int fail;

  fail = 0;
  b = 1U << h->h;
  waSz = rsecMkWaSz(h->h, n);
  pfSz = rsecMkPfSz(h->h, n);
  printf("\n== %s n=%u b=%u waSz=%u pfSz=%u ==\n",
   hashName, n, b, waSz, pfSz);

  shards = malloc(n * sizeof (*shards));
  cShards = malloc(n * sizeof (*cShards));
  proofs = malloc(n * sizeof (*proofs));
  work = malloc(waSz ? waSz : 1);
  vWork = malloc(rsecMkVfSz(h->h));
  savedRoot = malloc(b);
  if (!shards || !cShards || !proofs || !work || !vWork || !savedRoot) {
    fprintf(stderr, "malloc\n");
    exit(1);
  }
  for (i = 0; i < n; ++i) {
    shards[i] = malloc(ShardLen);
    /* allocate at least one byte so the library's null-pointer guard
     * does not trip on the degenerate pfSz=0 case (n=1) */
    proofs[i] = malloc(pfSz ? pfSz : 1);
    if (!shards[i] || !proofs[i]) {
      fprintf(stderr, "malloc\n");
      exit(1);
    }
    for (j = 0; j < ShardLen; ++j)
      shards[i][j] = (unsigned char)((i * 37 + j) & 0xff);
    cShards[i] = shards[i];
  }

  /* build tree */
  root = rsecMkHash(h, cShards, ShardLen, n, work);
  if (!root) {
    printf("  rsecMkHash: FAIL\n");
    fail = 1;
    goto cleanup;
  }
  memcpy(savedRoot, root, b);

  /* extract and verify every shard */
  for (i = 0; i < n; ++i) {
    if (!rsecMkProof(h, n, i, work, proofs[i])) {
      printf("  rsecMkProof[%u]: FAIL\n", i);
      fail = 1;
      goto cleanup;
    }
    extracted = rsecMkExtract(h, cShards[i], ShardLen, i, n, proofs[i], vWork);
    if (!extracted || memcmp(extracted, savedRoot, b) != 0) {
      printf("  verify[%u]: FAIL\n", i);
      fail = 1;
      goto cleanup;
    }
  }
  printf("  verify all %u shards: PASS\n", n);

  /* negative: bit-flip corruption */
  shards[0][0] ^= 0xff;
  extracted = rsecMkExtract(h, cShards[0], ShardLen, 0, n, proofs[0], vWork);
  if (extracted && memcmp(extracted, savedRoot, b) == 0) {
    printf("  corruption rejection: FAIL (accepted corrupted shard)\n");
    fail = 1;
  } else
    printf("  corruption rejection: PASS\n");
  shards[0][0] ^= 0xff;

  /* negative: wrong index (only meaningful when n > 1) */
  if (n > 1) {
    extracted = rsecMkExtract(h, cShards[0], ShardLen, 1, n, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-index rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-index rejection: PASS\n");
  }

  /* negative: wrong n (larger). the verifier thinks tree has n+1 shards;
   * the recomputed root must differ because n is bound at the root. */
  if (n < 256) {
    extracted = rsecMkExtract(h, cShards[0], ShardLen, 0, n + 1, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-n(+1) rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-n(+1) rejection: PASS\n");
  }

  /* negative: wrong n (smaller, same padded size). important case:
   * without n-binding, n=3 and n=4 would produce identical walks for i<3. */
  if (n > 1) {
    extracted = rsecMkExtract(h, cShards[0], ShardLen, 0, n - 1, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-n(-1) rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-n(-1) rejection: PASS\n");
  }

  /* null-argument guards */
  if (rsecMkHash(0, cShards, ShardLen, n, work)
   || rsecMkHash(h, 0, ShardLen, n, work)
   || rsecMkHash(h, cShards, 0, n, work)
   || rsecMkHash(h, cShards, ShardLen, 0, work)
   || rsecMkHash(h, cShards, ShardLen, 257, work)
   || rsecMkHash(h, cShards, ShardLen, n, 0)) {
    printf("  Hash null-arg guards: FAIL\n");
    fail = 1;
  }
  if (rsecMkProof(0, n, 0, work, proofs[0])
   || rsecMkProof(h, 0, 0, work, proofs[0])
   || rsecMkProof(h, 257, 0, work, proofs[0])
   || rsecMkProof(h, n, n, work, proofs[0])
   || rsecMkProof(h, n, 0, 0, proofs[0])
   || rsecMkProof(h, n, 0, work, 0)) {
    printf("  Proof null-arg guards: FAIL\n");
    fail = 1;
  }
  if (rsecMkExtract(0, shards[0], ShardLen, 0, n, proofs[0], vWork)
   || rsecMkExtract(h, 0, ShardLen, 0, n, proofs[0], vWork)
   || rsecMkExtract(h, shards[0], 0, 0, n, proofs[0], vWork)
   || rsecMkExtract(h, shards[0], ShardLen, n, n, proofs[0], vWork)
   || rsecMkExtract(h, shards[0], ShardLen, 0, 0, proofs[0], vWork)
   || rsecMkExtract(h, shards[0], ShardLen, 0, 257, proofs[0], vWork)
   || rsecMkExtract(h, shards[0], ShardLen, 0, n, 0, vWork)
   || rsecMkExtract(h, shards[0], ShardLen, 0, n, proofs[0], 0)) {
    printf("  Extract null-arg guards: FAIL\n");
    fail = 1;
  }
  if (!fail)
    printf("  argument guards: PASS\n");

cleanup:
  for (i = 0; i < n; ++i) {
    free(shards[i]);
    free(proofs[i]);
  }
  free(shards);
  free(cShards);
  free(proofs);
  free(work);
  free(vWork);
  free(savedRoot);
  return (fail);
}

int
main(
  void
){
  static const unsigned char Payload[] =
    "Hello Sam, this is a test of Merkle authenticated"
    " Reed-Solomon erasure coding with Huffman compression."
    " The quick brown fox jumps over the lazy dog.";
  enum { K = 5, M = 2, N = K + M };
  rsecMkHsh_t Hrmd;
  rsecMkHsh_t Hsha;
  unsigned int payloadLen;
  hufLen compLen;
  unsigned int shardSize;
  unsigned int paddedLen;
  unsigned int pfSz;
  unsigned int waSz;
  unsigned char *comp;
  unsigned char *padded;
  unsigned char *mkWork;
  unsigned char *vfWork;
  unsigned char *root;
  unsigned char *shardBuf[N];
  const unsigned char *cShardBuf[N];
  unsigned char *proofBuf[N];
  unsigned int i;
  unsigned int j;
  int fail;
  unsigned int nTests[] = { 1, 2, 3, 5, 7, 8, 100, 255, 256 };

  fail = 0;
  payloadLen = sizeof (Payload) - 1;

  /* rmd128 (2^4 = 16 bytes) */
  Hrmd.a = rmd128Allocate;
  Hrmd.i = (void(*)(void *))rmd128init;
  Hrmd.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  Hrmd.f = (void(*)(void *, unsigned char *))rmd128final;
  Hrmd.d = free;
  Hrmd.h = 4;

  /* sha256 (2^5 = 32 bytes) */
  Hsha.a = sha256Allocate;
  Hsha.i = (void(*)(void *))sha256init;
  Hsha.u = (void(*)(void *, const unsigned char *, unsigned int))sha256update;
  Hsha.f = (void(*)(void *, unsigned char *))sha256final;
  Hsha.d = free;
  Hsha.h = 5;

  printf("Payload (%u bytes): %.*s\n", payloadLen, (int)payloadLen, Payload);

  /*
   * Test 1: narrative integration (Huffman + RS + Merkle, rmd128)
   */
  printf("\nTest 1: Huffman+RS+Merkle integration (K=%u M=%u, rmd128)\n",
   (unsigned)K, (unsigned)M);

  comp = malloc(payloadLen + 256);
  if (!comp) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  compLen = hufEncode(comp, payloadLen + 256, Payload, payloadLen);
  if (!compLen) {
    fprintf(stderr, "hufEncode\n");
    return (1);
  }
  if (compLen > payloadLen + 256) {
    free(comp);
    comp = malloc(compLen);
    if (!comp) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    compLen = hufEncode(comp, compLen, Payload, payloadLen);
    if (!compLen) {
      fprintf(stderr, "hufEncode retry\n");
      return (1);
    }
  }
  printf("  Compressed: %u bytes\n", (unsigned int)compLen);

  shardSize = ((unsigned int)compLen + K - 1) / K;
  paddedLen = K * shardSize;
  printf("  Shard size: %u bytes, padded total: %u bytes\n", shardSize, paddedLen);

  padded = calloc(paddedLen, 1);
  if (!padded) {
    fprintf(stderr, "calloc\n");
    return (1);
  }
  memcpy(padded, comp, compLen);

  for (i = 0; i < K; ++i) {
    shardBuf[i] = padded + i * shardSize;
    cShardBuf[i] = shardBuf[i];
  }
  for (i = 0; i < M; ++i) {
    shardBuf[K + i] = malloc(shardSize);
    if (!shardBuf[K + i]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    cShardBuf[K + i] = shardBuf[K + i];
  }

  {
    const unsigned char *dp[K];
    unsigned char *pp[M];

    for (i = 0; i < K; ++i)
      dp[i] = cShardBuf[i];
    for (i = 0; i < M; ++i)
      pp[i] = shardBuf[K + i];
    if (rsecEncode(dp, pp, shardSize, K, M)) {
      fprintf(stderr, "rsecEncode\n");
      return (1);
    }
  }

  for (i = 0; i < N; ++i) {
    printf("  shard %u:", i);
    for (j = 0; j < shardSize && j < 16; ++j)
      printf(" %02x", shardBuf[i][j]);
    if (shardSize > 16)
      printf(" ...");
    printf("\n");
  }

  waSz = rsecMkWaSz(Hrmd.h, N);
  pfSz = rsecMkPfSz(Hrmd.h, N);
  mkWork = malloc(waSz);
  if (!mkWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  root = rsecMkHash(&Hrmd, cShardBuf, shardSize, N, mkWork);
  if (!root) {
    fprintf(stderr, "rsecMkHash\n");
    return (1);
  }
  printf("  Root:");
  for (i = 0; i < (1U << Hrmd.h); ++i)
    printf(" %02x", root[i]);
  printf("\n");

  vfWork = malloc(rsecMkVfSz(Hrmd.h));
  if (!vfWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  for (i = 0; i < N; ++i) {
    unsigned char *extracted;

    proofBuf[i] = malloc(pfSz);
    if (!proofBuf[i]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    if (!rsecMkProof(&Hrmd, N, i, mkWork, proofBuf[i])) {
      fprintf(stderr, "rsecMkProof %u\n", i);
      return (1);
    }
    extracted = rsecMkExtract(&Hrmd, cShardBuf[i], shardSize, i, N,
     proofBuf[i], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hrmd.h) != 0) {
      printf("  shard %u verify: FAIL\n", i);
      fail = 1;
    } else
      printf("  shard %u verify: PASS\n", i);
  }

  /* reconstruct from K shards (drop shards 1 and 3) */
  {
    const unsigned char *sp[K];
    unsigned char *rp[K];
    unsigned char idx[K];
    unsigned char rsWork[RS_WORK_SIZE(K)];
    unsigned char *recShards[K];
    unsigned char *recBuf;
    unsigned char *output;
    hufLen recLen;

    sp[0] = cShardBuf[0]; idx[0] = 0;
    sp[1] = cShardBuf[2]; idx[1] = 2;
    sp[2] = cShardBuf[4]; idx[2] = 4;
    sp[3] = cShardBuf[5]; idx[3] = 5;
    sp[4] = cShardBuf[6]; idx[4] = 6;

    for (i = 0; i < K; ++i) {
      recShards[i] = malloc(shardSize);
      if (!recShards[i]) {
        fprintf(stderr, "malloc\n");
        return (1);
      }
      rp[i] = recShards[i];
    }

    if (rsecDecode(sp, idx, rp, shardSize, K, M, rsWork)) {
      fprintf(stderr, "rsecDecode\n");
      return (1);
    }

    recBuf = malloc(paddedLen);
    if (!recBuf) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    for (i = 0; i < K; ++i)
      memcpy(recBuf + i * shardSize, recShards[i], shardSize);

    output = malloc(payloadLen + 256);
    if (!output) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    recLen = hufDecode(output, payloadLen + 256, recBuf, paddedLen);
    if (!recLen) {
      fprintf(stderr, "hufDecode\n");
      return (1);
    }

    if (recLen == payloadLen && memcmp(output, Payload, payloadLen) == 0)
      printf("  recovered payload: PASS\n");
    else {
      printf("  recovered payload: FAIL\n");
      fail = 1;
    }

    free(output);
    free(recBuf);
    for (i = 0; i < K; ++i)
      free(recShards[i]);
  }

  /* cleanup narrative test */
  for (i = 0; i < N; ++i)
    free(proofBuf[i]);
  free(vfWork);
  free(mkWork);
  for (i = 0; i < M; ++i)
    free(shardBuf[K + i]);
  free(padded);
  free(comp);

  /*
   * Test 2: parametric coverage (n edge cases, two hash sizes)
   */
  printf("\nTest 2: parametric coverage");
  for (i = 0; i < sizeof (nTests) / sizeof (nTests[0]); ++i) {
    if (parametricTest(&Hrmd, "rmd128", nTests[i]))
      fail = 1;
    if (parametricTest(&Hsha, "sha256", nTests[i]))
      fail = 1;
  }

  /*
   * Test 3: two leaf lengths under one root.  rsecMkHash hashes every leaf
   * at one length, so the tree is built by hand in its layout (leaf at slot
   * pw + j, node at slot j, root at slot 0; the layout rsecMkProof walks):
   * leaf 0 at L + 1 bytes, leaves 1 and 2 at L, the root bound at L.  The
   * root commits the length, so the odd leaf must not verify at its own
   * length while the others verify at theirs; bound at L + 1 instead, the
   * odd leaf verifies and the others must not.  No root admits both.
   */
  printf("\nTest 3: two leaf lengths under one root (rmd128)\n");
  {
    enum { L = 8, N3 = 3, PW = 4 };
    unsigned char leaf[N3][L + 1];
    unsigned char lens[2];
    unsigned char tag;
    unsigned char nb[2];
    unsigned char lb[4];
    unsigned char *w;
    unsigned char *pf;
    unsigned char *vf;
    unsigned char *x;
    void *hc;
    unsigned int b;
    unsigned int bound;
    unsigned int k;

    b = 1U << Hrmd.h;
    for (i = 0; i < N3; ++i)
      for (j = 0; j < L + 1; ++j)
        leaf[i][j] = i * 53 + j;
    lens[0] = L + 1;                   /* leaf 0 is the odd one */
    lens[1] = L;
    w = malloc(rsecMkWaSz(Hrmd.h, N3));
    pf = malloc(rsecMkPfSz(Hrmd.h, N3));
    vf = malloc(rsecMkVfSz(Hrmd.h));
    hc = Hrmd.a();
    if (!w || !pf || !vf || !hc) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    for (bound = L; bound <= L + 1; ++bound) {
      for (j = 0; j < PW; ++j) {
        if (j >= N3) {
          memset(w + (PW + j) * b, 0, b);
          continue;
        }
        tag = 0x00;
        Hrmd.i(hc);
        Hrmd.u(hc, &tag, 1);
        Hrmd.u(hc, leaf[j], lens[j ? 1 : 0]);
        Hrmd.f(hc, w + (PW + j) * b);
      }
      for (j = PW - 1; j; --j) {
        tag = 0x01;
        Hrmd.i(hc);
        Hrmd.u(hc, &tag, 1);
        Hrmd.u(hc, w + 2 * j * b, b << 1);
        Hrmd.f(hc, w + j * b);
      }
      tag = 0x02;
      nb[0] = N3 >> 8;
      nb[1] = N3 & 0xff;
      lb[0] = bound >> 24;
      lb[1] = (bound >> 16) & 0xff;
      lb[2] = (bound >> 8) & 0xff;
      lb[3] = bound & 0xff;
      Hrmd.i(hc);
      Hrmd.u(hc, &tag, 1);
      Hrmd.u(hc, nb, 2);
      Hrmd.u(hc, lb, 4);
      Hrmd.u(hc, w + b, b);
      Hrmd.f(hc, w);
      /* each leaf verified at its own length: exactly the leaves committed
       * at the bound length may pass */
      for (k = 0; k < N3; ++k) {
        unsigned int own;
        int pass;

        own = lens[k ? 1 : 0];
        if (!rsecMkProof(&Hrmd, N3, k, w, pf)) {
          fprintf(stderr, "rsecMkProof\n");
          return (1);
        }
        x = rsecMkExtract(&Hrmd, leaf[k], own, k, N3, pf, vf);
        pass = x && !memcmp(x, w, b);
        if (pass != (own == bound)) {
          printf("  root bound at %u, leaf %u at %u: %s: FAIL\n", bound, k, own
                ,pass ? "verified" : "refused");
          fail = 1;
        } else
          printf("  root bound at %u, leaf %u at %u: %s: PASS\n", bound, k, own
                ,pass ? "verified" : "refused");
      }
    }
    Hrmd.d(hc);
    free(w);
    free(pf);
    free(vf);
  }

  printf("\nAll tests completed%s.\n", fail ? " with FAILURES" : "");
  return (fail);
}
