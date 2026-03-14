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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsec.h"
#include "rsecMk.h"
#include "rmd128.h"
#include "huf.h"

static void *
hashAllocate(
  void
){
  return (malloc(rmd128tsize()));
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
  rsecMkHsh_t Hsh;
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

  fail = 0;
  payloadLen = sizeof (Payload) - 1;

  /* hash context: rmd128 (2^4 = 16 bytes) */
  Hsh.a = hashAllocate;
  Hsh.i = (void(*)(void *))rmd128init;
  Hsh.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  Hsh.f = (void(*)(void *, unsigned char *))rmd128final;
  Hsh.d = free;
  Hsh.h = 4;

  printf("Payload (%u bytes): %.*s\n", payloadLen, (int)payloadLen, Payload);

  /*
   * Step 1: Huffman compress
   * Depending on canonicalHuffman to recover the original length
   * from the padded compressed data.
   */
  printf("\nStep 1: Huffman compress\n");
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

  /*
   * Step 2: Pad and RS encode
   */
  printf("\nStep 2: RS encode (k=%u m=%u n=%u)\n", (unsigned)K, (unsigned)M, (unsigned)N);
  shardSize = ((unsigned int)compLen + K - 1) / K;
  paddedLen = K * shardSize;
  printf("  Shard size: %u bytes, padded total: %u bytes\n", shardSize, paddedLen);

  padded = calloc(paddedLen, 1);
  if (!padded) {
    fprintf(stderr, "calloc\n");
    return (1);
  }
  memcpy(padded, comp, compLen);

  /* data shards point into padded buffer, parity shards are separate */
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

  /*
   * Step 3: Build Merkle tree
   */
  printf("\nStep 3: Merkle tree (n=%u)\n", (unsigned)N);
  waSz = rsecMkWaSz(Hsh.h, N);
  pfSz = rsecMkPfSz(Hsh.h, N);
  printf("  Work area: %u bytes, proof size: %u bytes\n", waSz, pfSz);

  mkWork = malloc(waSz);
  if (!mkWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  root = rsecMkHash(&Hsh, cShardBuf, shardSize, N, mkWork);
  if (!root) {
    fprintf(stderr, "rsecMkHash\n");
    return (1);
  }
  printf("  Root:");
  for (i = 0; i < (1U << Hsh.h); ++i)
    printf(" %02x", root[i]);
  printf("\n");

  /*
   * Step 4: Extract proofs and verify all shards
   */
  printf("\nStep 4: Verify all shards\n");
  vfWork = malloc(rsecMkVfSz(Hsh.h));
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
    if (!rsecMkProof(&Hsh, N, i, mkWork, proofBuf[i])) {
      fprintf(stderr, "rsecMkProof %u\n", i);
      return (1);
    }
    extracted = rsecMkExtract(&Hsh, cShardBuf[i], shardSize, i, N,
     proofBuf[i], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0) {
      printf("  shard %u: FAIL\n", i);
      fail = 1;
    } else
      printf("  shard %u: PASS\n", i);
  }

  /*
   * Step 5: Corruption detection
   */
  printf("\nStep 5: Corruption detection\n");
  {
    unsigned char *extracted;

    shardBuf[0][0] ^= 0xff;
    extracted = rsecMkExtract(&Hsh, cShardBuf[0], shardSize, 0, N,
     proofBuf[0], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0)
      printf("  Corrupted shard: FAIL (expected)\n");
    else {
      printf("  Corrupted shard: PASS (unexpected!)\n");
      fail = 1;
    }
    shardBuf[0][0] ^= 0xff; /* restore */

    extracted = rsecMkExtract(&Hsh, cShardBuf[0], shardSize, 1, N,
     proofBuf[0], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0)
      printf("  Wrong index: FAIL (expected)\n");
    else {
      printf("  Wrong index: PASS (unexpected!)\n");
      fail = 1;
    }
  }

  /*
   * Step 6: Reconstruct from K shards (missing shards 1 and 3)
   */
  printf("\nStep 6: Reconstruct (missing shards 1 and 3)\n");
  {
    const unsigned char *sp[K];
    unsigned char *rp[K];
    unsigned char idx[K];
    unsigned char rsWork[RS_WORK_SIZE(K)];
    unsigned char *recShards[K];
    unsigned char *recBuf;
    unsigned char *output;
    hufLen recLen;

    /* use shards 0, 2, 4, 5, 6 */
    sp[0] = cShardBuf[0]; idx[0] = 0;
    sp[1] = cShardBuf[2]; idx[1] = 2;
    sp[2] = cShardBuf[4]; idx[2] = 4;
    sp[3] = cShardBuf[5]; idx[3] = 5;
    sp[4] = cShardBuf[6]; idx[4] = 6;

    /* verify received shards */
    for (i = 0; i < K; ++i) {
      unsigned char *extracted;

      extracted = rsecMkExtract(&Hsh, sp[i], shardSize, idx[i], N,
       proofBuf[idx[i]], vfWork);
      if (!extracted
       || memcmp(extracted, root, 1U << Hsh.h) != 0) {
        printf("  Verify shard %u: FAIL\n", (unsigned)idx[i]);
        return (1);
      }
    }
    printf("  All received shards verified\n");

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
    printf("  RS decode: OK\n");

    /* concatenate recovered data shards */
    recBuf = malloc(paddedLen);
    if (!recBuf) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    for (i = 0; i < K; ++i)
      memcpy(recBuf + i * shardSize, recShards[i], shardSize);

    /* Huffman decode */
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
    printf("  Decompressed: %u bytes\n", (unsigned int)recLen);

    if (recLen == payloadLen && memcmp(output, Payload, payloadLen) == 0)
      printf("  Payload match: PASS\n");
    else {
      printf("  Payload match: FAIL\n");
      fail = 1;
    }

    free(output);
    free(recBuf);
    for (i = 0; i < K; ++i)
      free(recShards[i]);
  }

  /* cleanup */
  for (i = 0; i < N; ++i)
    free(proofBuf[i]);
  free(vfWork);
  free(mkWork);
  for (i = 0; i < M; ++i)
    free(shardBuf[K + i]);
  free(padded);
  free(comp);

  printf("\nAll tests completed%s.\n", fail ? " with FAILURES" : "");
  return (fail);
}
