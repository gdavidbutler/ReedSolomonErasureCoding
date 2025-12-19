/*
 * reedSolomon - A small C implementation of Reed-Solomon erasure coding
 * Copyright (C) 2025 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of reedSolomon
 *
 * reedSolomon is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * reedSolomon is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include "reedSolomon.h"

int
main(
  void
){
  static unsigned char Data[4][16] = {
    {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10}
   ,{0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20}
   ,{0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30}
   ,{0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40}
  };
  static unsigned char Parity[2][16];
  static unsigned char Recovered[sizeof (Data) / sizeof (Data[0])][16];
  static unsigned char Work[RS_WORK_SIZE(sizeof (Data) / sizeof (Data[0]))];
  const unsigned char *Dp[sizeof (Data) / sizeof (Data[0])];
  unsigned char *Pp[sizeof (Parity) / sizeof (Parity[0])];
  const unsigned char *Sp[sizeof (Data) / sizeof (Data[0])];
  unsigned char *Rp[sizeof (Data) / sizeof (Data[0])];
  unsigned char Idx[sizeof (Data) / sizeof (Data[0])];
  unsigned int i;
  unsigned int j;
  unsigned char Expected;
  int Err;

  /* Setup pointers */
  for (i = 0; i < sizeof (Dp) / sizeof (Dp[0]); ++i)
    Dp[i] = Data[i];
  for (i = 0; i < sizeof (Pp) / sizeof (Pp[0]); ++i)
    Pp[i] = Parity[i];
  for (i = 0; i < sizeof (Rp) / sizeof (Rp[0]); ++i)
    Rp[i] = Recovered[i];

  /* Encode */
  printf("Encoding 4 data shards into 2 parity shards...\n");
  Err = rsEncode(Dp, Pp, 16, sizeof (Dp) / sizeof (Dp[0]), sizeof (Pp) / sizeof (Pp[0]));
  if (Err) {
    printf("Encode failed: %d\n", Err);
    return (1);
  }

  printf("Data shards:\n");
  for (i = 0; i < 4; ++i) {
    printf("  %u:", i);
    for (j = 0; j < 16; ++j)
      printf(" %02x", Data[i][j]);
    printf("\n");
  }

  printf("Parity shards:\n");
  for (i = 0; i < 2; ++i) {
    printf("  %u:", 4 + i);
    for (j = 0; j < 16; ++j)
      printf(" %02x", Parity[i][j]);
    printf("\n");
  }

  /* Test 1: All data present */
  printf("\nTest 1: All data shards present\n");
  Sp[0] = Data[0]; Idx[0] = 0;
  Sp[1] = Data[1]; Idx[1] = 1;
  Sp[2] = Data[2]; Idx[2] = 2;
  Sp[3] = Data[3]; Idx[3] = 3;
  memset(Recovered, 0, sizeof (Recovered));
  Err = rsDecode(Sp, Idx, Rp, 16, sizeof (Dp) / sizeof (Dp[0]), sizeof (Pp) / sizeof (Pp[0]), Work);
  if (Err) {
    printf("Decode failed: %d\n", Err);
    return (1);
  }
  if (memcmp(Recovered, Data, sizeof (Data)) == 0)
    printf("  PASS\n");
  else
    printf("  FAIL\n");

  /* Test 2: Missing shard 0, use parity 0 */
  printf("\nTest 2: Missing shard 0, use parity 0\n");
  Sp[0] = Parity[0]; Idx[0] = 4;
  Sp[1] = Data[1];   Idx[1] = 1;
  Sp[2] = Data[2];   Idx[2] = 2;
  Sp[3] = Data[3];   Idx[3] = 3;
  memset(Recovered, 0, sizeof (Recovered));
  Err = rsDecode(Sp, Idx, Rp, 16, sizeof (Dp) / sizeof (Dp[0]), sizeof (Pp) / sizeof (Pp[0]), Work);
  if (Err) {
    printf("Decode failed: %d\n", Err);
    return (1);
  }
  if (memcmp(Recovered, Data, sizeof (Data)) == 0)
    printf("  PASS\n");
  else {
    printf("  FAIL\n");
    for (i = 0; i < 4; ++i) {
      printf("  Recovered %u:", i);
      for (j = 0; j < 16; ++j)
        printf(" %02x", Recovered[i][j]);
      printf("\n");
    }
  }

  /* Test 3: Missing shards 0 and 1, use both parities */
  printf("\nTest 3: Missing shards 0 and 1, use both parities\n");
  Sp[0] = Parity[0]; Idx[0] = 4;
  Sp[1] = Parity[1]; Idx[1] = 5;
  Sp[2] = Data[2];   Idx[2] = 2;
  Sp[3] = Data[3];   Idx[3] = 3;
  memset(Recovered, 0, sizeof (Recovered));
  Err = rsDecode(Sp, Idx, Rp, 16, sizeof (Dp) / sizeof (Dp[0]), sizeof (Pp) / sizeof (Pp[0]), Work);
  if (Err) {
    printf("Decode failed: %d\n", Err);
    return (1);
  }
  if (memcmp(Recovered, Data, sizeof (Data)) == 0)
    printf("  PASS\n");
  else {
    printf("  FAIL\n");
    for (i = 0; i < 4; ++i) {
      printf("  Recovered %u:", i);
      for (j = 0; j < 16; ++j)
        printf(" %02x", Recovered[i][j]);
      printf("\n");
    }
  }

  /* Test 4: Missing shards 1 and 3 */
  printf("\nTest 4: Missing shards 1 and 3, use both parities\n");
  Sp[0] = Data[0];   Idx[0] = 0;
  Sp[1] = Parity[0]; Idx[1] = 4;
  Sp[2] = Data[2];   Idx[2] = 2;
  Sp[3] = Parity[1]; Idx[3] = 5;
  memset(Recovered, 0, sizeof (Recovered));
  Err = rsDecode(Sp, Idx, Rp, 16, sizeof (Dp) / sizeof (Dp[0]), sizeof (Pp) / sizeof (Pp[0]), Work);
  if (Err) {
    printf("Decode failed: %d\n", Err);
    return (1);
  }
  if (memcmp(Recovered, Data, sizeof (Data)) == 0)
    printf("  PASS\n");
  else {
    printf("  FAIL\n");
    for (i = 0; i < 4; ++i) {
      printf("  Recovered %u:", i);
      for (j = 0; j < 16; ++j)
        printf(" %02x", Recovered[i][j]);
      printf("\n");
    }
  }

  /* Test 5: m=1 XOR fast path */
  printf("\nTest 5: m=1 (XOR fast path) encode and decode\n");
  Pp[0] = Parity[0];
  Err = rsEncode(Dp, Pp, 16, 4, 1);
  if (Err) {
    printf("Encode failed: %d\n", Err);
    return (1);
  }
  printf("  Parity (m=1):");
  for (j = 0; j < 16; ++j)
    printf(" %02x", Parity[0][j]);
  printf("\n");
  /* Verify parity is XOR of all data */
  for (j = 0; j < 16; ++j) {
    Expected = Data[0][j] ^ Data[1][j] ^ Data[2][j] ^ Data[3][j];
    if (Parity[0][j] != Expected) {
      printf("  FAIL: parity mismatch at byte %u\n", j);
      return (1);
    }
  }
  printf("  Parity verified as XOR of all data shards\n");
  /* Decode with shard 2 missing */
  Sp[0] = Data[0];   Idx[0] = 0;
  Sp[1] = Data[1];   Idx[1] = 1;
  Sp[2] = Parity[0]; Idx[2] = 4;
  Sp[3] = Data[3];   Idx[3] = 3;
  memset(Recovered, 0, sizeof (Recovered));
  Err = rsDecode(Sp, Idx, Rp, 16, 4, 1, Work);
  if (Err) {
    printf("Decode failed: %d\n", Err);
    return (1);
  }
  if (memcmp(Recovered, Data, sizeof (Data)) == 0)
    printf("  PASS\n");
  else {
    printf("  FAIL\n");
    for (i = 0; i < 4; ++i) {
      printf("  Recovered %u:", i);
      for (j = 0; j < 16; ++j)
        printf(" %02x", Recovered[i][j]);
      printf("\n");
    }
  }

  printf("\nAll tests completed.\n");
  return (0);
}
