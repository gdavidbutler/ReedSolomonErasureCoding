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

#include <stdio.h>

/*
 * Generate GF(2^8) tables with primitive polynomial 0x11d
 */

int
main(
  void
){
  unsigned char Exp[512];
  unsigned char Log[256];
  unsigned int x;
  unsigned int i;
  unsigned int j;
  unsigned int inv4;
  unsigned int prod;

  x = 1;
  for (i = 0; i < 255; ++i) {
    Exp[i] = (unsigned char)x;
    Log[x] = (unsigned char)i;
    x <<= 1;
    if (x & 0x100)
      x ^= 0x11d;
  }
  Exp[255] = Exp[0];
  Log[0] = 0;

  /* Double at offset 255 since α^255 = 1 (group order is 255) */
  for (i = 0; i < 256; ++i)
    Exp[255 + i] = Exp[i];

  /* Verify */
  inv4 = Exp[255 - Log[4]];
  prod = Exp[Log[4] + Log[inv4]];
  printf("4 = 4, inv(4) = %u, 4 * inv(4) = %u\n\n", inv4, prod);

  printf("static const unsigned char GfExp[512] = {\n");
  for (i = 0; i < 32; ++i) {
    printf("  ");
    for (j = 0; j < 16; ++j) {
      printf("0x%02x", Exp[i * 16 + j]);
      if (i * 16 + j < 511)
        printf(",");
    }
    printf("\n");
  }
  printf("};\n\n");

  printf("static const unsigned char GfLog[256] = {\n");
  for (i = 0; i < 16; ++i) {
    printf("  ");
    for (j = 0; j < 16; ++j) {
      printf("0x%02x", Log[i * 16 + j]);
      if (i * 16 + j < 255)
        printf(",");
    }
    printf("\n");
  }
  printf("};\n");

  return (0);
}
