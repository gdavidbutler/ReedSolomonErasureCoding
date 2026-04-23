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

#include "rsecMk.h"

/* Domain separation tags: distinguish leaf hash input (arbitrary length s)
 * from internal-node hash input (2^(h+1) bytes of children). Prefixing
 * rules out leaf/node confusion from second-preimage attacks. */
static const unsigned char LeafTag = 0x00;
static const unsigned char NodeTag = 0x01;

/* next power of 2 >= n, for n in 1..256 */
static unsigned int
nextPow2(
  unsigned int n
){
  unsigned int p;

  for (p = 1; p < n; p <<= 1)
    ;
  return (p);
}

/* log2(p) for p that is a power of 2 */
static unsigned int
log2p(
  unsigned int p
){
  unsigned int d;

  for (d = 0; (1U << d) < p; ++d)
    ;
  return (d);
}

unsigned int
rsecMkWaSz(
  unsigned char h
 ,unsigned int n
){
  unsigned int p;

  if (n < 1 || n > 256)
    return (0);
  p = nextPow2(n);
  /* 2*p hash-sized slots (index 0 unused, 1..2p-1 are tree nodes) */
  return (p << (h + 1));
}

unsigned int
rsecMkPfSz(
  unsigned char h
 ,unsigned int n
){
  unsigned int p;

  if (n < 1 || n > 256)
    return (0);
  p = nextPow2(n);
  /* one sibling hash per tree level */
  return (log2p(p) << h);
}

unsigned int
rsecMkVfSz(
  unsigned char h
){
  /* current hash (2^h) */
  return (1U << h);
}

unsigned char *
rsecMkHash(
  const rsecMkHsh_t *h
 ,const unsigned char *const *s
 ,unsigned int l
 ,unsigned int n
 ,unsigned char *w
){
  void *c;
  unsigned int p;
  unsigned int b;
  unsigned int i;
  unsigned int j;
  unsigned char *np;
  unsigned char *cp;

  if (!h || !s || !l || n < 1 || n > 256 || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  p = nextPow2(n);
  if (!(c = h->a()))
    return (0);

  /* hash real shard leaves with LeafTag prefix */
  np = w + p * b;
  for (i = 0; i < n; ++i) {
    h->i(c);
    h->u(c, &LeafTag, 1);
    h->u(c, s[i], l);
    h->f(c, np);
    np += b;
  }

  /* zero padding leaves (never addressable via Extract: i >= n is rejected) */
  for (i = n; i < p; ++i)
    for (j = 0; j < b; ++j)
      *np++ = 0;

  /* build tree bottom-up: tree[i] = H(NodeTag || tree[2i] || tree[2i+1]) */
  np = w + (p - 1) * b;
  cp = np + (p - 1) * b;
  for (i = p - 1; i > 0; --i) {
    h->i(c);
    h->u(c, &NodeTag, 1);
    h->u(c, cp, b << 1);
    h->f(c, np);
    np -= b;
    cp -= b << 1;
  }

  if (h->d)
    h->d(c);
  return (w + b); /* tree[1] = root */
}

unsigned char *
rsecMkProof(
  const rsecMkHsh_t *h
 ,unsigned int n
 ,unsigned int i
 ,const unsigned char *w
 ,unsigned char *p
){
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned int j;
  const unsigned char *sp;

  if (!h || n < 1 || n > 256 || i >= n || !w || !p)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  node = pw + i;

  /* walk from leaf to root, copying sibling hashes */
  while (node > 1) {
    sp = w + (node ^ 1) * b;
    for (j = 0; j < b; ++j)
      *p++ = sp[j];
    node >>= 1;
  }
  return (p);
}

unsigned char *
rsecMkExtract(
  const rsecMkHsh_t *h
 ,const unsigned char *s
 ,unsigned int l
 ,unsigned int i
 ,unsigned int n
 ,const unsigned char *p
 ,unsigned char *w
){
  void *c;
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned char *cur;
  const unsigned char *lo;
  const unsigned char *hi;

  if (!h || !s || !l || n < 1 || n > 256 || i >= n || !p || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  cur = w;

  if (!(c = h->a()))
    return (0);

  /* hash shard data with LeafTag to get leaf hash */
  h->i(c);
  h->u(c, &LeafTag, 1);
  h->u(c, s, l);
  h->f(c, cur);

  /* walk up the tree, combining with proof siblings */
  node = pw + i;
  while (node > 1) {
    if (node & 1) {
      lo = p; hi = cur;   /* right child: sibling is left */
    } else {
      lo = cur; hi = p;   /* left child: sibling is right */
    }
    p += b;
    h->i(c);
    h->u(c, &NodeTag, 1);
    h->u(c, lo, b);
    h->u(c, hi, b);
    h->f(c, cur);
    node >>= 1;
  }

  if (h->d)
    h->d(c);
  return (cur);
}
