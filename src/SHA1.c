#define __STRICT_ANSI__
#include <stdint.h>
#include <string.h>

#include "jwevans_crypto/SHA1.h"

/////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////

const uint32_t K[80] = {
  0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
  0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
  0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
  0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
  0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
  0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
  0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
  0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
  0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
  0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
  0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
  0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
  0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
  0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
  0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
  0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
};

const uint32_t H_0[5] = {
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

const uint8_t PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/////////////////////////////////////////////////////////////////////
// Private Function Declarations
/////////////////////////////////////////////////////////////////////

uint32_t __sha1_Ch (uint32_t x, uint32_t y, uint32_t z);
uint32_t __sha1_Parity (uint32_t x, uint32_t y, uint32_t z);
uint32_t __sha1_Maj (uint32_t x, uint32_t y, uint32_t z);
uint32_t __sha1_f_t (uint32_t t, uint32_t x, uint32_t y, uint32_t z);
uint32_t __sha1_rotate_left (uint32_t n, uint32_t x);
void __sha1_process_block (SHA1_ref self);

/////////////////////////////////////////////////////////////////////
// Public Functions
/////////////////////////////////////////////////////////////////////

void
sha1_initialize (SHA1_ref self)
{
  self->length = 0;

  memset (self->block.bytes, 0, 64);

  self->H[0] = H_0[0];
  self->H[1] = H_0[1];
  self->H[2] = H_0[2];
  self->H[3] = H_0[3];
  self->H[4] = H_0[4];
}

void
sha1_update (SHA1_ref self, const uint8_t *const message,
             const uint64_t length)
{
  for (size_t i = 0; i < length; i++)
    {
      self->block.bytes[self->length % 64] = message[i];
      self->length += 1;

      if (self->length % 64 == 0)
        {
          __sha1_process_block (self);
        }
    }
}

void
sha1_finalize (SHA1_ref self, uint8_t *const hash)
{
  uint64_t length_bits = self->length * 8;
  uint64_t index = self->length % 64;
  uint64_t needed_padding
      = (index < 56) ? (56 - index) : (120 - index);

  sha1_update (self, PADDING, needed_padding);

  const uint8_t length[8] = {
    (uint8_t)((length_bits >> 56) & 0xFF),
    (uint8_t)((length_bits >> 48) & 0xFF),
    (uint8_t)((length_bits >> 40) & 0xFF),
    (uint8_t)((length_bits >> 32) & 0xFF),
    (uint8_t)((length_bits >> 24) & 0xFF),
    (uint8_t)((length_bits >> 16) & 0xFF),
    (uint8_t)((length_bits >> 8) & 0xFF),
    (uint8_t)((length_bits >> 0) & 0xFF),
  };
  sha1_update (self, length, 8);

  for (size_t i = 0; i < 5; i++)
    {
      hash[(i * 4) + 0] = (uint8_t)((self->H[i] >> 24) & 0xFF);
      hash[(i * 4) + 1] = (uint8_t)((self->H[i] >> 16) & 0xFF);
      hash[(i * 4) + 2] = (uint8_t)((self->H[i] >> 8) & 0xFF);
      hash[(i * 4) + 3] = (uint8_t)((self->H[i] >> 0) & 0xFF);
    }

  memset (self, 0, sizeof (SHA1));
}

/////////////////////////////////////////////////////////////////////
// Private Function Definitions
/////////////////////////////////////////////////////////////////////

uint32_t
__sha1_Ch (uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ ((~x) & z);
}

uint32_t
__sha1_Parity (uint32_t x, uint32_t y, uint32_t z)
{
  return x ^ y ^ z;
}

uint32_t
__sha1_Maj (uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t
__sha1_f_t (uint32_t t, uint32_t x, uint32_t y, uint32_t z)
{
  if (t < 20)
    {
      return __sha1_Ch (x, y, z);
    }
  else if (t < 40)
    {
      return __sha1_Parity (x, y, z);
    }
  else if (t < 60)
    {
      return __sha1_Maj (x, y, z);
    }
  else
    {
      return __sha1_Parity (x, y, z);
    }
}

uint32_t
__sha1_rotate_left (uint32_t n, uint32_t x)
{
  return (x << n) | (x >> (32 - n));
}

void
__sha1_process_block (SHA1_ref self)
{
  uint32_t W[80] = { 0 };

  /* Prepare Message Schedule */
  for (size_t t = 0; t < 80; t++)
    {
      if (t < 16)
        {
          W[t] = ((uint32_t)(self->block.bytes[(t * 4) + 0]) << 24)
                 | ((uint32_t)(self->block.bytes[(t * 4) + 1]) << 16)
                 | ((uint32_t)(self->block.bytes[(t * 4) + 2]) << 8)
                 | ((uint32_t)(self->block.bytes[(t * 4) + 3]) << 0);
        }
      else
        {
          W[t] = __sha1_rotate_left (1, W[t - 3] ^ W[t - 8]
                                            ^ W[t - 14] ^ W[t - 16]);
        }
    }

  uint32_t a = self->H[0], b = self->H[1], c = self->H[2],
           d = self->H[3], e = self->H[4];

  /* Perform Hashing */
  for (size_t t = 0; t < 80; t++)
    {
      uint32_t T = __sha1_rotate_left (5, a) + __sha1_f_t (t, b, c, d)
                   + e + K[t] + W[t];
      e = d;
      d = c;
      c = __sha1_rotate_left (30, b);
      b = a;
      a = T;
    }

  /* Update Intermediate */
  self->H[0] += a;
  self->H[1] += b;
  self->H[2] += c;
  self->H[3] += d;
  self->H[4] += e;
}
