#include <cstddef>
#include <stdint.h>

#include <gtest/gtest.h>

#include "jwevans/cryptography/SHA1.h"

bool
compare_hashes (uint8_t *expected, uint8_t *result, size_t length)
{
  for (size_t i = 0; i < length; i++)
    {
      EXPECT_EQ (expected[i], result[i]);
    }

  return true;
}

TEST (SHA1, EmptyData)
{
  const char *data = "";

  SHA1 ctx = {};
  uint8_t expected[20] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
  };
  uint8_t result[20] = { 0 };

  sha1_initialize (&ctx);
  sha1_update (&ctx, (uint8_t *)data, strlen (data));
  sha1_finalize (&ctx, result);

  compare_hashes (expected, result, 20);
}

TEST (SHA1, OneBlock)
{
  const char *data = "abc";

  SHA1 ctx = {};
  uint8_t expected[20] = {
    0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
    0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
  };
  uint8_t result[20] = { 0 };

  sha1_initialize (&ctx);
  sha1_update (&ctx, (uint8_t *)data, strlen (data));
  sha1_finalize (&ctx, result);

  compare_hashes (expected, result, 20);
}

TEST (SHA1, TwoBlock)
{
  const char *data
      = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

  SHA1 ctx = {};
  uint8_t expected[20] = {
    0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
    0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1,
  };
  uint8_t result[20] = { 0 };

  sha1_initialize (&ctx);
  sha1_update (&ctx, (uint8_t *)data, strlen (data));
  sha1_finalize (&ctx, result);

  compare_hashes (expected, result, 20);
}