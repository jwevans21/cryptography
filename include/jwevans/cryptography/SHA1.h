#ifndef __JWEVANS_CRYPTO_H_
#define __JWEVANS_CRYPTO_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  ///////////////////////////////////////////////////////////////////
  // Structure Definition for Hashing
  ///////////////////////////////////////////////////////////////////

  typedef struct SHA1_ctx
  {
    uint64_t length;
    union
    {
      uint32_t words[16];
      uint8_t bytes[64];
    } block;
    uint32_t H[5];
  } SHA1;

  typedef SHA1 *const SHA1_ref;

  ///////////////////////////////////////////////////////////////////
  // Public Functions for Updating
  ///////////////////////////////////////////////////////////////////

  ///
  /// Initializes the SHA1 structure with the initial values
  ///
  /// @param self Pointer to the SHA1 structure to initialize
  ///
  void sha1_initialize (SHA1_ref self);

  void sha1_update (SHA1_ref, const uint8_t *const, const uint64_t);

  void sha1_finalize (SHA1_ref, uint8_t *const);

#ifdef __cplusplus
} /* EXTERN C */
#endif

#endif
