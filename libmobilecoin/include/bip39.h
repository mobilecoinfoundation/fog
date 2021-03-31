#ifndef BIP39_H_
#define BIP39_H_

#include "common.h"

/* ==================== BIP39 ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== McBip39 ==== */

/// # Preconditions
///
/// * `entropy` - length must be a multiple of 4 and between 16 and 32,
///   inclusive, in bytes.
char* MC_NULLABLE mc_bip39_mnemonic_from_entropy(
  const McBuffer* MC_NONNULL entropy
)
MC_ATTRIBUTE_NONNULL(1);

/// # Preconditions
///
/// * `prefix` - must be a nul-terminated C string containing valid UTF-8.
char* MC_NULLABLE mc_bip39_words_by_prefix(
  const char* MC_NONNULL prefix
)
MC_ATTRIBUTE_NONNULL(1);


#ifdef __cplusplus
}
#endif

#endif /* !BIP39_H_ */
