#ifndef PQCLEAN_MCELIECE460896F_CLEAN_crypto_int32_h
#define PQCLEAN_MCELIECE460896F_CLEAN_crypto_int32_h

#include <inttypes.h>
typedef int32_t crypto_int32;

#include "namespace.h"

#define crypto_int32_negative_mask CRYPTO_NAMESPACE(crypto_int32_negative_mask)
crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x);
#define crypto_int32_nonzero_mask CRYPTO_NAMESPACE(crypto_int32_nonzero_mask)
crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x);
#define crypto_int32_zero_mask CRYPTO_NAMESPACE(crypto_int32_zero_mask)
crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x);
#define crypto_int32_positive_mask CRYPTO_NAMESPACE(crypto_int32_positive_mask)
crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x);
#define crypto_int32_unequal_mask CRYPTO_NAMESPACE(crypto_int32_unequal_mask)
crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x, crypto_int32 crypto_int32_y);
#define crypto_int32_equal_mask CRYPTO_NAMESPACE(crypto_int32_equal_mask)
crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x, crypto_int32 crypto_int32_y);
#define crypto_int32_smaller_mask CRYPTO_NAMESPACE(crypto_int32_smaller_mask)
crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x, crypto_int32 crypto_int32_y);
#define crypto_int32_min CRYPTO_NAMESPACE(crypto_int32_min)
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x, crypto_int32 crypto_int32_y);
#define crypto_int32_max CRYPTO_NAMESPACE(crypto_int32_max)
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x, crypto_int32 crypto_int32_y);
#define crypto_int32_minmax CRYPTO_NAMESPACE(crypto_int32_minmax)
void crypto_int32_minmax(crypto_int32 *crypto_int32_a, crypto_int32 *crypto_int32_b);

#endif
