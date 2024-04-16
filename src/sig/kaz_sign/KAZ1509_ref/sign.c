#include "api.h"
#include "gmp.h"
#include "kaz_api.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_content(char *tag, unsigned char *buffer,
                          unsigned long long length) {
  printf("%s : ", tag);
  for (int i = 0; i < length; i++)
    printf("%02x", buffer[i]);
  printf("\n");
}

int kaz_sign_1_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
  KS1_KAZ_DS_KeyGen(pk, sk);

  if (sizeof(pk) != 0 || sizeof(sk) != 0)
    return 0;
  else
    return -4;
}

int kaz_sign_1_crypto_sign(unsigned char *sm, unsigned long long *smlen,
                           const unsigned char *m, unsigned long long mlen,
                           const unsigned char *sk) {
  int status = KS1_KAZ_DS_SIGNATURE(sm, smlen, m, mlen, sk);

  if (*smlen > mlen && status == 0)
    return 0;
  else
    return status;
}

int kaz_sign_1_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                const unsigned char *sm,
                                unsigned long long smlen,
                                const unsigned char *pk) {

  int status = KS1_KAZ_DS_VERIFICATION(m, mlen, sm, smlen, pk);

  if (status == 0) {
    return 0;
  } else
    return status;
}

int kaz_sign_1_ref_keypair(unsigned char *public_key,
                           unsigned char *secret_key) {
  KS1_KAZ_DS_KeyGen(public_key, secret_key);

#ifdef KS1_DEBUG
  printf("pk length : %d\n", KS1_CRYPTO_PUBLICKEYBYTES);
  print_content("pk", public_key, KS1_CRYPTO_PUBLICKEYBYTES);
  printf("sk length : %d\n", KS1_CRYPTO_SECRETKEYBYTES);
  print_content("sk", secret_key, KS1_CRYPTO_SECRETKEYBYTES);
#endif

  if (sizeof(public_key) != 0 || sizeof(secret_key) != 0)
    return 0;
  else
    return -4;
}

int kaz_sign_1_ref_signature(unsigned char *signature, unsigned int *slen,
                             const unsigned char *message,
                             const unsigned int mlen,
                             const unsigned char *secret_key) {
  int status =
      KS1_KAZ_DS_SIGNATURE_DETACHED(signature, slen, message, mlen, secret_key);

#ifdef KS1_DEBUG
  printf("smlen sign : %u\n", *slen);
  printf("mlen sign : %u\n", mlen);
  print_content("sm sign : ", signature, *slen);
  print_content("m sign : ", message, mlen);
#endif

  if (status == 0)
    return 0;
  else
    return status;
}

int kaz_sign_1_ref_verify(const unsigned char *signature, unsigned int slen,
                          const unsigned char *message, unsigned int mlen,
                          const unsigned char *public_key) {

#ifdef KS1_DEBUG
  printf("smlen v : %u\n", slen);
  print_content("sm v : ", signature, slen);
  printf("mlen v : %u\n", mlen);
  print_content("m v : ", message, mlen);
#endif

  int status = KS1_KAZ_DS_VERIFICATION_DETACHED(message, mlen, signature, slen,
                                                public_key);

  if (status == 0) {
    return 0;
  } else
    return status;
}
