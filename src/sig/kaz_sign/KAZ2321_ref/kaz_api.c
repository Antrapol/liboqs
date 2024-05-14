#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "gmp.h"
#include "kaz_api.h"
#include "rng.h"
#include "sha256.h"

static void HashMsg(const unsigned char *msg, unsigned long long mlen,
                    unsigned char buf[32]) {
  sha256_t hash;
  sha256_init(&hash);
  sha256_update(&hash, msg, mlen);
  sha256_final(&hash, buf);
}

static void KAZ_DS_CRT(int size, mpz_t *x, mpz_t *modulus, mpz_t crt) {
  mpz_t *c = malloc(size * sizeof(mpz_t));
  mpz_t u, prod;

  mpz_inits(u, prod, NULL);
  for (int i = 0; i < size; i++)
    mpz_init(c[i]);

  mpz_set_ui(c[0], 0);

  for (int i = 1; i < size; i++) {
    mpz_set_ui(c[i], 1);

    for (int j = 0; j <= i - 1; j++) {
      mpz_invert(u, modulus[j], modulus[i]);
      mpz_mul(c[i], c[i], u);
      mpz_mod(c[i], c[i], modulus[i]);
    }
  }

  mpz_set(u, x[0]);
  mpz_set(crt, u);

  for (int i = 1; i < size; i++) {
    mpz_sub(u, x[i], crt);
    mpz_mul(u, u, c[i]);
    mpz_mod(u, u, modulus[i]);
    mpz_set_ui(prod, 1);

    for (int j = 0; j <= i - 1; j++)
      mpz_mul(prod, prod, modulus[j]);

    mpz_mul(u, u, prod);
    mpz_add(crt, crt, u);
  }

  for (int i = 0; i < size; i++)
    mpz_clear(c[i]);

  if(c != NULL)
    free(c);

  mpz_clears(u, prod, NULL);
}

static int KAZ_DS_GET_PFactors(mpz_t input) {
  mpz_t inp, prod;
  mpz_inits(inp, prod, NULL);
  mpz_set(inp, input);
  mpz_set_ui(prod, 1);

  int div = 2, count = 0;
  int i = 0;

  while (mpz_cmp_ui(inp, 1) > 0) {
    while (mpz_divisible_ui_p(inp, div) > 0) {
      count++;
      mpz_divexact_ui(inp, inp, div);
      mpz_mul_ui(prod, prod, div);
    }

    if (mpz_cmp_ui(prod, 1) > 0) {
      i++;
    }
    mpz_set_ui(prod, 1);
    div++;
    count = 0;
  }

  mpz_clears(inp, prod, NULL);

  return i;
}

static void KAZ_DS_PFactors(mpz_t ord, mpz_t *pfacs, int *qlist, int *elist) {
  mpz_t inp, prod;
  mpz_inits(inp, prod, NULL);
  mpz_set(inp, ord);
  mpz_set_ui(prod, 1);

  int div = 2, count = 0;
  unsigned long long i = 0;

  while (mpz_cmp_ui(inp, 1) > 0) {
    while (mpz_divisible_ui_p(inp, div) > 0) {
      count++;
      mpz_divexact_ui(inp, inp, div);
      mpz_mul_ui(prod, prod, div);
    }

    if (mpz_cmp_ui(prod, 1) > 0) {

      mpz_set(pfacs[i], prod);
      qlist[i] = div;
      elist[i] = count;
      i++;
    }
    mpz_set_ui(prod, 1);
    div++;
    count = 0;
  }

  mpz_clears(inp, prod, NULL);
}

static void KAZ_DS_RANDOM(int lb, int ub, mpz_t out) {
  mpz_t lbound, ubound;

  unsigned int r = 0;

  gmp_randstate_t gmpRandState;
  gmp_randinit_mt(gmpRandState);
  mpz_inits(lbound, ubound, NULL);

  mpz_ui_pow_ui(lbound, 2, lb);
  mpz_ui_pow_ui(ubound, 2, ub);

  unsigned int sd = 0;
  FILE *h = fopen("/dev/urandom", "rb");
  int read = fread(&r, sizeof(unsigned int), 1, h);

  if(read > 0) {}

  do {
    gmp_randseed_ui(gmpRandState, r + sd);
    mpz_urandomb(out, gmpRandState, ub);
    sd += 1;
  } while ((mpz_cmp(out, lbound) == -1) || (mpz_cmp(out, ubound) == 1));

  fclose(h);
  mpz_clears(lbound, ubound, NULL);
  gmp_randclear(gmpRandState);
}

static void KAZ_DS_FILTER(mpz_t VQ, mpz_t V2, mpz_t GRg, mpz_t Q, mpz_t qQ,
                          mpz_t GRgQ, mpz_t SF2) {
  mpz_t modulus, GCD, soln, SATU, check1, check2;

  mpz_inits(modulus, GCD, soln, SATU, check1, check2, NULL);

  int nGRgQ = KAZ_DS_GET_PFactors(GRgQ);

  mpz_t *pFactors = NULL; 
  int *p = NULL;
  int *e = NULL;
  mpz_t *x = NULL;
  mpz_t *y = NULL;
  
  pFactors = malloc(nGRgQ * sizeof(mpz_t));
  p = malloc(nGRgQ * sizeof(int));
  e = malloc(nGRgQ * sizeof(int));

  for (int i = 0; i < nGRgQ; i++)
    mpz_init(pFactors[i]);
  for (int i = 0; i < nGRgQ; i++)
    p[i] = 0;
  for (int i = 0; i < nGRgQ; i++)
    e[i] = 0;

  KAZ_DS_PFactors(GRgQ, pFactors, p, e);

  x = malloc(2 * sizeof(mpz_t));
  y = malloc(2 * sizeof(mpz_t));

  for (int i = 0; i < 2; i++)
    mpz_init(x[i]);
  for (int i = 0; i < 2; i++)
    mpz_init(y[i]);

  mpz_set_ui(SF2, 0);
  mpz_set_ui(modulus, 1);

  for (int i = 0; i < nGRgQ; i++) {
    mpz_set_ui(soln, 0);
    while (mpz_cmp(soln, pFactors[i]) < 0) {
      mpz_gcd(GCD, Q, pFactors[i]);
      mpz_mod(check1, soln, GCD);
      mpz_mod(check2, SATU, GCD);
      if (mpz_cmp(check1, check2) != 0) {
        mpz_add_ui(soln, soln, 1);
        continue;
      }

      mpz_gcd(GCD, GRg, pFactors[i]);
      mpz_mod(check1, soln, GCD);
      mpz_mod(check2, VQ, GCD);
      if (mpz_cmp(check1, check2) != 0) {
        mpz_add_ui(soln, soln, 1);
        continue;
      }

      mpz_gcd(GCD, qQ, pFactors[i]);
      mpz_mul(check1, soln, Q);
      mpz_mod(check1, check1, GCD);
      mpz_gcd(GCD, GRgQ, pFactors[i]);
      mpz_mod(check2, V2, GCD);
      if (mpz_cmp(check1, check2) != 0) {
        mpz_add_ui(soln, soln, 1);
        continue;
      }

      break;
    }

    mpz_set(x[0], SF2);
    mpz_set(x[1], soln);

    mpz_set(y[0], modulus);
    mpz_set(y[1], pFactors[i]);

    KAZ_DS_CRT(2, x, y, SF2);
    mpz_mul(modulus, modulus, pFactors[i]);
  }

  mpz_clears(modulus, GCD, soln, check1, check2, NULL);

  if(e != NULL)
    free(e);

  if(p != NULL)
    free(p);

  for (int i = 0; i < nGRgQ; i++)
    mpz_clear(pFactors[i]);
  for (int i = 0; i < 2; i++)
    mpz_clear(x[i]);
  for (int i = 0; i < 2; i++)
    mpz_clear(y[i]);

  if(pFactors != NULL)
    free(pFactors);

  if(x != NULL)
    free(x);

  if(y != NULL)
    free(y);
}

void KS3_KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                       unsigned char *kaz_ds_sign_key) {
  mpz_t N, GRg, phiGRg, phiphiGRg, phiGg, q, GRgq, Q, phiQ, qQ;
  mpz_t a, b, ALPHA, V1, V2, tmp;

  mpz_inits(N, GRg, phiGRg, phiphiGRg, phiGg, q, GRgq, Q, phiQ, qQ, NULL);
  mpz_inits(a, b, ALPHA, V1, V2, tmp, NULL);

#ifdef KS3_DEBUG
  printf("kaz-3 KG\n");
#endif

  // 1) Get all system parameters
  mpz_set_str(N, KS3_KAZ_DS_SP_N, 10);
  mpz_set_str(GRg, KS3_KAZ_DS_SP_GRg, 10);
  mpz_set_str(phiGRg, KS3_KAZ_DS_SP_PHIGRg, 10);
  mpz_set_str(phiphiGRg, KS3_KAZ_DS_SP_PHIPHIGRg, 10);
  mpz_set_str(phiGg, KS3_KAZ_DS_SP_PHIGg, 10);
  mpz_set_str(q, KS3_KAZ_DS_SP_q, 10);
  mpz_set_str(GRgq, KS3_KAZ_DS_SP_GRgq, 10);
  mpz_set_str(Q, KS3_KAZ_DS_SP_Q, 10);
  mpz_set_str(phiQ, KS3_KAZ_DS_SP_PHIQ, 10);
  mpz_set_str(qQ, KS3_KAZ_DS_SP_qQ, 10);

  int nphiGg = KS3_KAZ_DS_SP_nPHIGg;

  // 1) Generate a, ALPHA
  KAZ_DS_RANDOM(nphiGg - 2, nphiGg - 1, a);
  mpz_nextprime(a, a);

  KAZ_DS_RANDOM(nphiGg - 2, nphiGg - 1, ALPHA);
  mpz_nextprime(ALPHA, ALPHA);

  // 2) Compute V1
  mpz_mod(V1, ALPHA, GRgq);

  // 3) Compute b
  mpz_powm(b, a, phiphiGRg, phiGg);

  // 4) Compute V2
  mpz_mul(tmp, phiQ, b);
  mpz_powm(V2, ALPHA, tmp, qQ);
  mpz_mul(V2, V2, Q);
  mpz_mod(V2, V2, qQ);

  // 5) Set kaz_ds_sign_key=(ALPHA, b) & kaz_ds_verify_key=(V1, V2)
  size_t ALPHASIZE = mpz_sizeinbase(ALPHA, 16);
  size_t BSIZE = mpz_sizeinbase(b, 16);
  size_t V1SIZE = mpz_sizeinbase(V1, 16);
  size_t V2SIZE = mpz_sizeinbase(V2, 16);

#ifdef KS3_DEBUG
  printf("(3) Alpha size : %lu, BSIZE : %lu, Total : %lu\n", ALPHASIZE, BSIZE,
         ALPHASIZE + BSIZE);
  printf("(3) V1SIZE : %lu; V2SIZE : %lu, Total : %lu\n", V1SIZE, V2SIZE,
         V1SIZE + V2SIZE);
#endif

  unsigned char *ALPHABYTE = NULL;
  unsigned char *BBYTE = NULL;
  unsigned char *V1BYTE = NULL;
  unsigned char *V2BYTE = NULL;

  ALPHABYTE = (unsigned char *)malloc(ALPHASIZE * sizeof(unsigned char));
  if (ALPHABYTE == NULL) {
    printf("Keygen memory allocation failed 1\n");
    goto cleanup;
  }
  mpz_export(ALPHABYTE, &ALPHASIZE, 1, sizeof(char), 0, 0, ALPHA);

  BBYTE = (unsigned char *)malloc(BSIZE * sizeof(unsigned char));
  if (BBYTE == NULL) {
    printf("Keygen memory allocation failed 2\n");
    goto cleanup;
  }
  mpz_export(BBYTE, &BSIZE, 1, sizeof(char), 0, 0, b);

  V1BYTE = (unsigned char *)malloc(V1SIZE * sizeof(unsigned char));
  if (V1BYTE == NULL) {
    printf("Keygen memory allocation failed 3\n");
    goto cleanup;
  }
  mpz_export(V1BYTE, &V1SIZE, 1, sizeof(char), 0, 0, V1);

  V2BYTE = (unsigned char *)malloc(V2SIZE * sizeof(unsigned char));
  if (V2BYTE == NULL) {
    printf("Keygen memory allocation failed 4\n");
    goto cleanup;
  }
  mpz_export(V2BYTE, &V2SIZE, 1, sizeof(char), 0, 0, V2);

  for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++)
    kaz_ds_sign_key[i] = 0;

  int je = CRYPTO_SECRETKEYBYTES - 1;
  for (int i = BSIZE - 1; i >= 0; i--) {
    kaz_ds_sign_key[je] = BBYTE[i];
    je--;
  }

  je = CRYPTO_SECRETKEYBYTES - KS3_KAZ_DS_BBYTES - 1;
  for (int i = ALPHASIZE - 1; i >= 0; i--) {
    kaz_ds_sign_key[je] = ALPHABYTE[i];
    je--;
  }

  for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
    kaz_ds_verify_key[i] = 0;

  je = CRYPTO_PUBLICKEYBYTES - 1;
  for (int i = V2SIZE - 1; i >= 0; i--) {
    kaz_ds_verify_key[je] = V2BYTE[i];
    je--;
  }

  je = CRYPTO_PUBLICKEYBYTES - KS3_KAZ_DS_V2BYTES - 1;
  for (int i = V1SIZE - 1; i >= 0; i--) {
    kaz_ds_verify_key[je] = V1BYTE[i];
    je--;
  }

cleanup:
  mpz_clears(N, GRg, phiGRg, phiphiGRg, phiGg, q, GRgq, Q, phiQ, qQ, NULL);
  mpz_clears(a, b, ALPHA, V1, V2, tmp, NULL);

  if (ALPHABYTE != NULL)
    free(ALPHABYTE);

  if (BBYTE != NULL)
    free(BBYTE);

  if(V1BYTE != NULL)
    free(V1BYTE);

  if(V2BYTE != NULL)
    free(V2BYTE);
}

int KS3_KAZ_DS_SIGNATURE(unsigned char *signature, unsigned long long *signlen,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk) {
  mpz_t phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b;
  mpz_t tmp, hashValue, r, BETA, S;

  mpz_inits(phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b, NULL);
  mpz_inits(tmp, hashValue, r, BETA, S, NULL);

  // 1) Get all system parameters
  mpz_set_str(phiGg, KS3_KAZ_DS_SP_PHIGg, 10);
  mpz_set_str(phiphiGRg, KS3_KAZ_DS_SP_PHIPHIGRg, 10);
  mpz_set_str(phiQ, KS3_KAZ_DS_SP_PHIQ, 10);
  mpz_set_str(GRgqQ, KS3_KAZ_DS_SP_GRgqQ, 10);
  mpz_set_str(phiGRgqQ, KS3_KAZ_DS_SP_PHIGRgqQ, 10);
  mpz_set_str(qQ, KS3_KAZ_DS_SP_qQ, 10);
  mpz_set_str(phiqQ, KS3_KAZ_DS_SP_PHIqQ, 10);

  // 2) Get kaz_ds_sign_key=(ALPHA, b)
  unsigned char *ALPHABYTE = NULL;
  unsigned char *BBYTE = NULL;
  unsigned char *SBYTE = NULL;

  ALPHABYTE = (unsigned char *)malloc((KS3_KAZ_DS_ALPHABYTES) * sizeof(unsigned char));

  BBYTE = (unsigned char *)malloc((KS3_KAZ_DS_BBYTES) * sizeof(unsigned char));
  
  for (int i = 0; i < KS3_KAZ_DS_ALPHABYTES; i++)
    ALPHABYTE[i] = 0;
  for (int i = 0; i < KS3_KAZ_DS_BBYTES; i++)
    BBYTE[i] = 0;

  for (int i = 0; i < KS3_KAZ_DS_ALPHABYTES; i++) {
    ALPHABYTE[i] = sk[i];
  }
  for (int i = 0; i < KS3_KAZ_DS_BBYTES; i++) {
    BBYTE[i] = sk[i + KS3_KAZ_DS_ALPHABYTES];
  }

  mpz_import(ALPHA, KS3_KAZ_DS_ALPHABYTES, 1, sizeof(char), 0, 0, ALPHABYTE);
  mpz_import(b, KS3_KAZ_DS_BBYTES, 1, sizeof(char), 0, 0, BBYTE);

  // 3) Compute HASHValue(m)
  unsigned char buf[CRYPTO_BYTES] = {0};
  HashMsg(m, mlen, buf);

  mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(char), 0, 0, buf);
  mpz_nextprime(hashValue, hashValue);

  // 4) Generate random r & ephemeral BETA
  KAZ_DS_RANDOM(KS3_KAZ_DS_SP_nPHIGg - 2, KS3_KAZ_DS_SP_nPHIGg - 1, r);
  mpz_nextprime(r, r);

  mpz_powm(BETA, r, phiphiGRg, phiGg);

  // 5) Compute Signature
  mpz_mul(tmp, phiQ, b);
  mpz_powm(S, ALPHA, tmp, GRgqQ);

  mpz_mul(tmp, phiqQ, BETA);
  mpz_powm(tmp, hashValue, tmp, GRgqQ);

  mpz_mul(S, S, tmp);
  mpz_mod(S, S, GRgqQ);

  // 6) Set signature=(S, m)
  size_t SSIZE = mpz_sizeinbase(S, 16);

  SBYTE = (unsigned char *)malloc(SSIZE * sizeof(unsigned char));
  mpz_export(SBYTE, &SSIZE, 1, sizeof(char), 0, 0, S);

  for (int i = 0; i < (int)(mlen + KS3_KAZ_DS_SBYTES); i++)
    signature[i] = 0;

  int je = mlen + KS3_KAZ_DS_SBYTES - 1;
  for (int i = mlen - 1; i >= 0; i--) {
    signature[je] = m[i];
    je--;
  }

  je = KS3_KAZ_DS_SBYTES - 1;
  for (int i = SSIZE - 1; i >= 0; i--) {
    signature[je] = SBYTE[i];
    je--;
  }

  *signlen = mlen + KS3_KAZ_DS_SBYTES;

  if(SBYTE != NULL)
    free(SBYTE);

  if(ALPHABYTE != NULL)
    free(ALPHABYTE);

  if(BBYTE != NULL)
    free(BBYTE);

  mpz_clears(phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b,
             NULL);
  mpz_clears(tmp, hashValue, r, BETA, S, NULL);

  return 0;
}

int KS3_KAZ_DS_VERIFICATION(unsigned char *m, unsigned long long *mlen,
                            const unsigned char *sm, unsigned long long smlen,
                            const unsigned char *pk) {
  mpz_t N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
      hashValue, V1, V2, S;
  mpz_t tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2;

  mpz_inits(N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
            hashValue, V1, V2, S, NULL);
  mpz_inits(tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2, NULL);

  // 1) Get all system parameters
  mpz_set_str(N, KS3_KAZ_DS_SP_N, 10);
  mpz_set_str(g, KS3_KAZ_DS_SP_G, 10);
  mpz_set_str(Gg, KS3_KAZ_DS_SP_Gg, 10);
  mpz_set_str(R, KS3_KAZ_DS_SP_R, 10);
  mpz_set_str(GRg, KS3_KAZ_DS_SP_GRg, 10);
  mpz_set_str(q, KS3_KAZ_DS_SP_q, 10);
  mpz_set_str(Q, KS3_KAZ_DS_SP_Q, 10);
  mpz_set_str(phiQ, KS3_KAZ_DS_SP_PHIQ, 10);
  mpz_set_str(GRgQ, KS3_KAZ_DS_SP_GRgQ, 10);
  mpz_set_str(phiGRgQ, KS3_KAZ_DS_SP_PHIGRgQ, 10);
  mpz_set_str(GRgqQ, KS3_KAZ_DS_SP_GRgqQ, 10);
  mpz_set_str(qQ, KS3_KAZ_DS_SP_qQ, 10);
  mpz_set_str(phiqQ, KS3_KAZ_DS_SP_PHIqQ, 10);

  //int n = KS3_KAZ_DS_SP_n;

  // 2) Get kaz_ds_verify_key=(V1, V2)
  unsigned char *V1BYTE = NULL;
  unsigned char *V2BYTE = NULL;
  unsigned char *SBYTE = NULL;
  unsigned char *MBYTE = NULL;
  
  mpz_t *x = NULL;
  mpz_t *modulus = NULL;

  V1BYTE = (unsigned char *)malloc((KS3_KAZ_DS_V1BYTES) * sizeof(unsigned char));
  V2BYTE = (unsigned char *)malloc((KS3_KAZ_DS_V2BYTES) * sizeof(unsigned char));

  for (int i = 0; i < KS3_KAZ_DS_V1BYTES; i++)
    V1BYTE[i] = 0;
  for (int i = 0; i < KS3_KAZ_DS_V2BYTES; i++)
    V2BYTE[i] = 0;

  for (int i = 0; i < KS3_KAZ_DS_V1BYTES; i++) {
    V1BYTE[i] = pk[i];
  }
  for (int i = 0; i < KS3_KAZ_DS_V2BYTES; i++) {
    V2BYTE[i] = pk[i + KS3_KAZ_DS_V1BYTES];
  }

  mpz_import(V1, KS3_KAZ_DS_V1BYTES, 1, sizeof(char), 0, 0, V1BYTE);
  mpz_import(V2, KS3_KAZ_DS_V2BYTES, 1, sizeof(char), 0, 0, V2BYTE);

  // 3) Get signature=(S, m)
  int len = smlen - KS3_KAZ_DS_SBYTES;

  SBYTE = (unsigned char *)malloc(KS3_KAZ_DS_SBYTES * sizeof(unsigned char));
  MBYTE = (unsigned char *)malloc(len * sizeof(unsigned char));

  for (int i = 0; i < KS3_KAZ_DS_SBYTES; i++)
    SBYTE[i] = 0;
  for (int i = 0; i < len; i++)
    MBYTE[i] = 0;

  for (int i = 0; i < KS3_KAZ_DS_SBYTES; i++) {
    SBYTE[i] = sm[i];
  }
  for (int i = 0; i < len; i++) {
    MBYTE[i] = sm[i + KS3_KAZ_DS_SBYTES];
  }

  mpz_import(S, KS3_KAZ_DS_SBYTES, 1, sizeof(char), 0, 0, SBYTE);

  // 4) Compute the hash value of the message
  unsigned char buf[CRYPTO_BYTES] = {0};
  HashMsg(MBYTE, len, buf);

  mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(char), 0, 0, buf);
  mpz_nextprime(hashValue, hashValue);

  // 5) Filtering Procedures
  mpz_powm(y, V1, phiQ, GRgQ);
  mpz_powm(tmp, hashValue, phiqQ, GRgQ);
  mpz_mul(y, y, tmp);
  mpz_mod(y, y, GRgQ);

  x = malloc(2 * sizeof(mpz_t));
  modulus = malloc(2 * sizeof(mpz_t));

  for (int i = 0; i < 2; i++)
    mpz_init(x[i]);
  for (int i = 0; i < 2; i++)
    mpz_init(modulus[i]);

  mpz_divexact(x[0], V2, Q);
  mpz_set(x[1], y);

  mpz_set(modulus[0], q);
  mpz_set(modulus[1], GRgQ);

  KAZ_DS_CRT(2, x, modulus, SF1);

  mpz_powm(VQ, V1, phiQ, GRg);
  mpz_powm(tmp, hashValue, phiqQ, GRg);
  mpz_mul(VQ, VQ, tmp);
  mpz_mod(VQ, VQ, GRg);

  KAZ_DS_FILTER(VQ, V2, GRg, Q, qQ, GRgQ, SF2);

  // FILTER 1
  mpz_mod(tmp, S, GRgqQ);
  mpz_sub(W0, tmp, S);

  if (mpz_cmp_ui(W0, 0) != 0) {
    printf("Filter 1...\n");
    return -4;
  }

  // FILTER 2
  // mpz_mod(W1, S, GRgqQ);
  mpz_sub(W1, tmp, SF1);

  if (mpz_cmp_ui(W1, 0) == 0) {
    printf("Filter 2...\n");
    return -4;
  }

  // FILTER 3
  // mpz_mod(W2, S, GRgqQ);
  mpz_sub(W2, tmp, SF2);

  if (mpz_cmp_ui(W2, 0) == 0) {
    printf("Filter 3...\n");
    return -4;
  }

  // FILTER 4
  mpz_mul(W3, Q, S);
  mpz_mod(W3, W3, qQ);
  mpz_sub(W4, W3, V2);

  if (mpz_cmp_ui(W4, 0) != 0) {
    printf("Filter 4...\n");
    return -4;
  }

  // 6) Verifying Procedures
  mpz_powm(tmp, R, S, Gg);
  mpz_powm(y1, g, tmp, N);

  mpz_powm(tmp, V1, phiQ, GRg);
  mpz_powm(tmp2, hashValue, phiqQ, GRg);
  mpz_mul(tmp, tmp, tmp2);
  mpz_mod(tmp, tmp, GRg);
  mpz_powm(tmp, R, tmp, Gg);
  mpz_powm(y2, g, tmp, N);

  if (mpz_cmp(y1, y2) != 0)
    return -4;

  memcpy(m, MBYTE, len);
  *mlen = len;

  mpz_clears(N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
             hashValue, V1, V2, S, NULL);
  mpz_clears(tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2, NULL);

  for (int i = 0; i < 2; i++)
    mpz_clear(x[i]);

  if(x != NULL)
    free(x);

  for (int i = 0; i < 2; i++)
    mpz_clear(modulus[i]);

  if(modulus != NULL)
    free(modulus);

  if (V1BYTE != NULL)
    free(V1BYTE);

  if(V2BYTE != NULL)
    free(V2BYTE);

  if(SBYTE != NULL)
    free(SBYTE);

  if(MBYTE != NULL)
    free(MBYTE);

  return 0;
}

int KS3_KAZ_DS_SIGNATURE_DETACHED(unsigned char *signature,
                                  unsigned int *signlen, const unsigned char *m,
                                  unsigned int mlen, const unsigned char *sk) {
  mpz_t phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b;
  mpz_t tmp, hashValue, r, BETA, S;

  int ret = 0;

  mpz_inits(phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b, NULL);
  mpz_inits(tmp, hashValue, r, BETA, S, NULL);

  // 1) Get all system parameters
  mpz_set_str(phiGg, KS3_KAZ_DS_SP_PHIGg, 10);
  mpz_set_str(phiphiGRg, KS3_KAZ_DS_SP_PHIPHIGRg, 10);
  mpz_set_str(phiQ, KS3_KAZ_DS_SP_PHIQ, 10);
  mpz_set_str(GRgqQ, KS3_KAZ_DS_SP_GRgqQ, 10);
  mpz_set_str(phiGRgqQ, KS3_KAZ_DS_SP_PHIGRgqQ, 10);
  mpz_set_str(qQ, KS3_KAZ_DS_SP_qQ, 10);
  mpz_set_str(phiqQ, KS3_KAZ_DS_SP_PHIqQ, 10);

  // 2) Get kaz_ds_sign_key=(ALPHA, b)
  unsigned char *ALPHABYTE = NULL;
  unsigned char *BBYTE = NULL;
  unsigned char *SBYTE = NULL;

  ALPHABYTE = (unsigned char *)calloc(KS3_KAZ_DS_ALPHABYTES, sizeof(unsigned char));
  if (ALPHABYTE == NULL) {
    printf("Signing memory allocation failed 1\n");
    ret = -10;
    goto cleanup;
  }

  BBYTE = (unsigned char *)calloc(KS3_KAZ_DS_BBYTES, sizeof(unsigned char));
  if (BBYTE == NULL) {
    printf("Signing memory allocation failed 2\n");
    ret = -11;
    goto cleanup;
  }

  memcpy(ALPHABYTE, sk, KS3_KAZ_DS_ALPHABYTES);
  memcpy(BBYTE, sk + KS3_KAZ_DS_ALPHABYTES, KS3_KAZ_DS_BBYTES);

  mpz_import(ALPHA, KS3_KAZ_DS_ALPHABYTES, 1, sizeof(char), 0, 0, ALPHABYTE);
  mpz_import(b, KS3_KAZ_DS_BBYTES, 1, sizeof(char), 0, 0, BBYTE);

  // 3) Compute HASHValue(m)
  unsigned char buf[CRYPTO_BYTES] = {0};
  HashMsg(m, mlen, buf);

  mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(char), 0, 0, buf);
  mpz_nextprime(hashValue, hashValue);

  // 4) Generate random r & ephemeral BETA
  KAZ_DS_RANDOM(KS3_KAZ_DS_SP_nPHIGg - 2, KS3_KAZ_DS_SP_nPHIGg - 1, r);
  mpz_nextprime(r, r);

  mpz_powm(BETA, r, phiphiGRg, phiGg);

  // 5) Compute Signature
  mpz_mul(tmp, phiQ, b);
  mpz_powm(S, ALPHA, tmp, GRgqQ);

  mpz_mul(tmp, phiqQ, BETA);
  mpz_powm(tmp, hashValue, tmp, GRgqQ);

  mpz_mul(S, S, tmp);
  mpz_mod(S, S, GRgqQ);

  // 6) Set signature=(S, m)
  size_t SSIZE = mpz_sizeinbase(S, 16);

  SBYTE = (unsigned char *)malloc(SSIZE * sizeof(unsigned char));
  if (SBYTE == NULL) {
    printf("Signing memory allocation failed 3\n");
    ret = -12;
    goto cleanup;
  }
  mpz_export(SBYTE, &SSIZE, 1, sizeof(char), 0, 0, S);

  memset(signature, 0, KS3_KAZ_DS_SBYTES * sizeof(unsigned char));
  memcpy(signature + (KS3_KAZ_DS_SBYTES - SSIZE), SBYTE, SSIZE);

  *signlen = KS3_KAZ_DS_SBYTES;

cleanup:
  if(SBYTE != NULL)
    free(SBYTE);

  if(ALPHABYTE != NULL)
    free(ALPHABYTE);

  if(BBYTE != NULL)
    free(BBYTE);

  mpz_clears(phiGg, phiphiGRg, phiQ, GRgqQ, phiGRgqQ, qQ, phiqQ, ALPHA, b,
             NULL);
  mpz_clears(tmp, hashValue, r, BETA, S, NULL);

  return ret;
}

int KS3_KAZ_DS_VERIFICATION_DETACHED(const unsigned char *m, unsigned int mlen,
                                     const unsigned char *sm,
                                     unsigned int smlen,
                                     const unsigned char *pk) {
  mpz_t N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
      hashValue, V1, V2, S;
  mpz_t tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2;
  int ret = 0;

  mpz_inits(N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
            hashValue, V1, V2, S, NULL);
  mpz_inits(tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2, NULL);

  // 1) Get all system parameters
  mpz_set_str(N, KS3_KAZ_DS_SP_N, 10);
  mpz_set_str(g, KS3_KAZ_DS_SP_G, 10);
  mpz_set_str(Gg, KS3_KAZ_DS_SP_Gg, 10);
  mpz_set_str(R, KS3_KAZ_DS_SP_R, 10);
  mpz_set_str(GRg, KS3_KAZ_DS_SP_GRg, 10);
  mpz_set_str(q, KS3_KAZ_DS_SP_q, 10);
  mpz_set_str(Q, KS3_KAZ_DS_SP_Q, 10);
  mpz_set_str(phiQ, KS3_KAZ_DS_SP_PHIQ, 10);
  mpz_set_str(GRgQ, KS3_KAZ_DS_SP_GRgQ, 10);
  mpz_set_str(phiGRgQ, KS3_KAZ_DS_SP_PHIGRgQ, 10);
  mpz_set_str(GRgqQ, KS3_KAZ_DS_SP_GRgqQ, 10);
  mpz_set_str(qQ, KS3_KAZ_DS_SP_qQ, 10);
  mpz_set_str(phiqQ, KS3_KAZ_DS_SP_PHIqQ, 10);

  //int n = KS3_KAZ_DS_SP_n;

  // 2) Get kaz_ds_verify_key=(V1, V2)
  unsigned char *V1BYTE = NULL;
  unsigned char *V2BYTE = NULL;
  
  mpz_t *x = NULL;
  mpz_t *modulus = NULL;

  V1BYTE = (unsigned char *)calloc(KS3_KAZ_DS_V1BYTES, sizeof(unsigned char));
  if (V1BYTE == NULL) {
    printf("Verify memory allocation failed 1\n");
    ret = -10;
    goto cleanup;
  }

  V2BYTE = (unsigned char *)calloc(KS3_KAZ_DS_V2BYTES, sizeof(unsigned char));
  if (V2BYTE == NULL) {
    printf("Verify memory allocation failed 2\n");
    ret = -11;
    goto cleanup;
  }

  memcpy(V1BYTE, pk, KS3_KAZ_DS_V1BYTES);
  memcpy(V2BYTE, pk + KS3_KAZ_DS_V1BYTES, KS3_KAZ_DS_V2BYTES);

  mpz_import(V1, KS3_KAZ_DS_V1BYTES, 1, sizeof(char), 0, 0, V1BYTE);
  mpz_import(V2, KS3_KAZ_DS_V2BYTES, 1, sizeof(char), 0, 0, V2BYTE);

  // 3) Get signature=(S, m)
  if(smlen > 0) {}
  mpz_import(S, KS3_KAZ_DS_SBYTES, 1, sizeof(unsigned char), 0, 0, sm);

  // 4) Compute the hash value of the message
  unsigned char buf[CRYPTO_BYTES] = {0};
  HashMsg(m, mlen, buf);

  mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(unsigned char), 0, 0, buf);
  mpz_nextprime(hashValue, hashValue);

  // 5) Filtering Procedures
  mpz_powm(y, V1, phiQ, GRgQ);
  mpz_powm(tmp, hashValue, phiqQ, GRgQ);
  mpz_mul(y, y, tmp);
  mpz_mod(y, y, GRgQ);

  x = malloc(2 * sizeof(mpz_t));
  modulus = malloc(2 * sizeof(mpz_t));

  for (int i = 0; i < 2; i++)
    mpz_init(x[i]);
  for (int i = 0; i < 2; i++)
    mpz_init(modulus[i]);

  mpz_divexact(x[0], V2, Q);
  mpz_set(x[1], y);

  mpz_set(modulus[0], q);
  mpz_set(modulus[1], GRgQ);

  KAZ_DS_CRT(2, x, modulus, SF1);

  mpz_powm(VQ, V1, phiQ, GRg);
  mpz_powm(tmp, hashValue, phiqQ, GRg);
  mpz_mul(VQ, VQ, tmp);
  mpz_mod(VQ, VQ, GRg);

  KAZ_DS_FILTER(VQ, V2, GRg, Q, qQ, GRgQ, SF2);

  // FILTER 1
  mpz_mod(tmp, S, GRgqQ);
  mpz_sub(W0, tmp, S);

  if (mpz_cmp_ui(W0, 0) != 0) {
    printf("Filter 1...\n");
    ret = -20;
    goto cleanup;
  }

  // FILTER 2
  // mpz_mod(W1, S, GRgqQ);
  mpz_sub(W1, tmp, SF1);

  if (mpz_cmp_ui(W1, 0) == 0) {
    printf("Filter 2...\n");
    ret = -21;
    goto cleanup;
  }

  // FILTER 3
  // mpz_mod(W2, S, GRgqQ);
  mpz_sub(W2, tmp, SF2);

  if (mpz_cmp_ui(W2, 0) == 0) {
    printf("Filter 3...\n");
    ret = -22;
    goto cleanup;
  }

  // FILTER 4
  mpz_mul(W3, Q, S);
  mpz_mod(W3, W3, qQ);
  mpz_sub(W4, W3, V2);

  if (mpz_cmp_ui(W4, 0) != 0) {
    printf("Filter 4...\n");
    ret = -23;
    goto cleanup;
  }

  // 6) Verifying Procedures
  mpz_powm(tmp, R, S, Gg);
  mpz_powm(y1, g, tmp, N);

  mpz_powm(tmp, V1, phiQ, GRg);
  mpz_powm(tmp2, hashValue, phiqQ, GRg);
  mpz_mul(tmp, tmp, tmp2);
  mpz_mod(tmp, tmp, GRg);
  mpz_powm(tmp, R, tmp, Gg);
  mpz_powm(y2, g, tmp, N);

  if (mpz_cmp(y1, y2) != 0) {
    printf("Filter 5...\n");
    ret = -24;
    goto cleanup;
  }

cleanup:
  mpz_clears(N, g, Gg, R, GRg, q, Q, phiQ, GRgQ, phiGRgQ, GRgqQ, qQ, phiqQ,
             hashValue, V1, V2, S, NULL);
  mpz_clears(tmp, tmp2, SF1, SF2, W0, W1, W2, W3, W4, VQ, y, y1, y2, NULL);

  for (int i = 0; i < 2; i++)
    mpz_clear(x[i]);

  if(x != NULL)
    free(x);

  for (int i = 0; i < 2; i++)
    mpz_clear(modulus[i]);

  if(modulus != NULL)
    free(modulus);

  if(V1BYTE != NULL)
    free(V1BYTE);

  if(V2BYTE != NULL)
    free(V2BYTE);

  return ret;
}
