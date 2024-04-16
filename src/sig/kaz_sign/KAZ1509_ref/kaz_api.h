#ifndef KS1_FILE_H_INCLUDED
#define KS1_FILE_H_INCLUDED
#include "gmp.h"

#define KS1_KAZ_DS_SP_J 180
#define KS1_KAZ_DS_SP_K 134

#define KS1_KAZ_DS_SP_N                                                        \
  "16654099924025690560880991628826166333626342440673565018885011847989446\
                                 73390411604901732676624210376510769252181354174828223286340057028944019\
                                 91339669414651118456372695070769619863131971414241586048862803140660472\
                                 06653222207353469933659597534156792443205461406819169388949586947835045\
                                 09315984550444746877596669802184487731229941008215513808488975493742420\
                                 95332359872258964174269418980707061566230310986271334632962653419873630\
                                 52884725941333218996085207555"

#define KS1_KAZ_DS_SP_n 1509

#define KS1_KAZ_DS_SP_Q "116431182179248680450031658440253681535"
#define KS1_KAZ_DS_SP_PHIQ "27739969042773783995307880611840000000"
#define KS1_KAZ_DS_SP_PHIPHIQ "4794067407163270021663791513600000000"

#define KS1_KAZ_DS_SP_G "6007"
#define KS1_KAZ_DS_SP_Gg                                                       \
  "66425249147392035103359575563682919206231140688573787652572381678879876\
                                 350990985890249087277450456295776000"
#define KS1_KAZ_DS_SP_PHIGg                                                    \
  "69025991055271083563108509669543205198091379906257170576075063002464606\
                                 15498054972211200000000000000000000"
#define KS1_KAZ_DS_SP_nPHIGg 352

#define KS1_KAZ_DS_SP_R "6151"
#define KS1_KAZ_DS_SP_GRg "964284630129748924872876000"
#define KS1_KAZ_DS_SP_PHIGRg "137005430034525396664320000"
#define KS1_KAZ_DS_SP_PHIPHIGRg "25983496793805532692480000"

#define KS1_KAZ_DS_SP_GRgQ                                                     \
  "112272799443286228215182487240051713050175574408899790863544660000"
#define KS1_KAZ_DS_SP_PHIGRgQ                                                  \
  "13195170808477513128033647660316185885361748971324702720000000000"

#define KS1_KAZ_DS_SP_q "19622981469770784085257257918661917296793"
#define KS1_KAZ_DS_SP_GRgq                                                     \
  "18922139428620837464965310742017573422968515743635820123087486668000"
#define KS1_KAZ_DS_SP_GRgqQ                                                    \
  "22031270630348972597475958430799310183802415569685291109901764549819429\
                                 48469701999741238400477230275380000"
#define KS1_KAZ_DS_SP_PHIGRgqQ                                                 \
  "25892859226521461587603410482490403883967390885193816188766111333437628\
                                 0005852670907715409674240000000000"

#define KS1_KAZ_DS_SP_qQ                                                       \
  "22847269304069031950651271577793505081995599848324603820445725437088134\
                                 98817255"

#define KS1_KAZ_DS_SP_PHIqQ                                                    \
  "54434089849836515836263436785430173298114754862533363049548379982921728000" \
  "0000"

#define KS1_KAZ_DS_ALPHABYTES 45
#define KS1_KAZ_DS_BBYTES 45
#define KS1_KAZ_DS_V1BYTES 29
#define KS1_KAZ_DS_V2BYTES 33
#define KS1_KAZ_DS_SBYTES 45

extern void KS1_KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                              unsigned char *kaz_ds_sign_key);

extern int KS1_KAZ_DS_SIGNATURE(unsigned char *signature,
                                unsigned long long *signlen,
                                const unsigned char *m, unsigned long long mlen,
                                const unsigned char *kaz_ds_sign_key);

extern int KS1_KAZ_DS_VERIFICATION(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm,
                                   unsigned long long smlen,
                                   const unsigned char *pk);

extern int KS1_KAZ_DS_SIGNATURE_DETACHED(unsigned char *signature,
                                         unsigned int *signlen,
                                         const unsigned char *m,
                                         unsigned int mlen,
                                         const unsigned char *kaz_ds_sign_key);

extern int KS1_KAZ_DS_VERIFICATION_DETACHED(const unsigned char *m,
                                            unsigned int mlen,
                                            const unsigned char *sm,
                                            unsigned int smlen,
                                            const unsigned char *pk);

#endif // KS1_FILE_H_INCLUDED
