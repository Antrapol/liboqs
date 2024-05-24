#ifndef KS3_FILE_H_INCLUDED
#define KS3_FILE_H_INCLUDED
#include "gmp.h"

#define KS3_KAZ_DS_SP_J 258
#define KS3_KAZ_DS_SP_K 198

#define KS3_KAZ_DS_SP_N                                                        \
  "46759781633193085932210580959238145383675146627658021160776703660197662\
								 84309095575706469428835436474742770048322861396175300317303624223782655\
								 81734794282984690028150157145980074281292566731770571423749001321999800\
								 37404276736920556580598591738277536884367979898734058882667256768293478\
								 95884839152754674991232442195397685281964144115888733328833506735072089\
								 57623885149982409768782662260256033583088295537760922309998149698910449\
								 36428489972477942044730377618695999472542904676257903550630694646196235\
								 20975140597282373675602319098855616251701113212350825145004011369716720\
								 14897642672510064283349035886954252913240104862836223024721351047469380\
								 982094744623689350493066107951410660778357687057201251046585"

#define KS3_KAZ_DS_SP_n 2321

#define KS3_KAZ_DS_SP_Q "116431182179248680450031658440253681535"
#define KS3_KAZ_DS_SP_PHIQ "27739969042773783995307880611840000000"
#define KS3_KAZ_DS_SP_PHIPHIQ "4794067407163270021663791513600000000"

#define KS3_KAZ_DS_SP_G "6007"
#define KS3_KAZ_DS_SP_Gg                                                       \
  "22454043250428773247460909028042207884161972004320225533938655455928952\
                                 57883733275592608066918868457698539827892596863237792058786088397050704\
								 0858655740241632000"
#define KS3_KAZ_DS_SP_PHIGg                                                    \
  "21909173310818284449775616326207574433971176860060482332602081925988004\
                                 68568276396341779804242051505811731981760020615514792949272543232000000\
								 000000000000000000"
#define KS3_KAZ_DS_SP_nPHIGg 530

#define KS3_KAZ_DS_SP_R "6151"
#define KS3_KAZ_DS_SP_GRg "1690404083586125425143844520333180405256000"
#define KS3_KAZ_DS_SP_PHIGRg "215531152527396013350376745572761600000000"
#define KS3_KAZ_DS_SP_PHIPHIGRg "38880485930520015284446057149235200000000"

#define KS3_KAZ_DS_SP_GRgQ                                                     \
  "19681574581256208345990833946852940075217966208160355929078843267727726\
                                 4147960000"
#define KS3_KAZ_DS_SP_PHIGRgQ                                                  \
  "22750364015564470546250618908337269890052039535156910129852613184716800\
                                 000000000"

#define KS3_KAZ_DS_SP_q                                                        \
  "222202375805678622965207689796451042546083652526243709105029"
#define KS3_KAZ_DS_SP_GRgq                                                     \
  "37561180344445802083328034023847633103919284263865531783983229046972065\
                                 5405928093266114139287632424000"
#define KS3_KAZ_DS_SP_GRgqQ                                                    \
  "43732926315517838843875211334949995481037409205313999747155465512298489\
                                 531267536659145099372482025131310344571946070952176948959836090840000"
#define KS3_KAZ_DS_SP_PHIGRgqQ                                                 \
  "50551849347024442730116303420065283642562241285615807357092620390624454\
                                 56648112425289223871619536956570871472539431204175636070400000000000"

#define KS3_KAZ_DS_SP_qQ                                                       \
  "25871285298092847040001409562415349113099045668445603797692932641042022\
                                 453084393146204617232939515"
#define KS3_KAZ_DS_SP_PHIqQ                                                    \
  "61638870260803114509738727100333623012973408225107134354163730524536843\
                                 15243066999460331520000000"

#define KS3_KAZ_DS_ALPHABYTES 67
#define KS3_KAZ_DS_BBYTES 67
#define KS3_KAZ_DS_V1BYTES 43
#define KS3_KAZ_DS_V2BYTES 41
#define KS3_KAZ_DS_SBYTES 60

extern int KS3_KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                             unsigned char *kaz_ds_sign_key);

extern int KS3_KAZ_DS_SIGNATURE(unsigned char *signature,
                                unsigned long long *signlen,
                                const unsigned char *m, unsigned long long mlen,
                                const unsigned char *kaz_ds_sign_key);

extern int KS3_KAZ_DS_VERIFICATION(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm,
                                   unsigned long long smlen,
                                   const unsigned char *pk);

extern int KS3_KAZ_DS_SIGNATURE_DETACHED(unsigned char *signature,
                                         unsigned int *signlen,
                                         const unsigned char *m,
                                         unsigned int mlen,
                                         const unsigned char *kaz_ds_sign_key);

extern int KS3_KAZ_DS_VERIFICATION_DETACHED(const unsigned char *m,
                                            unsigned int mlen,
                                            const unsigned char *sm,
                                            unsigned int smlen,
                                            const unsigned char *pk);

#endif // KS3_FILE_H_INCLUDED
