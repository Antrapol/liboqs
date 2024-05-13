# SPDX-License-Identifier: MIT

set(_KAZ_SIGN_OBJS "")

set(_KAZ_SIGN_OBJS_COMMON "")

add_library(kaz_sign_common OBJECT kaz-common/rng.c kaz-common/sha256.c)
target_include_directories(kaz_sign_common PRIVATE ${PROJECT_SOURCE_DIR}/src/common/aes)
#target_include_directories(kaz_sign_common PRIVATE ${OPENSSL_INCLUDE_DIR})
set(_KAZ_SIGN_OBJS_COMMON ${KAZ_SIGN_OBJS_COMMON} $<TARGET_OBJECTS:kaz_sign_common>)

if(OQS_ENABLE_SIG_kaz_sign_1)
  add_library(kaz_sign_1_ref OBJECT sig_kaz_sign_1.c sig_kaz_sign.h KAZ1509_ref/kaz_api.c KAZ1509_ref/kaz_api.h KAZ1509_ref/sign.c)
  target_include_directories(kaz_sign_1_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/kaz-common)
  target_include_directories(kaz_sign_1_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/KAZ1509_ref)
  target_include_directories(kaz_sign_1_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
  #target_include_directories(kaz_sign_1_ref PRIVATE ${OPENSSL_INCLUDE_DIR})
  set(_KAZ_SIGN_OBJS ${_KAZ_SIGN_OBJS} ${KAZ_SIGN_OBJS_COMMON} $<TARGET_OBJECTS:kaz_sign_1_ref>)
endif()

if(OQS_ENABLE_SIG_kaz_sign_3)
  add_library(kaz_sign_3_ref OBJECT sig_kaz_sign_3.c  sig_kaz_sign.h KAZ2321_ref/kaz_api.c KAZ2321_ref/kaz_api.h KAZ2321_ref/sign.c)
  target_include_directories(kaz_sign_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/kaz-common)
  target_include_directories(kaz_sign_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/KAZ2321_ref)
  target_include_directories(kaz_sign_3_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
  #target_include_directories(kaz_sign_3_ref PRIVATE ${OPENSSL_INCLUDE_DIR})
  set(_KAZ_SIGN_OBJS ${_KAZ_SIGN_OBJS} $<TARGET_OBJECTS:kaz_sign_3_ref>)
endif()

if(OQS_ENABLE_SIG_kaz_sign_5)
  add_library(kaz_sign_5_ref OBJECT sig_kaz_sign_5.c sig_kaz_sign.h KAZ3241_ref/kaz_api.c KAZ3241_ref/kaz_api.h KAZ3241_ref/sign.c)
  target_include_directories(kaz_sign_5_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/kaz-common)
  target_include_directories(kaz_sign_5_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/KAZ3241_ref)
  target_include_directories(kaz_sign_5_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
  #target_include_directories(kaz_sign_5_ref PRIVATE ${OPENSSL_INCLUDE_DIR})
  set(_KAZ_SIGN_OBJS ${_KAZ_SIGN_OBJS} $<TARGET_OBJECTS:kaz_sign_5_ref>)
endif()

set(KAZ_SIGN_OBJS ${_KAZ_SIGN_OBJS} ${_KAZ_SIGN_OBJS_COMMON} PARENT_SCOPE)
