/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI (2013-2015)
    Contributors : Ryad BENADJILA [ryadbenadjila@gmail.com],
    Thomas CALDERON [calderon.thomas@gmail.com]
    Marion DAUBIGNARD [marion.daubignard@ssi.gouv.fr]

    This software is a computer program whose purpose is to implement
    a PKCS#11 proxy as well as a PKCS#11 filter with security features
    in mind. The project source tree is subdivided in six parts.
    There are five main parts:
      1] OCaml/C PKCS#11 bindings (using OCaml IDL).
      2] XDR RPC generators (to be used with ocamlrpcgen and/or rpcgen).
      3] A PKCS#11 RPC server (daemon) in OCaml using a Netplex RPC basis.
      4] A PKCS#11 filtering module used as a backend to the RPC server.
      5] A PKCS#11 client module that comes as a dynamic library offering
         the PKCS#11 API to the software.
    There is one "optional" part:
      6] Tests in C and OCaml to be used with client module 5] or with the
         bindings 1]

    Here is a big picture of how the PKCS#11 proxy works:

 ----------------------   --------  socket (TCP or Unix)  --------------------
| 3] PKCS#11 RPC server|-|2] RPC  |<+++++++++++++++++++> | 5] Client library  |
 ----------------------  |  Layer | [SSL/TLS optional]   |  --------          |
           |              --------                       | |2] RPC  | PKCS#11 |
 ----------------------                                  | |  Layer |functions|
| 4] PKCS#11 filter    |                                 |  --------          |
 ----------------------                                   --------------------
           |                                                        |
 ----------------------                                             |
| 1] PKCS#11 OCaml     |                                  { PKCS#11 INTERFACE }
|       bindings       |                                            |
 ----------------------                                       APPLICATION
           |
           |
 { PKCS#11 INTERFACE }
           |
 REAL PKCS#11 MIDDLEWARE
    (shared library)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright holders
    shall not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization.

    The current source code is part of the bindings 1] source tree:
 ----------------------
| 1] PKCS#11 OCaml     |
|       bindings       |
 ----------------------
           |
           |
 { PKCS#11 INTERFACE }
           |
  REAL PKCS#11 MIDDLEWARE
     (shared library)

    Project: PKCS#11 Filtering Proxy
    File:    src/bindings-pkcs11/pkcs11.h

-------------------------- MIT License HEADER ----------------------------------*/
/* File generated from pkcs11.idl */

#ifndef _CAMLIDL_PKCS11_H
#define _CAMLIDL_PKCS11_H

#ifdef __cplusplus
#define _CAMLIDL_EXTERN_C extern "C"
#else
#define _CAMLIDL_EXTERN_C extern
#endif

#ifdef _WIN32
#pragma pack(push,1)		/* necessary for COM interfaces */
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned long ck_flags_t;

struct ck_version {
  unsigned char major;
  unsigned char minor;
};

#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#ifdef __FreeBSD__
/* Needed on FreeBSD for endianess conversion functions */
#include <sys/endian.h>
#endif

#ifdef __APPLE__
/* Needed on Mac OS X for endianess conversion functions */
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

#ifdef CUSTOM_ALLOC
void *custom_malloc(size_t size);
void custom_free(void **to_free);

/* Custom malloc to fail on malloc error */
void *custom_malloc(size_t size)
{
  void *returned_pointer = (void *)malloc(size);
  if (returned_pointer == NULL) {
#ifdef DEBUG
    printf("malloc error: NULL pointer returned! We exit\n");
#endif
    exit(-1);
  }
  return returned_pointer;
}

/* Custom free to force NULL on variables */
void custom_free(void **to_free)
{
  if (*to_free == NULL) {
#ifdef DEBUG
    printf("warning: trying to free a NULL pointer! Ignoring ...\n");
#endif
    return;
  }
  free(*to_free);
  *to_free = NULL;
  return;
}
#else
extern void *custom_malloc(size_t size);
extern void custom_free(void **to_free);
#endif
/* To handle nativeint versus int64 for native bindings versus RPC ocaml client */
#ifdef CAMLRPC
#define custom_copy_int(input) copy_int64((input))
#define custom_int_val(input) Int64_val((input))
#else
#define custom_copy_int(input) copy_nativeint((input))
#define custom_int_val(input) Nativeint_val((input))
#endif
#define LITTLE_ENDIAN_64 1
#define LITTLE_ENDIAN_32 2
#define BIG_ENDIAN_64 3
#define BIG_ENDIAN_32 4
#define UNSUPPORTED_ARCHITECTURE 5
#define NOT_INITIALIZED 6

#ifdef SERVER_ROLE
/* variable used to avoid multiple calls to C_LoadModule */
unsigned long module_loaded = NOT_INITIALIZED;
/* variable used to detect architecture */
unsigned long peer_arch = NOT_INITIALIZED;
#else
unsigned long peer_arch;
#endif
unsigned long my_arch;

struct ck_info {
  struct ck_version cryptoki_version;
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  unsigned char library_description[32];
  struct ck_version library_version;
};

typedef unsigned long ck_notification_t;

typedef unsigned long ck_slot_id_t;

struct ck_slot_info {
  unsigned char slot_description[64];
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
};

struct ck_token_info {
  unsigned char label[32];
  unsigned char manufacturer_id[32];
  unsigned char model[16];
  unsigned char serial_number[16];
  ck_flags_t flags;
  unsigned long max_session_count;
  unsigned long session_count;
  unsigned long max_rw_session_count;
  unsigned long rw_session_count;
  unsigned long max_pin_len;
  unsigned long min_pin_len;
  unsigned long total_public_memory;
  unsigned long free_public_memory;
  unsigned long total_private_memory;
  unsigned long free_private_memory;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
  unsigned char utc_time[16];
};

typedef unsigned long ck_session_handle_t;

typedef unsigned long ck_user_type_t;

typedef unsigned long ck_state_t;

struct ck_session_info {
  ck_slot_id_t slot_id;
  ck_state_t state;
  ck_flags_t flags;
  unsigned long device_error;
};

typedef unsigned long ck_object_handle_t;

typedef unsigned long ck_object_class_t;

typedef unsigned long ck_hw_feature_type_t;

typedef unsigned long ck_key_type_t;

typedef unsigned long ck_certificate_type_t;

typedef unsigned long ck_attribute_type_t;

struct ck_attribute {
  ck_attribute_type_t type_;
  char *value;
  unsigned long value_len;
};

struct ck_date {
  unsigned char year[4];
  unsigned char month[2];
  unsigned char day[2];
};

typedef unsigned long ck_mechanism_type_t;

struct ck_mechanism {
  ck_mechanism_type_t mechanism;
  char *parameter;
  unsigned long parameter_len;
};

struct ck_mechanism_info {
  unsigned long min_key_size;
  unsigned long max_key_size;
  ck_flags_t flags;
};

typedef unsigned char CK_BYTE;

typedef unsigned char CK_CHAR;

typedef unsigned char CK_UTF8CHAR;

typedef unsigned char CK_BBOOL;

typedef unsigned long CK_ULONG;

typedef long CK_LONG;

typedef CK_BYTE *CK_BYTE_PTR;

typedef CK_CHAR *CK_CHAR_PTR;

typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

typedef CK_ULONG *CK_ULONG_PTR;

typedef struct ck_version CK_VERSION;

typedef struct ck_version *CK_VERSION_PTR;

typedef struct ck_info CK_INFO;

typedef struct ck_info *CK_INFO_PTR;

typedef ck_slot_id_t *CK_SLOT_ID_PTR;

typedef struct ck_slot_info CK_SLOT_INFO;

typedef struct ck_slot_info *CK_SLOT_INFO_PTR;

typedef struct ck_token_info CK_TOKEN_INFO;

typedef struct ck_token_info *CK_TOKEN_INFO_PTR;

typedef ck_session_handle_t *CK_SESSION_HANDLE_PTR;

typedef struct ck_session_info CK_SESSION_INFO;

typedef struct ck_session_info *CK_SESSION_INFO_PTR;

typedef ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

typedef ck_object_class_t *CK_OBJECT_CLASS_PTR;

typedef struct ck_attribute CK_ATTRIBUTE;

typedef struct ck_attribute *CK_ATTRIBUTE_PTR;

typedef struct ck_date CK_DATE;

typedef struct ck_date *CK_DATE_PTR;

typedef ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

typedef struct ck_mechanism CK_MECHANISM;

typedef struct ck_mechanism *CK_MECHANISM_PTR;

typedef struct ck_mechanism_info CK_MECHANISM_INFO;

typedef struct ck_mechanism_info *CK_MECHANISM_INFO_PTR;

struct ck_c_initialize_args;
typedef struct ck_c_initialize_args CK_C_INITIALIZE_ARGS;

typedef struct ck_c_initialize_args *CK_C_INITIALIZE_ARGS_PTR;

typedef unsigned long ck_rv_t;

typedef int *ck_createmutex_t;

typedef int *ck_destroymutex_t;

typedef int *ck_lockmutex_t;

typedef int *ck_unlockmutex_t;

struct ck_c_initialize_args {
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t lock_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  void *reserved;
};

extern ck_rv_t ML_CK_C_Daemonize( /*in */ unsigned char *param,	/*in */
				 unsigned long param_len);

extern ck_rv_t ML_CK_C_SetupArch( /*in */ unsigned int arch);

extern ck_rv_t ML_CK_C_LoadModule( /*in */ unsigned char *libname);

extern ck_rv_t ML_CK_C_Initialize(void);

extern ck_rv_t ML_CK_C_Finalize(void);

extern ck_rv_t ML_CK_C_GetSlotList( /*in */ unsigned int token_present,	/*out */
				   ck_slot_id_t * slot_list,	/*in */
				   unsigned long count,	/*out */
				   unsigned long *real_count);

extern ck_rv_t ML_CK_C_GetInfo( /*out */ struct ck_info *info);

extern ck_rv_t ML_CK_C_WaitForSlotEvent( /*in */ ck_flags_t flags,	/*out */
					ck_slot_id_t * slot_id);

extern ck_rv_t ML_CK_C_GetSlotInfo( /*in */ ck_slot_id_t slot_id,	/*out */
				   struct ck_slot_info *info);

extern ck_rv_t ML_CK_C_GetTokenInfo( /*in */ ck_slot_id_t slot_id,	/*out */
				    struct ck_token_info *info);

extern ck_rv_t ML_CK_C_InitToken( /*in */ ck_slot_id_t slot_id,	/*in */
				 unsigned char *pin,	/*in */
				 unsigned long pin_len,	/*in */
				 unsigned char *label);

extern ck_rv_t ML_CK_C_OpenSession( /*in */ ck_slot_id_t slot_id,	/*in */
				   ck_flags_t flags,	/*out */
				   ck_session_handle_t * session);

extern ck_rv_t ML_CK_C_CloseSession( /*in */ ck_session_handle_t session);

extern ck_rv_t ML_CK_C_CloseAllSessions( /*in */ ck_slot_id_t slot_id);

extern ck_rv_t ML_CK_C_GetSessionInfo( /*in */ ck_session_handle_t session,
				      /*out */ struct ck_session_info *info);

extern ck_rv_t ML_CK_C_Login( /*in */ ck_session_handle_t session,	/*in */
			     ck_user_type_t user_type,	/*in */
			     unsigned char *pin, /*in */ unsigned long pin_len);

extern ck_rv_t ML_CK_C_Logout( /*in */ ck_session_handle_t session);

extern ck_rv_t ML_CK_C_GetMechanismList( /*in */ ck_slot_id_t slot_id,	/*out */
					ck_mechanism_type_t * mechanism_list,
					/*in */ unsigned long count,
					/*out */
					unsigned long *real_count);

extern ck_rv_t ML_CK_C_GetMechanismInfo( /*in */ ck_slot_id_t slot_id,	/*in */
					ck_mechanism_type_t mechanism,	/*out */
					struct ck_mechanism_info *info);

extern ck_rv_t ML_CK_C_InitPIN( /*in */ ck_session_handle_t session,	/*in */
			       unsigned char *pin,	/*in */
			       unsigned long pin_len);

extern ck_rv_t ML_CK_C_SetPIN( /*in */ ck_session_handle_t session,	/*in */
			      unsigned char *old_pin,	/*in */
			      unsigned long old_pin_len,	/*in */
			      unsigned char *new_pin,	/*in */
			      unsigned long new_pin_len);

extern ck_rv_t ML_CK_C_SeedRandom( /*in */ ck_session_handle_t session,	/*in */
				  unsigned char *seed,	/*in */
				  unsigned long seed_len);

extern ck_rv_t ML_CK_C_GenerateRandom( /*in */ ck_session_handle_t session,
				      /*out */ unsigned char *rand_value,
				      /*in */ unsigned long rand_len);

extern ck_rv_t ML_CK_C_FindObjectsInit( /*in */ ck_session_handle_t session,
				       /*in */ struct ck_attribute *templ,
				       /*in */ unsigned long count);

extern ck_rv_t ML_CK_C_FindObjects( /*in */ ck_session_handle_t session,
				   /*out */ ck_object_handle_t * object,
				   /*in */
				   unsigned long max_object_count,	/*out */
				   unsigned long *object_count);

extern ck_rv_t ML_CK_C_FindObjectsFinal( /*in */ ck_session_handle_t session);

extern ck_rv_t ML_CK_C_GenerateKey( /*in */ ck_session_handle_t session,	/*in */
				   struct ck_mechanism mechanism,	/*in */
				   struct ck_attribute *templ,	/*in */
				   unsigned long count,	/*out */
				   ck_object_handle_t * phkey);

extern ck_rv_t ML_CK_C_GenerateKeyPair( /*in */ ck_session_handle_t session,
				       /*in */ struct ck_mechanism mechanism,
				       /*in */ struct ck_attribute *pub_templ,
				       /*in */ unsigned long pub_count,
				       /*in */
				       struct ck_attribute *priv_templ,	/*in */
				       unsigned long priv_count,	/*out */
				       ck_object_handle_t * phpubkey,	/*out */
				       ck_object_handle_t * phprivkey);

extern ck_rv_t ML_CK_C_CreateObject( /*in */ ck_session_handle_t session,
				    /*in */ struct ck_attribute *templ,
				    /*in */
				    unsigned long count,	/*out */
				    ck_object_handle_t * phobject);

extern ck_rv_t ML_CK_C_CopyObject( /*in */ ck_session_handle_t session,	/*in */
				  ck_object_handle_t hobject,	/*in */
				  struct ck_attribute *templ,	/*in */
				  unsigned long count,	/*out */
				  ck_object_handle_t * phnewobject);

extern ck_rv_t ML_CK_C_DestroyObject( /*in */ ck_session_handle_t session,
				     /*in */ ck_object_handle_t hobject);

extern ck_rv_t ML_CK_C_GetAttributeValue( /*in */ ck_session_handle_t session,
					 /*in */ ck_object_handle_t hobject,
					 /*in,out */ struct ck_attribute *templ,
					 /*in */ unsigned long count);

extern ck_rv_t ML_CK_C_SetAttributeValue( /*in */ ck_session_handle_t session,
					 /*in */ ck_object_handle_t hobject,
					 /*in */ struct ck_attribute *templ,
					 /*in */ unsigned long count);

extern ck_rv_t ML_CK_C_GetObjectSize( /*in */ ck_session_handle_t session,
				     /*in */ ck_object_handle_t hobject,
				     /*out */ unsigned long *object_size);

extern ck_rv_t ML_CK_C_WrapKey( /*in */ ck_session_handle_t session,	/*in */
			       struct ck_mechanism mechanism,	/*in */
			       ck_object_handle_t hwrappingkey,	/*in */
			       ck_object_handle_t hkey,	/*out */
			       unsigned char *wrapped_key,	/*in */
			       unsigned long *wrapped_key_len);

extern ck_rv_t ML_CK_C_UnwrapKey( /*in */ ck_session_handle_t session,	/*in */
				 struct ck_mechanism mechanism,	/*in */
				 ck_object_handle_t hunwrappingkey,	/*in */
				 unsigned char *wrapped_key,	/*in */
				 unsigned long wrapped_key_len,	/*in */
				 struct ck_attribute *templ,	/*in */
				 unsigned long count,	/*out */
				 ck_object_handle_t * phobject);

extern ck_rv_t ML_CK_C_DeriveKey( /*in */ ck_session_handle_t session,	/*in */
				 struct ck_mechanism mechanism,	/*in */
				 ck_object_handle_t hbasekey,	/*in */
				 struct ck_attribute *templ,	/*in */
				 unsigned long count,	/*out */
				 ck_object_handle_t * phkey);

extern ck_rv_t ML_CK_C_DigestInit( /*in */ ck_session_handle_t session,	/*in */
				  struct ck_mechanism mechanism);

extern ck_rv_t ML_CK_C_Digest( /*in */ ck_session_handle_t session,	/*in */
			      unsigned char *data,	/*in */
			      unsigned long data_len,	/*out */
			      unsigned char *digest,	/*in */
			      unsigned long *digest_len);

extern ck_rv_t ML_CK_C_DigestUpdate( /*in */ ck_session_handle_t session,
				    /*in */ unsigned char *data,
				    /*in */
				    unsigned long data_len);

extern ck_rv_t ML_CK_C_DigestKey( /*in */ ck_session_handle_t session,	/*in */
				 ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_DigestFinal( /*in */ ck_session_handle_t session,
				   /*out */ unsigned char *digest,
				   /*in */
				   unsigned long *digest_len);

extern ck_rv_t ML_CK_C_SignInit( /*in */ ck_session_handle_t session,	/*in */
				struct ck_mechanism mechanism,	/*in */
				ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_SignRecoverInit( /*in */ ck_session_handle_t session,
				       /*in */ struct ck_mechanism mechanism,
				       /*in */ ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_Sign( /*in */ ck_session_handle_t session,	/*in */
			    unsigned char *data, /*in */ unsigned long data_len,
			    /*out */ unsigned char *signature,
			    /*in */
			    unsigned long *signed_len);

extern ck_rv_t ML_CK_C_SignRecover( /*in */ ck_session_handle_t session,	/*in */
				   unsigned char *data,	/*in */
				   unsigned long data_len,	/*out */
				   unsigned char *signature,	/*in */
				   unsigned long *signed_len);

extern ck_rv_t ML_CK_C_SignUpdate( /*in */ ck_session_handle_t session,	/*in */
				  unsigned char *data,	/*in */
				  unsigned long data_len);

extern ck_rv_t ML_CK_C_SignFinal( /*in */ ck_session_handle_t session,	/*out */
				 unsigned char *signature,	/*in */
				 unsigned long *signed_len);

extern ck_rv_t ML_CK_C_VerifyInit( /*in */ ck_session_handle_t session,	/*in */
				  struct ck_mechanism mechanism,	/*in */
				  ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_VerifyRecoverInit( /*in */ ck_session_handle_t session,
					 /*in */ struct ck_mechanism mechanism,
					 /*in */ ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_Verify( /*in */ ck_session_handle_t session,	/*in */
			      unsigned char *data,	/*in */
			      unsigned long data_len,	/*in */
			      unsigned char *signature,	/*in */
			      unsigned long signed_len);

extern ck_rv_t ML_CK_C_VerifyRecover(ck_session_handle_t session,
				     unsigned char *signature,
				     unsigned long signature_len,
				     unsigned char **data,
				     unsigned long *data_len);

extern ck_rv_t ML_CK_C_VerifyUpdate( /*in */ ck_session_handle_t session,
				    /*in */ unsigned char *data,
				    /*in */
				    unsigned long data_len);

extern ck_rv_t ML_CK_C_VerifyFinal( /*in */ ck_session_handle_t session,	/*in */
				   unsigned char *signature,	/*in */
				   unsigned long signed_len);

extern ck_rv_t ML_CK_C_EncryptInit( /*in */ ck_session_handle_t session,	/*in */
				   struct ck_mechanism mechanism,	/*in */
				   ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_Encrypt(ck_session_handle_t session, unsigned char *data,
			       unsigned long data_len,
			       unsigned char **encrypted,
			       unsigned long *encrypted_len);

extern ck_rv_t ML_CK_C_EncryptUpdate(ck_session_handle_t session,
				     unsigned char *data,
				     unsigned long data_len,
				     unsigned char **encrypted,
				     unsigned long *encrypted_len);

extern ck_rv_t ML_CK_C_EncryptFinal(ck_session_handle_t session,
				    unsigned char **encrypted,
				    unsigned long *encrypted_len);

extern ck_rv_t ML_CK_C_DigestEncryptUpdate(ck_session_handle_t session,
					   unsigned char *data,
					   unsigned long data_len,
					   unsigned char **encrypted,
					   unsigned long *encrypted_len);

extern ck_rv_t ML_CK_C_SignEncryptUpdate(ck_session_handle_t session,
					 unsigned char *data,
					 unsigned long data_len,
					 unsigned char **encrypted,
					 unsigned long *encrypted_len);

extern ck_rv_t ML_CK_C_DecryptInit( /*in */ ck_session_handle_t session,	/*in */
				   struct ck_mechanism mechanism,	/*in */
				   ck_object_handle_t hkey);

extern ck_rv_t ML_CK_C_Decrypt(ck_session_handle_t session,
			       unsigned char *encrypted,
			       unsigned long encrypted_len,
			       unsigned char **decrypted,
			       unsigned long *decrypted_len);

extern ck_rv_t ML_CK_C_DecryptUpdate(ck_session_handle_t session,
				     unsigned char *encrypted,
				     unsigned long encrypted_len,
				     unsigned char **data,
				     unsigned long *data_len);

extern ck_rv_t ML_CK_C_DecryptFinal(ck_session_handle_t session,
				    unsigned char **decrypted,
				    unsigned long *decrypted_len);

extern ck_rv_t ML_CK_C_DecryptDigestUpdate(ck_session_handle_t session,
					   unsigned char *encrypted,
					   unsigned long encrypted_len,
					   unsigned char **data,
					   unsigned long *data_len);

extern ck_rv_t ML_CK_C_DecryptVerifyUpdate(ck_session_handle_t session,
					   unsigned char *encrypted,
					   unsigned long encrypted_len,
					   unsigned char **data,
					   unsigned long *data_len);

extern ck_rv_t ML_CK_C_GetOperationState(ck_session_handle_t session,
					 unsigned char **data,
					 unsigned long *data_len);

extern ck_rv_t ML_CK_C_SetOperationState( /*in */ ck_session_handle_t session,
					 /*in */ unsigned char *data,
					 /*in */
					 unsigned long data_len,	/*in */
					 ck_object_handle_t hencryptionkey,
					 /*in */
					 ck_object_handle_t hauthenticationkey);

extern ck_rv_t ML_CK_C_GetFunctionStatus( /*in */ ck_session_handle_t session);

extern ck_rv_t ML_CK_C_CancelFunction( /*in */ ck_session_handle_t session);

extern void int_to_ulong_char_array( /*in */ unsigned long input,	/*out */
				    unsigned char *data);

extern void char_array_to_ulong( /*in */ unsigned char *data,	/*in */
				size_t data_size,	/*out */
				unsigned long *output);

extern void hton_char_array( /*in */ unsigned char *in, unsigned long in_len,
								/*out */ unsigned char *out,
								/*in */
			    unsigned long *out_len);

extern void ntoh_char_array( /*in */ unsigned char *in, unsigned long in_len,
								/*out */ unsigned char *out,
								/*in */
			    unsigned long *out_len);

/* Avoid declaring caml stuff when sharing this header with C rpc client code */
#if !defined(CRPC)
void camlidl_ml2c_pkcs11_ck_flags_t(value _v1, ck_flags_t * _c2,
				    camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_flags_t(ck_flags_t * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_version(value _v1, struct ck_version *_c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_version(struct ck_version *_c1,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_info(value _v1, struct ck_info *_c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_info(struct ck_info *_c1, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_notification_t(value _v1, ck_notification_t * _c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_notification_t(ck_notification_t * _c2,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_slot_id_t(value _v1, ck_slot_id_t * _c2,
				      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_slot_id_t(ck_slot_id_t * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_slot_info(value _v1,
					     struct ck_slot_info *_c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_slot_info(struct ck_slot_info *_c1,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_token_info(value _v1,
					      struct ck_token_info *_c2,
					      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_token_info(struct ck_token_info *_c1,
					       camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_session_handle_t(value _v1,
					     ck_session_handle_t * _c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_session_handle_t(ck_session_handle_t * _c2,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_user_type_t(value _v1, ck_user_type_t * _c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_user_type_t(ck_user_type_t * _c2,
					 camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_state_t(value _v1, ck_state_t * _c2,
				    camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_state_t(ck_state_t * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_session_info(value _v1,
						struct ck_session_info *_c2,
						camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_session_info(struct ck_session_info *_c1,
						 camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_object_handle_t(value _v1, ck_object_handle_t * _c2,
					    camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_object_handle_t(ck_object_handle_t * _c2,
					     camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_object_class_t(value _v1, ck_object_class_t * _c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_object_class_t(ck_object_class_t * _c2,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_hw_feature_type_t(value _v1,
					      ck_hw_feature_type_t * _c2,
					      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_hw_feature_type_t(ck_hw_feature_type_t * _c2,
					       camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_key_type_t(value _v1, ck_key_type_t * _c2,
				       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_key_type_t(ck_key_type_t * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_certificate_type_t(value _v1,
					       ck_certificate_type_t * _c2,
					       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_certificate_type_t(ck_certificate_type_t * _c2,
						camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_attribute_type_t(value _v1,
					     ck_attribute_type_t * _c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_attribute_type_t(ck_attribute_type_t * _c2,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_attribute(value _v1,
					     struct ck_attribute *_c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_attribute(struct ck_attribute *_c1,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_date(value _v1, struct ck_date *_c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_date(struct ck_date *_c1, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_mechanism_type_t(value _v1,
					     ck_mechanism_type_t * _c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_mechanism_type_t(ck_mechanism_type_t * _c2,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_mechanism(value _v1,
					     struct ck_mechanism *_c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_struct_ck_mechanism_info(value _v1,
						  struct ck_mechanism_info *_c2,
						  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_struct_ck_mechanism_info(struct ck_mechanism_info
						   *_c1, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_BYTE(value _v1, CK_BYTE * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_BYTE(CK_BYTE * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_CHAR(value _v1, CK_CHAR * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_CHAR(CK_CHAR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_UTF8CHAR(value _v1, CK_UTF8CHAR * _c2,
				     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_UTF8CHAR(CK_UTF8CHAR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_BBOOL(value _v1, CK_BBOOL * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_BBOOL(CK_BBOOL * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_ULONG(value _v1, CK_ULONG * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_ULONG(CK_ULONG * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_LONG(value _v1, CK_LONG * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_LONG(CK_LONG * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_BYTE_PTR(value _v1, CK_BYTE_PTR * _c2,
				     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_BYTE_PTR(CK_BYTE_PTR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_CHAR_PTR(value _v1, CK_CHAR_PTR * _c2,
				     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_CHAR_PTR(CK_CHAR_PTR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_UTF8CHAR_PTR(value _v1, CK_UTF8CHAR_PTR * _c2,
					 camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_UTF8CHAR_PTR(CK_UTF8CHAR_PTR * _c2,
					  camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_ULONG_PTR(value _v1, CK_ULONG_PTR * _c2,
				      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_ULONG_PTR(CK_ULONG_PTR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_VERSION(value _v1, CK_VERSION * _c2,
				    camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_VERSION(CK_VERSION * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_VERSION_PTR(value _v1, CK_VERSION_PTR * _c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_VERSION_PTR(CK_VERSION_PTR * _c2,
					 camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_INFO(value _v1, CK_INFO * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_INFO(CK_INFO * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_INFO_PTR(value _v1, CK_INFO_PTR * _c2,
				     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_INFO_PTR(CK_INFO_PTR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SLOT_ID_PTR(value _v1, CK_SLOT_ID_PTR * _c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SLOT_ID_PTR(CK_SLOT_ID_PTR * _c2,
					 camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SLOT_INFO(value _v1, CK_SLOT_INFO * _c2,
				      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SLOT_INFO(CK_SLOT_INFO * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SLOT_INFO_PTR(value _v1, CK_SLOT_INFO_PTR * _c2,
					  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SLOT_INFO_PTR(CK_SLOT_INFO_PTR * _c2,
					   camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO(value _v1, CK_TOKEN_INFO * _c2,
				       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO(CK_TOKEN_INFO * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO_PTR(value _v1, CK_TOKEN_INFO_PTR * _c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO_PTR(CK_TOKEN_INFO_PTR * _c2,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SESSION_HANDLE_PTR(value _v1,
					       CK_SESSION_HANDLE_PTR * _c2,
					       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SESSION_HANDLE_PTR(CK_SESSION_HANDLE_PTR * _c2,
						camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SESSION_INFO(value _v1, CK_SESSION_INFO * _c2,
					 camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SESSION_INFO(CK_SESSION_INFO * _c2,
					  camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_SESSION_INFO_PTR(value _v1,
					     CK_SESSION_INFO_PTR * _c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_SESSION_INFO_PTR(CK_SESSION_INFO_PTR * _c2,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_OBJECT_HANDLE_PTR(value _v1,
					      CK_OBJECT_HANDLE_PTR * _c2,
					      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_OBJECT_HANDLE_PTR(CK_OBJECT_HANDLE_PTR * _c2,
					       camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_OBJECT_CLASS_PTR(value _v1,
					     CK_OBJECT_CLASS_PTR * _c2,
					     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_OBJECT_CLASS_PTR(CK_OBJECT_CLASS_PTR * _c2,
					      camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE(value _v1, CK_ATTRIBUTE * _c2,
				      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE(CK_ATTRIBUTE * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE_PTR(value _v1, CK_ATTRIBUTE_PTR * _c2,
					  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE_PTR(CK_ATTRIBUTE_PTR * _c2,
					   camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_DATE(value _v1, CK_DATE * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_DATE(CK_DATE * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_DATE_PTR(value _v1, CK_DATE_PTR * _c2,
				     camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_DATE_PTR(CK_DATE_PTR * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_MECHANISM_TYPE_PTR(value _v1,
					       CK_MECHANISM_TYPE_PTR * _c2,
					       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_MECHANISM_TYPE_PTR(CK_MECHANISM_TYPE_PTR * _c2,
						camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_MECHANISM(value _v1, CK_MECHANISM * _c2,
				      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_MECHANISM(CK_MECHANISM * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_MECHANISM_PTR(value _v1, CK_MECHANISM_PTR * _c2,
					  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_MECHANISM_PTR(CK_MECHANISM_PTR * _c2,
					   camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO(value _v1, CK_MECHANISM_INFO * _c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO(CK_MECHANISM_INFO * _c2,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO_PTR(value _v1,
					       CK_MECHANISM_INFO_PTR * _c2,
					       camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO_PTR(CK_MECHANISM_INFO_PTR * _c2,
						camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS(value _v1,
					      CK_C_INITIALIZE_ARGS * _c2,
					      camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS(CK_C_INITIALIZE_ARGS * _c2,
					       camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS_PTR(value _v1,
						  CK_C_INITIALIZE_ARGS_PTR *
						  _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS_PTR(CK_C_INITIALIZE_ARGS_PTR *
						   _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_rv_t(value _v1, ck_rv_t * _c2, camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_rv_t(ck_rv_t * _c2, camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_createmutex_t(value _v1, ck_createmutex_t * _c2,
					  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_createmutex_t(ck_createmutex_t * _c2,
					   camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_destroymutex_t(value _v1, ck_destroymutex_t * _c2,
					   camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_destroymutex_t(ck_destroymutex_t * _c2,
					    camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_lockmutex_t(value _v1, ck_lockmutex_t * _c2,
					camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_lockmutex_t(ck_lockmutex_t * _c2,
					 camlidl_ctx _ctx);
void camlidl_ml2c_pkcs11_ck_unlockmutex_t(value _v1, ck_unlockmutex_t * _c2,
					  camlidl_ctx _ctx);
value camlidl_c2ml_pkcs11_ck_unlockmutex_t(ck_unlockmutex_t * _c2,
					   camlidl_ctx _ctx);
value camlidl_pkcs11_ML_CK_C_Daemonize(value _v_param);
value camlidl_pkcs11_ML_CK_C_SetupArch(value _v_client_arch);
value camlidl_pkcs11_ML_CK_C_LoadModule(value _v_libname);
value camlidl_pkcs11_ML_CK_C_Initialize(value _unit);
value camlidl_pkcs11_ML_CK_C_Finalize(value _unit);
value camlidl_pkcs11_ML_CK_C_GetSlotList(value _v_token_present,
					 value _v_count);
value camlidl_pkcs11_ML_CK_C_GetInfo(value _unit);
value camlidl_pkcs11_ML_CK_C_WaitForSlotEvent(value _v_flags);
value camlidl_pkcs11_ML_CK_C_GetSlotInfo(value _v_slot_id);
value camlidl_pkcs11_ML_CK_C_GetTokenInfo(value _v_slot_id);
value camlidl_pkcs11_ML_CK_C_InitToken(value _v_slot_id, value _v_pin,
				       value _v_label);
value camlidl_pkcs11_ML_CK_C_OpenSession(value _v_slot_id, value _v_flags);
value camlidl_pkcs11_ML_CK_C_CloseSession(value _v_session);
value camlidl_pkcs11_ML_CK_C_CloseAllSessions(value _v_slot_id);
value camlidl_pkcs11_ML_CK_C_GetSessionInfo(value _v_session);
value camlidl_pkcs11_ML_CK_C_Login(value _v_session, value _v_user_type,
				   value _v_pin);
value camlidl_pkcs11_ML_CK_C_Logout(value _v_session);
value camlidl_pkcs11_ML_CK_C_GetMechanismList(value _v_slot_id, value _v_count);
value camlidl_pkcs11_ML_CK_C_GetMechanismInfo(value _v_slot_id,
					      value _v_mechanism);
value camlidl_pkcs11_ML_CK_C_InitPIN(value _v_session, value _v_pin);
value camlidl_pkcs11_ML_CK_C_SetPIN(value _v_session, value _v_old_pin,
				    value _v_new_pin);
value camlidl_pkcs11_ML_CK_C_SeedRandom(value _v_session, value _v_seed);
value camlidl_pkcs11_ML_CK_C_GenerateRandom(value _v_session,
					    value _v_rand_len);
value camlidl_pkcs11_ML_CK_C_FindObjectsInit(value _v_session, value _v_templ);
value camlidl_pkcs11_ML_CK_C_FindObjects(value _v_session,
					 value _v_max_object_count);
value camlidl_pkcs11_ML_CK_C_FindObjectsFinal(value _v_session);
value camlidl_pkcs11_ML_CK_C_GenerateKey(value _v_session, value _v_mechanism,
					 value _v_templ);
value camlidl_pkcs11_ML_CK_C_GenerateKeyPair(value _v_session,
					     value _v_mechanism,
					     value _v_pub_templ,
					     value _v_priv_templ);
value camlidl_pkcs11_ML_CK_C_CreateObject(value _v_session, value _v_templ);
value camlidl_pkcs11_ML_CK_C_CopyObject(value _v_session, value _v_hobject,
					value _v_templ);
value camlidl_pkcs11_ML_CK_C_DestroyObject(value _v_session, value _v_hobject);
value camlidl_pkcs11_ML_CK_C_GetAttributeValue(value _v_session,
					       value _v_hobject,
					       value _v_templ);
value camlidl_pkcs11_ML_CK_C_SetAttributeValue(value _v_session,
					       value _v_hobject,
					       value _v_templ);
value camlidl_pkcs11_ML_CK_C_GetObjectSize(value _v_session, value _v_hobject);
value camlidl_pkcs11_ML_CK_C_WrapKey(value _v_session, value _v_mechanism,
				     value _v_hwrappingkey, value _v_hkey);
value camlidl_pkcs11_ML_CK_C_UnwrapKey(value _v_session, value _v_mechanism,
				       value _v_hunwrappingkey,
				       value _v_wrapped_key, value _v_templ);
value camlidl_pkcs11_ML_CK_C_DeriveKey(value _v_session, value _v_mechanism,
				       value _v_hbasekey, value _v_templ);
value camlidl_pkcs11_ML_CK_C_DigestInit(value _v_session, value _v_mechanism);
value camlidl_pkcs11_ML_CK_C_Digest(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_DigestUpdate(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_DigestKey(value _v_session, value _v_hkey);
value camlidl_pkcs11_ML_CK_C_DigestFinal(value _v_session);
value camlidl_pkcs11_ML_CK_C_SignInit(value _v_session, value _v_mechanism,
				      value _v_hkey);
value camlidl_pkcs11_ML_CK_C_SignRecoverInit(value _v_session,
					     value _v_mechanism, value _v_hkey);
value camlidl_pkcs11_ML_CK_C_Sign(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_SignRecover(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_SignUpdate(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_SignFinal(value _v_session);
value camlidl_pkcs11_ML_CK_C_VerifyInit(value _v_session, value _v_mechanism,
					value _v_hkey);
value camlidl_pkcs11_ML_CK_C_VerifyRecoverInit(value _v_session,
					       value _v_mechanism,
					       value _v_hkey);
value camlidl_pkcs11_ML_CK_C_Verify(value _v_session, value _v_data,
				    value _v_signature);
value camlidl_pkcs11_ML_CK_C_VerifyRecover(value _v_session,
					   value _v_signature);
value camlidl_pkcs11_ML_CK_C_VerifyUpdate(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_VerifyFinal(value _v_session, value _v_signature);
value camlidl_pkcs11_ML_CK_C_EncryptInit(value _v_session, value _v_mechanism,
					 value _v_hkey);
value camlidl_pkcs11_ML_CK_C_Encrypt(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_EncryptUpdate(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_EncryptFinal(value _v_session);
value camlidl_pkcs11_ML_CK_C_DigestEncryptUpdate(value _v_session,
						 value _v_data);
value camlidl_pkcs11_ML_CK_C_SignEncryptUpdate(value _v_session, value _v_data);
value camlidl_pkcs11_ML_CK_C_DecryptInit(value _v_session, value _v_mechanism,
					 value _v_hkey);
value camlidl_pkcs11_ML_CK_C_Decrypt(value _v_session, value _v_encrypted);
value camlidl_pkcs11_ML_CK_C_DecryptUpdate(value _v_session,
					   value _v_encrypted);
value camlidl_pkcs11_ML_CK_C_DecryptFinal(value _v_session);
value camlidl_pkcs11_ML_CK_C_DecryptDigestUpdate(value _v_session,
						 value _v_encrypted);
value camlidl_pkcs11_ML_CK_C_DecryptVerifyUpdate(value _v_session,
						 value _v_encrypted);
value camlidl_pkcs11_ML_CK_C_GetOperationState(value _v_session);
value camlidl_pkcs11_ML_CK_C_SetOperationState(value _v_session, value _v_data,
					       value _v_hencryptionkey,
					       value _v_hauthenticationkey);
value camlidl_pkcs11_ML_CK_C_GetFunctionStatus(value _v_session);
value camlidl_pkcs11_ML_CK_C_CancelFunction(value _v_session);
value camlidl_pkcs11_int_to_ulong_char_array(value _v_input);
value camlidl_pkcs11_char_array_to_ulong(value _v_data);
value camlidl_pkcs11_hton_char_array(value _v_data);
value camlidl_pkcs11_ntoh_char_array(value _v_data);
#ifdef SERVER_ROLE
int decode_ck_attribute_arch(value, struct ck_attribute *, camlidl_ctx);
int encode_ck_attribute_arch(struct ck_attribute *, struct ck_attribute *);
#endif
#endif				/* !CRPC */
#ifdef _WIN32
#pragma pack(pop)
#endif

#endif				/* !_CAMLIDL_PKCS11_H */
