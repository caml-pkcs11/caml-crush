/*------------------------ CeCILL-B HEADER ------------------------------------
    Copyright ANSSI (2013)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]

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

    This software is governed by the CeCILL-B license under French law and
    abiding by the rules of distribution of free software.  You can  use,
    modify and/ or redistribute the software under the terms of the CeCILL-B
    license as circulated by CEA, CNRS and INRIA at the following URL
    "http://www.cecill.info".

    As a counterpart to the access to the source code and  rights to copy,
    modify and redistribute granted by the license, users are provided only
    with a limited warranty  and the software's author,  the holder of the
    economic rights,  and the successive licensors  have only  limited
    liability.

    In this respect, the user's attention is drawn to the risks associated
    with loading,  using,  modifying and/or developing or reproducing the
    software by the user in light of its specific status of free software,
    that may mean  that it is complicated to manipulate,  and  that  also
    therefore means  that it is reserved for developers  and  experienced
    professionals having in-depth computer knowledge. Users are therefore
    encouraged to load and test the software's suitability as regards their
    requirements in conditions enabling the security of their systems and/or
    data to be ensured and,  more generally, to use and operate it in the
    same conditions as regards security.

    The fact that you are presently reading this means that you have had
    knowledge of the CeCILL-B license and that you accept its terms.

    The current source code is part of the client library 5] source tree:
                                                          --------------------
                                                         | 5] Client library  |
                                                         |  --------          |
                                                         | |        | PKCS#11 |
                                                         | |        |functions|
                                                         |  --------          |
                                                          --------------------
                                                                    |
                                                                    |
                                                          { PKCS#11 INTERFACE }
                                                                    |
                                                              APPLICATION

    Project: PKCS#11 Filtering Proxy
    File:    src/client-lib/modwrap.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include <stddef.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>
#ifdef Custom_tag
#include <caml/custom.h>
#include <caml/bigarray.h>
#endif
#include <caml/camlidlruntime.h>

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "helpers_pkcs11.h"

/* Check for a socket type */
#if !defined(TCP_SOCKET) && !defined(UNIX_SOCKET)
#error "No socket defined at compile time"
#endif

/* UNIX_SOCKET on Mac OS X is not supported */
#if defined(UNIX_SOCKET) && defined(__APPLE__)
#error "Sorry, Apple implementation of XDR RPC does not support UNIX sockets, please use TCP"
#endif

/* Wrap return code to adapt it to CRPC/CAMLRPC */
#ifdef CRPC
#define Return(x) do { return x; } while(0);
#else
#define Return(x) do { CAMLreturn(x); } while(0);
#endif

/* Macro to factorize check of results */
#define check_linked_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len) do {\
  /* Remember previous calls */\
  elem = check_element_in_filtering_list(input0, operation_cst, input1, input1_len);\
  if (elem != NULL) {\
    if (output2 == NULL) {\
\
      DEBUG_CALL(operation_type, "was called again with NULL output buffer\n");\
\
      *output2_len = elem->out_len;\
      Return(CKR_OK);\
    }\
    if (*output2_len < elem->out_len) {\
\
      DEBUG_CALL(operation_type, "was called with an output buffer too small\n");\
\
      *output2_len = elem->out_len;\
      Return(CKR_BUFFER_TOO_SMALL);\
    } else {\
      /* buffer size is enough, copy back and remove item from list */\
      DEBUG_CALL(operation_type, "Buffer given is big enough, let's copy data back\n");\
      memcpy(output2, elem->out, elem->out_len);\
      remove_elements_from_filtering_list(input0, operation_cst, input1,\
                                          input1_len);\
      Return(CKR_OK);\
    }\
  }\
} while(0);

#ifdef CRPC
/* add_op_element_to_list for CAMLRPC */
#define add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len) do {\
      elem = add_element_to_list(input0, operation_cst, input1, input1_len, output2,\
                 *output2_len);\
      elem->out = custom_malloc(MAX_BUFF_LEN * sizeof(unsigned char));\
      elem->out_len = ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_len;\
      memcpy(elem->out, ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_val,\
         ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_len);\
      *output2_len = elem->out_len;\
      custom_free((void**)&ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_val);\
} while(0);
#else
/* add_op_element_to_list for CAMLRPC */
#define add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len) do {\
      elem = add_element_to_list(input0, operation_cst, input1, input1_len, output2,\
                 *output2_len);\
      elem->out = custom_malloc(MAX_BUFF_LEN * sizeof(unsigned char));\
      custom_pkcs11_ml2c_char_array_to_buffer(Field(tuple, 1), elem->out, &elem->out_len);\
      camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);\
      *output2_len = elem->out_len;\
} while(0);
#endif

#ifdef CRPC
/* handle_linked_list for CRPC */
#define handle_linked_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len) do {\
  if (ret.c_ ## operation_type ## _rv == CKR_OK) {\
    if (output2 == NULL) {\
      add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len);\
      return ret.c_ ## operation_type ## _rv;\
    }\
    if (*output2_len < ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_len) {\
      add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len);\
      return CKR_BUFFER_TOO_SMALL;\
    }\
  }\
  /* Normal case when called with already allocated stuff */\
  *output2_len = ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_len;\
  memcpy(output2, ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_val,\
     ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_len);\
  custom_free((void**)&ret.c_ ## operation_type ## _value.c_ ## operation_type ## _value_val);\
  return ret.c_ ## operation_type ## _rv;\
} while(0);
#else
/* handle_linked_list for CAMLRPC */
#define handle_linked_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len) do {\
  if (ret == CKR_OK) {\
    if (output2 == NULL) {\
      add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len);\
      CAMLreturn(ret);\
    }\
    if (*output2_len < Wosize_val(Field(tuple, 1))) {\
      add_op_element_to_list(operation_type, operation_cst, input0, input1, input1_len, output2, output2_len);\
      CAMLreturn(CKR_BUFFER_TOO_SMALL);\
    }\
  }\
  /* Normal case when called with already allocated stuff */\
  custom_pkcs11_ml2c_char_array_to_buffer(Field(tuple, 1), output2, output2_len);\
  CAMLreturn(ret);\
} while(0);
#endif

/* Macro to adapt to different version or RPCGEN */
#ifdef CRPC
/* MACRO to intialize the ret */
#ifdef RPCGEN_MT
#define init_ret do {\
  memset (&ret, 0, sizeof (ret));\
} while(0);
#else
#define init_ret do {\
} while(0);
#endif

/* MACRO to check the return status of the RPC */
#ifdef RPCGEN_MT
#define assert_rpc\
  if (retval != RPC_SUCCESS)
#else
#define assert_rpc \
  if (pret == NULL)
#endif

#endif

/* bindings include 					 */
#include "pkcs11.h"
/* rpc C include */
/* We only include the rpc headers if we compile the CRPC */
#ifdef CRPC
#include "pkcs11_rpc.h"
#endif

/* gethostbyname include */
#ifdef TCP_SOCKET
#include <netdb.h>
#define MAX_HOSTNAME_LEN 1024
#endif

#ifdef WITH_SSL
#include <sys/poll.h>
#include <errno.h>
void override_net_functions(CLIENT *);
int readnet(char *, char *, int);
int writenet(char *, char *, int);

#define MCALL_MSG_SIZE 24
struct ct_data {
  int ct_sock;
  bool_t ct_closeit;
  struct timeval ct_wait;
  bool_t ct_waitset;		/* wait set by clnt_control? */
#ifdef UNIX_SOCKET
  struct sockaddr_un ct_addr;
#else
  struct sockaddr_in ct_addr;
#endif
  struct rpc_err ct_error;
  char ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
  u_int ct_mpos;		/* pos after marshal */
  XDR ct_xdrs;
};

int provision_certificates(void);

#endif

/* GNUTLS SSL */
#ifdef GNU_TLS
#include <gnutls/gnutls.h>

int start_gnutls(int sock);
int purge_gnutls(void);
void print_info(gnutls_session_t gsession);

/* Global variables for GNU_TLS */
gnutls_session_t gnutls_global_session;
gnutls_certificate_credentials_t xcred;
#endif

/* OpenSSL */
#if defined(WITH_SSL) && !defined(GNU_TLS)
#include <openssl/ssl.h>
int start_openssl(int sock);
int purge_openssl(void);
SSL_CTX *ctx;
SSL *ssl;
#endif

#define ENV_SOCKET_PATH_NAME "PKCS11PROXY_SOCKET_PATH"

/* --------- PKCS#11 useful defines - */
#define CKR_OK                          (0UL)
#define CKR_ARGUMENTS_BAD               (7UL)
#define CKR_BUFFER_TOO_SMALL            (0x150UL)
#define CKR_OPERATION_ACTIVE            (0x90L)
#define CKR_FUNCTION_NOT_SUPPORTED      (0x54UL)

/* Defines imported to match mechanism in sanitize function */
#define CKM_RSA_PKCS_KEY_PAIR_GEN       (0UL)
#define CKM_RSA_PKCS                    (1UL)
#define CKM_RSA_9796                    (2UL)
#define CKM_RSA_X_509                   (3UL)
#define CKM_MD2_RSA_PKCS                (4UL)
#define CKM_MD5_RSA_PKCS                (5UL)
#define CKM_SHA1_RSA_PKCS               (6UL)
#define CKM_RIPEMD128_RSA_PKCS          (7UL)
#define CKM_RIPEMD160_RSA_PKCS          (8UL)
#define CKM_RSA_PKCS_OAEP               (9UL)
#define CKM_RSA_X9_31_KEY_PAIR_GEN      (0xaUL)
#define CKM_RSA_X9_31                   (0xbUL)
#define CKM_SHA1_RSA_X9_31              (0xcUL)
#define CKM_RSA_PKCS_PSS                (0xdUL)
#define CKM_SHA1_RSA_PKCS_PSS           (0xeUL)
#define CKM_DSA_KEY_PAIR_GEN            (0x10UL)
#define CKM_DSA                         (0x11UL)
#define CKM_DSA_SHA1                    (0x12UL)
#define CKM_DH_PKCS_KEY_PAIR_GEN        (0x20UL)
#define CKM_DH_PKCS_DERIVE              (0x21UL)
#define CKM_X9_42_DH_KEY_PAIR_GEN       (0x30UL)
#define CKM_X9_42_DH_DERIVE             (0x31UL)
#define CKM_X9_42_DH_HYBRID_DERIVE      (0x32UL)
#define CKM_X9_42_MQV_DERIVE            (0x33UL)
#define CKM_SHA256_RSA_PKCS             (0x40UL)
#define CKM_SHA384_RSA_PKCS             (0x41UL)
#define CKM_SHA512_RSA_PKCS             (0x42UL)
#define CKM_SHA256_RSA_PKCS_PSS         (0x43UL)
#define CKM_SHA384_RSA_PKCS_PSS         (0x44UL)
#define CKM_SHA512_RSA_PKCS_PSS         (0x45UL)
#define CKM_RC2_KEY_GEN                 (0x100UL)
#define CKM_RC2_ECB                     (0x101UL)
#define CKM_RC2_CBC                     (0x102UL)
#define CKM_RC2_MAC                     (0x103UL)
#define CKM_RC2_MAC_GENERAL             (0x104UL)
#define CKM_RC2_CBC_PAD                 (0x105UL)
#define CKM_RC4_KEY_GEN                 (0x110UL)
#define CKM_RC4                         (0x111UL)
#define CKM_DES_KEY_GEN                 (0x120UL)
#define CKM_DES_ECB                     (0x121UL)
#define CKM_DES_CBC                     (0x122UL)
#define CKM_DES_MAC                     (0x123UL)
#define CKM_DES_MAC_GENERAL             (0x124UL)
#define CKM_DES_CBC_PAD                 (0x125UL)
#define CKM_DES2_KEY_GEN                (0x130UL)
#define CKM_DES3_KEY_GEN                (0x131UL)
#define CKM_DES3_ECB                    (0x132UL)
#define CKM_DES3_CBC                    (0x133UL)
#define CKM_DES3_MAC                    (0x134UL)
#define CKM_DES3_MAC_GENERAL            (0x135UL)
#define CKM_DES3_CBC_PAD                (0x136UL)
#define CKM_CDMF_KEY_GEN                (0x140UL)
#define CKM_CDMF_ECB                    (0x141UL)
#define CKM_CDMF_CBC                    (0x142UL)
#define CKM_CDMF_MAC                    (0x143UL)
#define CKM_CDMF_MAC_GENERAL            (0x144UL)
#define CKM_CDMF_CBC_PAD                (0x145UL)
#define CKM_MD2                         (0x200UL)
#define CKM_MD2_HMAC                    (0x201UL)
#define CKM_MD2_HMAC_GENERAL            (0x202UL)
#define CKM_MD5                         (0x210UL)
#define CKM_MD5_HMAC                    (0x211UL)
#define CKM_MD5_HMAC_GENERAL            (0x212UL)
#define CKM_SHA_1                       (0x220UL)
#define CKM_SHA_1_HMAC                  (0x221UL)
#define CKM_SHA_1_HMAC_GENERAL          (0x222UL)
#define CKM_RIPEMD128                   (0x230UL)
#define CKM_RIPEMD128_HMAC              (0x231UL)
#define CKM_RIPEMD128_HMAC_GENERAL      (0x232UL)
#define CKM_RIPEMD160                   (0x240UL)
#define CKM_RIPEMD160_HMAC              (0x241UL)
#define CKM_RIPEMD160_HMAC_GENERAL      (0x242UL)
#define CKM_SHA256                      (0x250UL)
#define CKM_SHA256_HMAC                 (0x251UL)
#define CKM_SHA256_HMAC_GENERAL         (0x252UL)
#define CKM_SHA384                      (0x260UL)
#define CKM_SHA384_HMAC                 (0x261UL)
#define CKM_SHA384_HMAC_GENERAL         (0x262UL)
#define CKM_SHA512                      (0x270UL)
#define CKM_SHA512_HMAC                 (0x271UL)
#define CKM_SHA512_HMAC_GENERAL         (0x272UL)
#define CKM_CAST_KEY_GEN                (0x300UL)
#define CKM_CAST_ECB                    (0x301UL)
#define CKM_CAST_CBC                    (0x302UL)
#define CKM_CAST_MAC                    (0x303UL)
#define CKM_CAST_MAC_GENERAL            (0x304UL)
#define CKM_CAST_CBC_PAD                (0x305UL)
#define CKM_CAST3_KEY_GEN               (0x310UL)
#define CKM_CAST3_ECB                   (0x311UL)
#define CKM_CAST3_CBC                   (0x312UL)
#define CKM_CAST3_MAC                   (0x313UL)
#define CKM_CAST3_MAC_GENERAL           (0x314UL)
#define CKM_CAST3_CBC_PAD               (0x315UL)
#define CKM_CAST5_KEY_GEN               (0x320UL)
#define CKM_CAST128_KEY_GEN             (0x320UL)
#define CKM_CAST5_ECB                   (0x321UL)
#define CKM_CAST128_ECB                 (0x321UL)
#define CKM_CAST5_CBC                   (0x322UL)
#define CKM_CAST128_CBC                 (0x322UL)
#define CKM_CAST5_MAC                   (0x323UL)
#define CKM_CAST128_MAC                 (0x323UL)
#define CKM_CAST5_MAC_GENERAL           (0x324UL)
#define CKM_CAST128_MAC_GENERAL         (0x324UL)
#define CKM_CAST5_CBC_PAD               (0x325UL)
#define CKM_CAST128_CBC_PAD             (0x325UL)
#define CKM_RC5_KEY_GEN                 (0x330UL)
#define CKM_RC5_ECB                     (0x331UL)
#define CKM_RC5_CBC                     (0x332UL)
#define CKM_RC5_MAC                     (0x333UL)
#define CKM_RC5_MAC_GENERAL             (0x334UL)
#define CKM_RC5_CBC_PAD                 (0x335UL)
#define CKM_IDEA_KEY_GEN                (0x340UL)
#define CKM_IDEA_ECB                    (0x341UL)
#define CKM_IDEA_CBC                    (0x342UL)
#define CKM_IDEA_MAC                    (0x343UL)
#define CKM_IDEA_MAC_GENERAL            (0x344UL)
#define CKM_IDEA_CBC_PAD                (0x345UL)
#define CKM_GENERIC_SECRET_KEY_GEN      (0x350UL)
#define CKM_CONCATENATE_BASE_AND_KEY    (0x360UL)
#define CKM_CONCATENATE_BASE_AND_DATA   (0x362UL)
#define CKM_CONCATENATE_DATA_AND_BASE   (0x363UL)
#define CKM_XOR_BASE_AND_DATA           (0x364UL)
#define CKM_EXTRACT_KEY_FROM_KEY        (0x365UL)
#define CKM_SSL3_PRE_MASTER_KEY_GEN     (0x370UL)
#define CKM_SSL3_MASTER_KEY_DERIVE      (0x371UL)
#define CKM_SSL3_KEY_AND_MAC_DERIVE     (0x372UL)
#define CKM_SSL3_MASTER_KEY_DERIVE_DH   (0x373UL)
#define CKM_TLS_PRE_MASTER_KEY_GEN      (0x374UL)
#define CKM_TLS_MASTER_KEY_DERIVE       (0x375UL)
#define CKM_TLS_KEY_AND_MAC_DERIVE      (0x376UL)
#define CKM_TLS_MASTER_KEY_DERIVE_DH    (0x377UL)
#define CKM_SSL3_MD5_MAC                (0x380UL)
#define CKM_SSL3_SHA1_MAC               (0x381UL)
#define CKM_MD5_KEY_DERIVATION          (0x390UL)
#define CKM_MD2_KEY_DERIVATION          (0x391UL)
#define CKM_SHA1_KEY_DERIVATION         (0x392UL)
#define CKM_PBE_MD2_DES_CBC             (0x3a0UL)
#define CKM_PBE_MD5_DES_CBC             (0x3a1UL)
#define CKM_PBE_MD5_CAST_CBC            (0x3a2UL)
#define CKM_PBE_MD5_CAST3_CBC           (0x3a3UL)
#define CKM_PBE_MD5_CAST5_CBC           (0x3a4UL)
#define CKM_PBE_MD5_CAST128_CBC         (0x3a4UL)
#define CKM_PBE_SHA1_CAST5_CBC          (0x3a5UL)
#define CKM_PBE_SHA1_CAST128_CBC        (0x3a5UL)
#define CKM_PBE_SHA1_RC4_128            (0x3a6UL)
#define CKM_PBE_SHA1_RC4_40             (0x3a7UL)
#define CKM_PBE_SHA1_DES3_EDE_CBC       (0x3a8UL)
#define CKM_PBE_SHA1_DES2_EDE_CBC       (0x3a9UL)
#define CKM_PBE_SHA1_RC2_128_CBC        (0x3aaUL)
#define CKM_PBE_SHA1_RC2_40_CBC         (0x3abUL)
#define CKM_PKCS5_PBKD2                 (0x3b0UL)
#define CKM_PBA_SHA1_WITH_SHA1_HMAC     (0x3c0UL)
#define CKM_KEY_WRAP_LYNKS              (0x400UL)
#define CKM_KEY_WRAP_SET_OAEP           (0x401UL)
#define CKM_SKIPJACK_KEY_GEN            (0x1000UL)
#define CKM_SKIPJACK_ECB64              (0x1001UL)
#define CKM_SKIPJACK_CBC64              (0x1002UL)
#define CKM_SKIPJACK_OFB64              (0x1003UL)
#define CKM_SKIPJACK_CFB64              (0x1004UL)
#define CKM_SKIPJACK_CFB32              (0x1005UL)
#define CKM_SKIPJACK_CFB16              (0x1006UL)
#define CKM_SKIPJACK_CFB8               (0x1007UL)
#define CKM_SKIPJACK_WRAP               (0x1008UL)
#define CKM_SKIPJACK_PRIVATE_WRAP       (0x1009UL)
#define CKM_SKIPJACK_RELAYX             (0x100aUL)
#define CKM_KEA_KEY_PAIR_GEN            (0x1010UL)
#define CKM_KEA_KEY_DERIVE              (0x1011UL)
#define CKM_FORTEZZA_TIMESTAMP          (0x1020UL)
#define CKM_BATON_KEY_GEN               (0x1030UL)
#define CKM_BATON_ECB128                (0x1031UL)
#define CKM_BATON_ECB96                 (0x1032UL)
#define CKM_BATON_CBC128                (0x1033UL)
#define CKM_BATON_COUNTER               (0x1034UL)
#define CKM_BATON_SHUFFLE               (0x1035UL)
#define CKM_BATON_WRAP                  (0x1036UL)
#define CKM_ECDSA_KEY_PAIR_GEN          (0x1040UL)
#define CKM_EC_KEY_PAIR_GEN             (0x1040UL)
#define CKM_ECDSA                       (0x1041UL)
#define CKM_ECDSA_SHA1                  (0x1042UL)
#define CKM_ECDH1_DERIVE                (0x1050UL)
#define CKM_ECDH1_COFACTOR_DERIVE       (0x1051UL)
#define CKM_ECMQV_DERIVE                (0x1052UL)
#define CKM_JUNIPER_KEY_GEN             (0x1060UL)
#define CKM_JUNIPER_ECB128              (0x1061UL)
#define CKM_JUNIPER_CBC128              (0x1062UL)
#define CKM_JUNIPER_COUNTER             (0x1063UL)
#define CKM_JUNIPER_SHUFFLE             (0x1064UL)
#define CKM_JUNIPER_WRAP                (0x1065UL)
#define CKM_FASTHASH                    (0x1070UL)
#define CKM_AES_KEY_GEN                 (0x1080UL)
#define CKM_AES_ECB                     (0x1081UL)
#define CKM_AES_CBC                     (0x1082UL)
#define CKM_AES_MAC                     (0x1083UL)
#define CKM_AES_MAC_GENERAL             (0x1084UL)
#define CKM_AES_CBC_PAD                 (0x1085UL)
#define CKM_DSA_PARAMETER_GEN           (0x2000UL)
#define CKM_DH_PKCS_PARAMETER_GEN       (0x2001UL)
#define CKM_X9_42_DH_PARAMETER_GEN      (0x2002UL)
#define CKM_VENDOR_DEFINED              ((unsigned long) (1UL << 31))

/* C_WaitForSlotEvent */
#define CKF_DONT_BLOCK                  (1UL)
#define CKR_NO_EVENT                    (8UL)
#define CKR_CRYPTOKI_NOT_INITIALIZED    (0x190UL)

/* PKCS11 function declaration (copyed from true pkcs11.h */
typedef ck_rv_t(*ck_notify_t) (ck_session_handle_t session,
			       ck_notification_t event, void *application);

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#pragma pack(push, cryptoki, 1)

#ifdef CRYPTOKI_EXPORTS
#define CK_SPEC __declspec(dllexport)
#else
#define CK_SPEC __declspec(dllimport)
#endif

#else

#define CK_SPEC

#endif

struct ck_function_list;

#define _CK_DECLARE_FUNCTION(name, args)    \
typedef ck_rv_t (*CK_ ## name) args;        \
ck_rv_t CK_SPEC name args

_CK_DECLARE_FUNCTION(C_Initialize, (void *init_args));
_CK_DECLARE_FUNCTION(C_Finalize, (void *reserved));
_CK_DECLARE_FUNCTION(C_GetInfo, (struct ck_info * info));
_CK_DECLARE_FUNCTION(C_GetFunctionList,
		     (struct ck_function_list ** function_list));

_CK_DECLARE_FUNCTION(C_GetSlotList,
		     (unsigned char token_present, ck_slot_id_t * slot_list,
		      unsigned long *count));
_CK_DECLARE_FUNCTION(C_GetSlotInfo,
		     (ck_slot_id_t slot_id, struct ck_slot_info * info));
_CK_DECLARE_FUNCTION(C_GetTokenInfo,
		     (ck_slot_id_t slot_id, struct ck_token_info * info));
_CK_DECLARE_FUNCTION(C_WaitForSlotEvent,
		     (ck_flags_t flags, ck_slot_id_t * slot, void *reserved));
_CK_DECLARE_FUNCTION(C_GetMechanismList,
		     (ck_slot_id_t slot_id,
		      ck_mechanism_type_t * mechanism_list,
		      unsigned long *count));
_CK_DECLARE_FUNCTION(C_GetMechanismInfo,
		     (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		      struct ck_mechanism_info * info));
_CK_DECLARE_FUNCTION(C_InitToken,
		     (ck_slot_id_t slot_id, unsigned char *pin,
		      unsigned long pin_len, unsigned char *label));
_CK_DECLARE_FUNCTION(C_InitPIN,
		     (ck_session_handle_t session, unsigned char *pin,
		      unsigned long pin_len));
_CK_DECLARE_FUNCTION(C_SetPIN,
		     (ck_session_handle_t session, unsigned char *old_pin,
		      unsigned long old_len, unsigned char *new_pin,
		      unsigned long new_len));

_CK_DECLARE_FUNCTION(C_OpenSession,
		     (ck_slot_id_t slot_id, ck_flags_t flags,
		      void *application, ck_notify_t notify,
		      ck_session_handle_t * session));
_CK_DECLARE_FUNCTION(C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION(C_CloseAllSessions, (ck_slot_id_t slot_id));
_CK_DECLARE_FUNCTION(C_GetSessionInfo,
		     (ck_session_handle_t session,
		      struct ck_session_info * info));
_CK_DECLARE_FUNCTION(C_GetOperationState,
		     (ck_session_handle_t session,
		      unsigned char *operation_state,
		      unsigned long *operation_state_len));
_CK_DECLARE_FUNCTION(C_SetOperationState,
		     (ck_session_handle_t session,
		      unsigned char *operation_state,
		      unsigned long operation_state_len,
		      ck_object_handle_t encryption_key,
		      ck_object_handle_t authentiation_key));
_CK_DECLARE_FUNCTION(C_Login,
		     (ck_session_handle_t session, ck_user_type_t user_type,
		      unsigned char *pin, unsigned long pin_len));
_CK_DECLARE_FUNCTION(C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION(C_CreateObject,
		     (ck_session_handle_t session,
		      struct ck_attribute * templ,
		      unsigned long count, ck_object_handle_t * object));
_CK_DECLARE_FUNCTION(C_CopyObject,
		     (ck_session_handle_t session, ck_object_handle_t object,
		      struct ck_attribute * templ, unsigned long count,
		      ck_object_handle_t * new_object));
_CK_DECLARE_FUNCTION(C_DestroyObject,
		     (ck_session_handle_t session, ck_object_handle_t object));
_CK_DECLARE_FUNCTION(C_GetObjectSize,
		     (ck_session_handle_t session,
		      ck_object_handle_t object, unsigned long *size));
_CK_DECLARE_FUNCTION(C_GetAttributeValue,
		     (ck_session_handle_t session,
		      ck_object_handle_t object,
		      struct ck_attribute * templ, unsigned long count));
_CK_DECLARE_FUNCTION(C_SetAttributeValue,
		     (ck_session_handle_t session,
		      ck_object_handle_t object,
		      struct ck_attribute * templ, unsigned long count));
_CK_DECLARE_FUNCTION(C_FindObjectsInit,
		     (ck_session_handle_t session,
		      struct ck_attribute * templ, unsigned long count));
_CK_DECLARE_FUNCTION(C_FindObjects,
		     (ck_session_handle_t session,
		      ck_object_handle_t * object,
		      unsigned long max_object_count,
		      unsigned long *object_count));
_CK_DECLARE_FUNCTION(C_FindObjectsFinal, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION(C_EncryptInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_Encrypt,
		     (ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *encrypted_data,
		      unsigned long *encrypted_data_len));
_CK_DECLARE_FUNCTION(C_EncryptUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len,
		      unsigned char *encrypted_part,
		      unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION(C_EncryptFinal,
		     (ck_session_handle_t session,
		      unsigned char *last_encrypted_part,
		      unsigned long *last_encrypted_part_len));

_CK_DECLARE_FUNCTION(C_DecryptInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_Decrypt,
		     (ck_session_handle_t session,
		      unsigned char *encrypted_data,
		      unsigned long encrypted_data_len,
		      unsigned char *data, unsigned long *data_len));
_CK_DECLARE_FUNCTION(C_DecryptUpdate,
		     (ck_session_handle_t session,
		      unsigned char *encrypted_part,
		      unsigned long encrypted_part_len,
		      unsigned char *part, unsigned long *part_len));
_CK_DECLARE_FUNCTION(C_DecryptFinal,
		     (ck_session_handle_t session,
		      unsigned char *last_part, unsigned long *last_part_len));

_CK_DECLARE_FUNCTION(C_DigestInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism));
_CK_DECLARE_FUNCTION(C_Digest,
		     (ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *digest, unsigned long *digest_len));
_CK_DECLARE_FUNCTION(C_DigestUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION(C_DigestKey,
		     (ck_session_handle_t session, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_DigestFinal,
		     (ck_session_handle_t session,
		      unsigned char *digest, unsigned long *digest_len));

_CK_DECLARE_FUNCTION(C_SignInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_Sign,
		     (ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *signature, unsigned long *signature_len));
_CK_DECLARE_FUNCTION(C_SignUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION(C_SignFinal,
		     (ck_session_handle_t session,
		      unsigned char *signature, unsigned long *signature_len));
_CK_DECLARE_FUNCTION(C_SignRecoverInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_SignRecover,
		     (ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *signature, unsigned long *signature_len));

_CK_DECLARE_FUNCTION(C_VerifyInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_Verify,
		     (ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *signature, unsigned long signature_len));
_CK_DECLARE_FUNCTION(C_VerifyUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION(C_VerifyFinal,
		     (ck_session_handle_t session,
		      unsigned char *signature, unsigned long signature_len));
_CK_DECLARE_FUNCTION(C_VerifyRecoverInit,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism, ck_object_handle_t key));
_CK_DECLARE_FUNCTION(C_VerifyRecover,
		     (ck_session_handle_t session,
		      unsigned char *signature,
		      unsigned long signature_len,
		      unsigned char *data, unsigned long *data_len));

_CK_DECLARE_FUNCTION(C_DigestEncryptUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len,
		      unsigned char *encrypted_part,
		      unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION(C_DecryptDigestUpdate,
		     (ck_session_handle_t session,
		      unsigned char *encrypted_part,
		      unsigned long encrypted_part_len,
		      unsigned char *part, unsigned long *part_len));
_CK_DECLARE_FUNCTION(C_SignEncryptUpdate,
		     (ck_session_handle_t session,
		      unsigned char *part, unsigned long part_len,
		      unsigned char *encrypted_part,
		      unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION(C_DecryptVerifyUpdate,
		     (ck_session_handle_t session,
		      unsigned char *encrypted_part,
		      unsigned long encrypted_part_len,
		      unsigned char *part, unsigned long *part_len));

_CK_DECLARE_FUNCTION(C_GenerateKey,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism,
		      struct ck_attribute * templ,
		      unsigned long count, ck_object_handle_t * key));
_CK_DECLARE_FUNCTION(C_GenerateKeyPair,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism,
		      struct ck_attribute * public_key_template,
		      unsigned long public_key_attribute_count,
		      struct ck_attribute * private_key_template,
		      unsigned long private_key_attribute_count,
		      ck_object_handle_t * public_key,
		      ck_object_handle_t * private_key));
_CK_DECLARE_FUNCTION(C_WrapKey,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism,
		      ck_object_handle_t wrapping_key,
		      ck_object_handle_t key,
		      unsigned char *wrapped_key,
		      unsigned long *wrapped_key_len));
_CK_DECLARE_FUNCTION(C_UnwrapKey,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism,
		      ck_object_handle_t unwrapping_key,
		      unsigned char *wrapped_key,
		      unsigned long wrapped_key_len,
		      struct ck_attribute * templ,
		      unsigned long attribute_count, ck_object_handle_t * key));
_CK_DECLARE_FUNCTION(C_DeriveKey,
		     (ck_session_handle_t session,
		      struct ck_mechanism * mechanism,
		      ck_object_handle_t base_key,
		      struct ck_attribute * templ,
		      unsigned long attribute_count, ck_object_handle_t * key));

_CK_DECLARE_FUNCTION(C_SeedRandom,
		     (ck_session_handle_t session, unsigned char *seed,
		      unsigned long seed_len));
_CK_DECLARE_FUNCTION(C_GenerateRandom,
		     (ck_session_handle_t session,
		      unsigned char *random_data, unsigned long random_len));

_CK_DECLARE_FUNCTION(C_GetFunctionStatus, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION(C_CancelFunction, (ck_session_handle_t session));

struct ck_function_list {
  struct ck_version version;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_GetObjectSize C_GetObjectSize;
  CK_C_GetAttributeValue C_GetAttributeValue;
  CK_C_SetAttributeValue C_SetAttributeValue;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_DigestKey C_DigestKey;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_GenerateKey C_GenerateKey;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_WrapKey C_WrapKey;
  CK_C_UnwrapKey C_UnwrapKey;
  CK_C_DeriveKey C_DeriveKey;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

/* ----------- LINKED LIST ---------- */
/* Linked structure */
typedef struct p11_request_struct_ {
  /* Session handle */
  ck_session_handle_t session;
  /* Operation type (Sign, Encrypt, ...) */
  unsigned long operation_type;
  unsigned char *in;
  unsigned long in_len;
  unsigned char *out;
  unsigned long out_len;
  /* Pointer to the nex node */
  struct p11_request_struct_ *next;
} p11_request_struct;

/* Linked list global variable */
p11_request_struct *request_data;

/* Linked list operation discriminant */
enum op_types {
  SIGN_OP,
  ENCRYPT_OP,
  DECRYPT_OP,
  DIGEST_OP,
  ENCRYPT_UPDATE_OP,
  DECRYPT_UPDATE_OP,
  SIGN_FINAL_OP,
  ENCRYPT_FINAL_OP,
  DECRYPT_FINAL_OP,
  DIGEST_FINAL_OP,
  SIGN_RECOVER_OP,
  VERIFY_RECOVER_OP,
  DIGEST_ENCRYPT_UPDATE_OP,
  DECRYPT_DIGEST_UPDATE_OP,
  SIGN_ENCRYPT_UPDATE_OP,
  DECRYPT_VERIFY_UPDATE_OP,
  WRAPKEY_OP,
  GETOPERATION_STATE_OP
} op_type;

/* Size allocated to keep data in linked list */
/* TODO: try to do a better job than allocating a huge chunk */
#define MAX_BUFF_LEN                    2048

/* ----------- GLOBAL MUTEX ---------- */
/* Global mutex to avoid concurrency issues */
#ifndef CAMLRPC
pthread_mutex_t linkedlist_mutex;
#endif
pthread_mutex_t mutex;
/* TODO: cheap way to synchronize, might not work in all cases
  C_WaitForSlotEvent case
  0 -> No one is waiting
  1 -> C_WaitForSlotEvent is waiting
  2 -> C_Finalize was called while a waiting, used to signal
 */
volatile unsigned long is_Blocking;

/* ----------- COMPILER HELPER for passing LIBRARY NAME to LoadModule ---------- */
#ifndef LIBNAME
#error "NO LIBNAME PROVIDED: YOU MUST PROVIDE ONE!"
#endif

#define xstr(s) str(s)
#define str(s) #s

/* modwrap.c */
p11_request_struct *add_element_to_list(ck_session_handle_t session,
					unsigned long operation_type,
					unsigned char *in, unsigned long in_len,
					unsigned char *out,
					unsigned long out_len);
int remove_elements_from_filtering_list(ck_session_handle_t session,
					unsigned long operation_type,
					unsigned char *in,
					unsigned long in_len);
int remove_all_elements_from_filtering_list(void);
p11_request_struct *check_element_in_filtering_list(ck_session_handle_t
						    session,
						    unsigned long
						    operation_type,
						    unsigned char *in,
						    unsigned long in_len);
p11_request_struct *check_operation_active_in_filtering_list(ck_session_handle_t
							     session,
							     unsigned long
							     operation_type);
void custom_sanitize_ck_mechanism(struct ck_mechanism *mech);
value custom_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
					     camlidl_ctx _ctx);
value custom_pkcs11_c2ml_buffer_to_ck_attribute_array(struct ck_attribute
						      *array,
						      unsigned long
						      array_len,
						      camlidl_ctx _ctx);
void custom_ml2c_pkcs11_struct_ck_attribute(value _v1,
					    struct ck_attribute *_c2,
					    camlidl_ctx _ctx,
					    unsigned long ret);
int custom_pkcs11_ml2c_ck_attribute_array_to_buffer(value _v_data, struct ck_attribute
						    *array,
						    unsigned long *array_len,
						    camlidl_ctx _ctx,
						    unsigned long ret);
value custom_pkcs11_c2ml_buffer_to_char_array(unsigned char *array,
					      unsigned long array_len);
int custom_pkcs11_ml2c_char_array_to_buffer(value _v_data,
					    unsigned char *array,
					    unsigned long *array_len);

void init(void);
ck_rv_t init_ml(const char *);
ck_rv_t init_c(const char *);

void destroy(void);
void destroy_c(void);
void destroy_ml(void);

/* P11 OCAML RPC functions */
ck_rv_t myRPC_connect(void);
ck_rv_t myC_SetupArch(void);
ck_rv_t myC_Initialize(void *init_args);
ck_rv_t myC_Finalize(void *init_args);
ck_rv_t myC_GetSlotList(CK_BBOOL input0, ck_slot_id_t * output2,
			unsigned long *output3);
ck_rv_t myC_GetInfo(struct ck_info *output0);
ck_rv_t myC_WaitForSlotEvent(ck_flags_t input0, ck_slot_id_t * output1,
			     void *reserved);
ck_rv_t myC_GetSlotInfo(ck_slot_id_t input0, struct ck_slot_info *output1);
ck_rv_t myC_GetTokenInfo(ck_slot_id_t input0, struct ck_token_info *output1);
ck_rv_t myC_InitToken(ck_slot_id_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *input2);
ck_rv_t myC_OpenSession(ck_slot_id_t input0, ck_flags_t input1,
			void *application, ck_notify_t notify,
			ck_session_handle_t * output2);
ck_rv_t myC_CloseSession(ck_session_handle_t input0);
ck_rv_t myC_CloseAllSessions(ck_slot_id_t input0);
ck_rv_t myC_GetSessionInfo(ck_session_handle_t input0,
			   struct ck_session_info *output1);
ck_rv_t myC_Login(ck_session_handle_t input0, ck_user_type_t input1,
		  unsigned char *input2, unsigned long input2_len);
ck_rv_t myC_Logout(ck_session_handle_t input0);
ck_rv_t myC_GetMechanismList(ck_slot_id_t input0,
			     ck_mechanism_type_t * output2,
			     unsigned long *output3);
ck_rv_t myC_GetMechanismInfo(ck_slot_id_t input0, ck_mechanism_type_t input1,
			     struct ck_mechanism_info *output2);
ck_rv_t myC_InitPIN(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len);
ck_rv_t myC_SetPIN(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len, unsigned char *input2,
		   unsigned long input2_len);
ck_rv_t myC_SeedRandom(ck_session_handle_t input0, unsigned char *input1,
		       unsigned long input1_len);
ck_rv_t myC_GenerateRandom(ck_session_handle_t input0,
			   unsigned char *output2, unsigned long output2_len);
ck_rv_t myC_GetOperationState(ck_session_handle_t input0,
			      unsigned char *output1,
			      unsigned long *output1_len);
ck_rv_t myC_SetOperationState(ck_session_handle_t input0,
			      unsigned char *input1,
			      unsigned long input1_len,
			      ck_object_handle_t input2,
			      ck_object_handle_t input3);
ck_rv_t myC_FindObjectsInit(ck_session_handle_t input0,
			    CK_ATTRIBUTE * input1, unsigned long count);
ck_rv_t myC_FindObjects(ck_session_handle_t input0,
			ck_object_handle_t * output2, unsigned long input1,
			unsigned long *output3);
ck_rv_t myC_FindObjectsFinal(ck_session_handle_t input0);
ck_rv_t myC_GenerateKey(ck_session_handle_t input0,
			struct ck_mechanism *input1, CK_ATTRIBUTE * input2,
			unsigned long count, ck_object_handle_t * output3);
ck_rv_t myC_GenerateKeyPair(ck_session_handle_t input0,
			    struct ck_mechanism *input1,
			    CK_ATTRIBUTE * input2, unsigned long count,
			    CK_ATTRIBUTE * input3, unsigned long count2,
			    ck_object_handle_t * output4,
			    ck_object_handle_t * output5);
ck_rv_t myC_CreateObject(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
			 unsigned long count, ck_object_handle_t * output2);
ck_rv_t myC_CopyObject(ck_session_handle_t input0, ck_object_handle_t input1,
		       CK_ATTRIBUTE * input2, unsigned long count,
		       ck_object_handle_t * output3);
ck_rv_t myC_DestroyObject(ck_session_handle_t input0,
			  ck_object_handle_t input1);
ck_rv_t myC_GetAttributeValue(ck_session_handle_t input0,
			      ck_object_handle_t input1,
			      struct ck_attribute *input2,
			      unsigned long input3);
ck_rv_t myC_SetAttributeValue(ck_session_handle_t input0,
			      ck_object_handle_t input1,
			      CK_ATTRIBUTE * input2, unsigned long count);
ck_rv_t myC_GetObjectSize(ck_session_handle_t input0,
			  ck_object_handle_t input1, unsigned long *output2);
ck_rv_t myC_WrapKey(ck_session_handle_t input0, struct ck_mechanism *input1,
		    ck_object_handle_t input2, ck_object_handle_t input3,
		    unsigned char *output4, unsigned long *output4_len);
ck_rv_t myC_UnwrapKey(ck_session_handle_t input0,
		      struct ck_mechanism *input1, ck_object_handle_t input2,
		      unsigned char *input3, unsigned long input3_len,
		      CK_ATTRIBUTE * input4, unsigned long count,
		      ck_object_handle_t * output5);
ck_rv_t myC_DeriveKey(ck_session_handle_t input0,
		      struct ck_mechanism *input1, ck_object_handle_t input2,
		      CK_ATTRIBUTE * input3, unsigned long count,
		      ck_object_handle_t * output4);
ck_rv_t myC_DigestInit(ck_session_handle_t input0, struct ck_mechanism *input1);
ck_rv_t myC_Digest(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len, unsigned char *output2,
		   unsigned long *output2_len);
ck_rv_t myC_DigestUpdate(ck_session_handle_t input0, unsigned char *input1,
			 unsigned long input1_len);
ck_rv_t myC_DigestFinal(ck_session_handle_t input0, unsigned char *output1,
			unsigned long *output1_len);
ck_rv_t myC_DigestKey(ck_session_handle_t input0, ck_object_handle_t input1);
ck_rv_t myC_SignInit(ck_session_handle_t input0, struct ck_mechanism *input1,
		     ck_object_handle_t input2);
ck_rv_t myC_Sign(ck_session_handle_t input0, unsigned char *input1,
		 unsigned long input1_len, unsigned char *output2,
		 unsigned long *output2_len);
ck_rv_t myC_SignUpdate(ck_session_handle_t input0, unsigned char *input1,
		       unsigned long input1_len);
ck_rv_t myC_SignFinal(ck_session_handle_t input0, unsigned char *output1,
		      unsigned long *output1_len);
ck_rv_t myC_SignRecoverInit(ck_session_handle_t input0,
			    struct ck_mechanism *input1,
			    ck_object_handle_t input2);
ck_rv_t myC_SignRecover(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *output2,
			unsigned long *output2_len);
ck_rv_t myC_VerifyRecoverInit(ck_session_handle_t input0,
			      struct ck_mechanism *input1,
			      ck_object_handle_t input2);
ck_rv_t myC_VerifyInit(ck_session_handle_t input0,
		       struct ck_mechanism *input1, ck_object_handle_t input2);
ck_rv_t myC_Verify(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len, unsigned char *input2,
		   unsigned long input2_len);
ck_rv_t myC_VerifyUpdate(ck_session_handle_t input0, unsigned char *input1,
			 unsigned long input1_len);
ck_rv_t myC_VerifyFinal(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len);
ck_rv_t myC_VerifyRecover(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len);
ck_rv_t myC_EncryptInit(ck_session_handle_t input0,
			struct ck_mechanism *input1, ck_object_handle_t input2);
ck_rv_t myC_Encrypt(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len);
ck_rv_t myC_EncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len);
ck_rv_t myC_EncryptFinal(ck_session_handle_t input0, unsigned char *output1,
			 unsigned long *output1_len);
ck_rv_t myC_DigestEncryptUpdate(ck_session_handle_t input0,
				unsigned char *input1,
				unsigned long input1_len,
				unsigned char *output2,
				unsigned long *output2_len);
ck_rv_t myC_SignEncryptUpdate(ck_session_handle_t input0,
			      unsigned char *input1,
			      unsigned long input1_len,
			      unsigned char *output2,
			      unsigned long *output2_len);
ck_rv_t myC_DecryptInit(ck_session_handle_t input0,
			struct ck_mechanism *input1, ck_object_handle_t input2);
ck_rv_t myC_Decrypt(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len);
ck_rv_t myC_DecryptUpdate(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len);
ck_rv_t myC_DecryptFinal(ck_session_handle_t input0, unsigned char *output1,
			 unsigned long *output1_len);
ck_rv_t myC_DecryptDigestUpdate(ck_session_handle_t input0,
				unsigned char *input1,
				unsigned long input1_len,
				unsigned char *output2,
				unsigned long *output2_len);
ck_rv_t myC_DecryptVerifyUpdate(ck_session_handle_t input0,
				unsigned char *input1,
				unsigned long input1_len,
				unsigned char *output2,
				unsigned long *output2_len);
ck_rv_t myC_GetFunctionStatus(ck_session_handle_t input0);
ck_rv_t myC_CancelFunction(ck_session_handle_t input0);
ck_rv_t myC_LoadModule(const char *libname);

/* P11 C RPC functions */
#ifdef CRPC
void deserialize_rpc_ck_version(struct ck_version *out,
				struct rpc_ck_version *in);
void deserialize_rpc_ck_info(struct ck_info *out, struct rpc_ck_info *in);
void deserialize_rpc_ck_slot_info(struct ck_slot_info *out,
				  struct rpc_ck_slot_info *in);
void deserialize_rpc_ck_token_info(struct ck_token_info *out,
				   struct rpc_ck_token_info *in);
void deserialize_rpc_ck_mechanism(struct ck_mechanism *out,
				  struct rpc_ck_mechanism *in);
void deserialize_rpc_ck_session_info(struct ck_session_info *out,
				     struct rpc_ck_session_info *in);
void deserialize_rpc_ck_mechanism_info(struct ck_mechanism_info *out,
				       struct rpc_ck_mechanism_info *in);
void deserialize_rpc_ck_attribute(struct ck_attribute *out,
				  struct rpc_ck_attribute *in, ck_rv_t ret);
void deserialize_rpc_ck_attribute_array(struct ck_attribute *out,
					rpc_ck_attribute_array * in,
					ck_rv_t ret);
void deserialize_rpc_ck_date(struct ck_date *out, struct rpc_ck_date *in);
void serialize_rpc_ck_attribute(struct ck_attribute *in,
				struct rpc_ck_attribute *out);
void free_rpc_ck_attribute(rpc_ck_attribute * in);
void serialize_rpc_ck_attribute_array(struct ck_attribute *in,
				      unsigned long in_len,
				      rpc_ck_attribute_array * out);
void free_rpc_ck_attribute_array(rpc_ck_attribute_array * in);
void serialize_rpc_ck_mechanism(struct ck_mechanism *in,
				struct rpc_ck_mechanism *out);
void free_rpc_ck_mechanism(rpc_ck_mechanism * in);
void parse_socket_path(const char *socket_path, struct sockaddr_in *serv_addr);
#endif

ck_rv_t myC_SetupArch_C(void);
ck_rv_t myC_Initialize_C(void *init_args);
ck_rv_t myC_Finalize_C(void *init_args);
ck_rv_t myC_GetSlotList_C(CK_BBOOL input0, ck_slot_id_t * output2,
			  unsigned long *output3);
ck_rv_t myC_GetInfo_C(struct ck_info *output0);
ck_rv_t myC_WaitForSlotEvent_C(ck_flags_t input0, ck_slot_id_t * output1,
			       void *reserved);
ck_rv_t myC_GetSlotInfo_C(ck_slot_id_t input0, struct ck_slot_info *output1);
ck_rv_t myC_GetTokenInfo_C(ck_slot_id_t input0, struct ck_token_info *output1);
ck_rv_t myC_InitToken_C(ck_slot_id_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *input2);
ck_rv_t myC_OpenSession_C(ck_slot_id_t input0, ck_flags_t input1,
			  void *application, ck_notify_t notify,
			  ck_session_handle_t * output2);
ck_rv_t myC_CloseSession_C(ck_session_handle_t input0);
ck_rv_t myC_CloseAllSessions_C(ck_slot_id_t input0);
ck_rv_t myC_GetSessionInfo_C(ck_session_handle_t input0,
			     struct ck_session_info *output1);
ck_rv_t myC_Login_C(ck_session_handle_t input0, ck_user_type_t input1,
		    unsigned char *input2, unsigned long input2_len);
ck_rv_t myC_Logout_C(ck_session_handle_t input0);
ck_rv_t myC_GetMechanismList_C(ck_slot_id_t input0,
			       ck_mechanism_type_t * output2,
			       unsigned long *output3);
ck_rv_t myC_GetMechanismInfo_C(ck_slot_id_t input0,
			       ck_mechanism_type_t input1,
			       struct ck_mechanism_info *output2);
ck_rv_t myC_InitPIN_C(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len);
ck_rv_t myC_SetPIN_C(ck_session_handle_t input0, unsigned char *input1,
		     unsigned long input1_len, unsigned char *input2,
		     unsigned long input2_len);
ck_rv_t myC_SeedRandom_C(ck_session_handle_t input0, unsigned char *input1,
			 unsigned long input1_len);
ck_rv_t myC_GenerateRandom_C(ck_session_handle_t input0,
			     unsigned char *output2, unsigned long output2_len);
ck_rv_t myC_GetOperationState_C(ck_session_handle_t input0,
				unsigned char *output1,
				unsigned long *output1_len);
ck_rv_t myC_SetOperationState_C(ck_session_handle_t input0,
				unsigned char *input1,
				unsigned long input1_len,
				ck_object_handle_t input2,
				ck_object_handle_t input3);
ck_rv_t myC_FindObjectsInit_C(ck_session_handle_t input0,
			      CK_ATTRIBUTE * input1, unsigned long count);
ck_rv_t myC_FindObjects_C(ck_session_handle_t input0,
			  ck_object_handle_t * output2, unsigned long input1,
			  unsigned long *output3);
ck_rv_t myC_FindObjectsFinal_C(ck_session_handle_t input0);
ck_rv_t myC_GenerateKey_C(ck_session_handle_t input0,
			  struct ck_mechanism *input1, CK_ATTRIBUTE * input2,
			  unsigned long count, ck_object_handle_t * output3);
ck_rv_t myC_GenerateKeyPair_C(ck_session_handle_t input0,
			      struct ck_mechanism *input1,
			      CK_ATTRIBUTE * input2, unsigned long count,
			      CK_ATTRIBUTE * input3, unsigned long count2,
			      ck_object_handle_t * output4,
			      ck_object_handle_t * output5);
ck_rv_t myC_CreateObject_C(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
			   unsigned long count, ck_object_handle_t * output2);
ck_rv_t myC_CopyObject_C(ck_session_handle_t input0,
			 ck_object_handle_t input1, CK_ATTRIBUTE * input2,
			 unsigned long count, ck_object_handle_t * output3);
ck_rv_t myC_DestroyObject_C(ck_session_handle_t input0,
			    ck_object_handle_t input1);
ck_rv_t myC_GetAttributeValue_C(ck_session_handle_t input0,
				ck_object_handle_t input1,
				struct ck_attribute *input2,
				unsigned long input3);
ck_rv_t myC_SetAttributeValue_C(ck_session_handle_t input0,
				ck_object_handle_t input1,
				CK_ATTRIBUTE * input2, unsigned long count);
ck_rv_t myC_GetObjectSize_C(ck_session_handle_t input0,
			    ck_object_handle_t input1, unsigned long *output2);
ck_rv_t myC_WrapKey_C(ck_session_handle_t input0,
		      struct ck_mechanism *input1, ck_object_handle_t input2,
		      ck_object_handle_t input3, unsigned char *output4,
		      unsigned long *output4_len);
ck_rv_t myC_UnwrapKey_C(ck_session_handle_t input0,
			struct ck_mechanism *input1,
			ck_object_handle_t input2, unsigned char *input3,
			unsigned long input3_len, CK_ATTRIBUTE * input4,
			unsigned long count, ck_object_handle_t * output5);
ck_rv_t myC_DeriveKey_C(ck_session_handle_t input0,
			struct ck_mechanism *input1,
			ck_object_handle_t input2, CK_ATTRIBUTE * input3,
			unsigned long count, ck_object_handle_t * output4);
ck_rv_t myC_DigestInit_C(ck_session_handle_t input0,
			 struct ck_mechanism *input1);
ck_rv_t myC_Digest_C(ck_session_handle_t input0, unsigned char *input1,
		     unsigned long input1_len, unsigned char *output2,
		     unsigned long *output2_len);
ck_rv_t myC_DigestUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			   unsigned long input1_len);
ck_rv_t myC_DigestFinal_C(ck_session_handle_t input0, unsigned char *output1,
			  unsigned long *output1_len);
ck_rv_t myC_DigestKey_C(ck_session_handle_t input0, ck_object_handle_t input1);
ck_rv_t myC_SignInit_C(ck_session_handle_t input0,
		       struct ck_mechanism *input1, ck_object_handle_t input2);
ck_rv_t myC_Sign_C(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len, unsigned char *output2,
		   unsigned long *output2_len);
ck_rv_t myC_SignUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			 unsigned long input1_len);
ck_rv_t myC_SignFinal_C(ck_session_handle_t input0, unsigned char *output1,
			unsigned long *output1_len);
ck_rv_t myC_SignRecoverInit_C(ck_session_handle_t input0,
			      struct ck_mechanism *input1,
			      ck_object_handle_t input2);
ck_rv_t myC_SignRecover_C(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len);
ck_rv_t myC_VerifyRecoverInit_C(ck_session_handle_t input0,
				struct ck_mechanism *input1,
				ck_object_handle_t input2);
ck_rv_t myC_VerifyInit_C(ck_session_handle_t input0,
			 struct ck_mechanism *input1,
			 ck_object_handle_t input2);
ck_rv_t myC_Verify_C(ck_session_handle_t input0, unsigned char *input1,
		     unsigned long input1_len, unsigned char *input2,
		     unsigned long input2_len);
ck_rv_t myC_VerifyUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			   unsigned long input1_len);
ck_rv_t myC_VerifyFinal_C(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len);
ck_rv_t myC_VerifyRecover_C(ck_session_handle_t input0,
			    unsigned char *input1, unsigned long input1_len,
			    unsigned char *output2, unsigned long *output2_len);
ck_rv_t myC_EncryptInit_C(ck_session_handle_t input0,
			  struct ck_mechanism *input1,
			  ck_object_handle_t input2);
ck_rv_t myC_Encrypt_C(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len);
ck_rv_t myC_EncryptUpdate_C(ck_session_handle_t input0,
			    unsigned char *input1, unsigned long input1_len,
			    unsigned char *output2, unsigned long *output2_len);
ck_rv_t myC_EncryptFinal_C(ck_session_handle_t input0,
			   unsigned char *output1, unsigned long *output1_len);
ck_rv_t myC_DigestEncryptUpdate_C(ck_session_handle_t input0,
				  unsigned char *input1,
				  unsigned long input1_len,
				  unsigned char *output2,
				  unsigned long *output2_len);
ck_rv_t myC_SignEncryptUpdate_C(ck_session_handle_t input0,
				unsigned char *input1,
				unsigned long input1_len,
				unsigned char *output2,
				unsigned long *output2_len);
ck_rv_t myC_DecryptInit_C(ck_session_handle_t input0,
			  struct ck_mechanism *input1,
			  ck_object_handle_t input2);
ck_rv_t myC_Decrypt_C(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len);
ck_rv_t myC_DecryptUpdate_C(ck_session_handle_t input0,
			    unsigned char *input1, unsigned long input1_len,
			    unsigned char *output2, unsigned long *output2_len);
ck_rv_t myC_DecryptFinal_C(ck_session_handle_t input0,
			   unsigned char *output1, unsigned long *output1_len);
ck_rv_t myC_DecryptDigestUpdate_C(ck_session_handle_t input0,
				  unsigned char *input1,
				  unsigned long input1_len,
				  unsigned char *output2,
				  unsigned long *output2_len);
ck_rv_t myC_DecryptVerifyUpdate_C(ck_session_handle_t input0,
				  unsigned char *input1,
				  unsigned long input1_len,
				  unsigned char *output2,
				  unsigned long *output2_len);
ck_rv_t myC_GetFunctionStatus_C(ck_session_handle_t input0);
ck_rv_t myC_CancelFunction_C(ck_session_handle_t input0);
ck_rv_t myC_LoadModule_C(const char *libname);
