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
    File:    src/bindings-pkcs11/helpers_pkcs11.h

-------------------------- MIT License HEADER ----------------------------------*/
/* Only include original_pkcs11.h for bindings to allow re-use of debug functions
 * across all the project
 */
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if !(defined(CRPC) || defined (CAMLRPC))
#include "original_pkcs11.h"

unsigned long get_local_arch(void);

void int_to_ulong_char_array(unsigned long, unsigned char *);

void char_array_to_ulong(unsigned char*, size_t, unsigned long*);

void hton_char_array(unsigned char*, unsigned long, unsigned char*, unsigned long*);

void ntoh_char_array(unsigned char*, unsigned long, unsigned char*, unsigned long*);

void print_pkcs11_error(CK_RV);

void print_pkcs11_error(CK_RV rv)
{
  switch (rv) {
  case CKR_OK:
    printf("CKR_OK    ");
    break;
  case CKR_CANCEL:
    printf("CKR_CANCEL   ");
    break;
  case CKR_HOST_MEMORY:
    printf("CKR_HOST_MEMORY   ");
    break;
  case CKR_SLOT_ID_INVALID:
    printf("CKR_SLOT_ID_INVALID  ");
    break;
  case CKR_GENERAL_ERROR:
    printf("CKR_GENERAL_ERROR  ");
    break;
  case CKR_FUNCTION_FAILED:
    printf("CKR_FUNCTION_FAILED  ");
    break;
  case CKR_ARGUMENTS_BAD:
    printf("CKR_ARGUMENTS_BAD  ");
    break;
  case CKR_NO_EVENT:
    printf("CKR_NO_EVENT   ");
    break;
  case CKR_NEED_TO_CREATE_THREADS:
    printf("CKR_NEED_TO_CREATE_THREADS ");
    break;
  case CKR_CANT_LOCK:
    printf("CKR_CANT_LOCK   ");
    break;
  case CKR_ATTRIBUTE_READ_ONLY:
    printf("CKR_ATTRIBUTE_READ_ONLY  ");
    break;
  case CKR_ATTRIBUTE_SENSITIVE:
    printf("CKR_ATTRIBUTE_SENSITIVE  ");
    break;
  case CKR_ATTRIBUTE_TYPE_INVALID:
    printf("CKR_ATTRIBUTE_TYPE_INVALID ");
    break;
  case CKR_ATTRIBUTE_VALUE_INVALID:
    printf("CKR_ATTRIBUTE_VALUE_INVALID ");
    break;
  case CKR_DATA_INVALID:
    printf("CKR_DATA_INVALID  ");
    break;
  case CKR_DATA_LEN_RANGE:
    printf("CKR_DATA_LEN_RANGE  ");
    break;
  case CKR_DEVICE_ERROR:
    printf("CKR_DEVICE_ERROR  ");
    break;
  case CKR_DEVICE_MEMORY:
    printf("CKR_DEVICE_MEMORY  ");
    break;
  case CKR_DEVICE_REMOVED:
    printf("CKR_DEVICE_REMOVED  ");
    break;
  case CKR_ENCRYPTED_DATA_INVALID:
    printf("CKR_ENCRYPTED_DATA_INVALID ");
    break;
  case CKR_ENCRYPTED_DATA_LEN_RANGE:
    printf("CKR_ENCRYPTED_DATA_LEN_RANGE ");
    break;
  case CKR_FUNCTION_CANCELED:
    printf("CKR_FUNCTION_CANCELED  ");
    break;
  case CKR_FUNCTION_NOT_PARALLEL:
    printf("CKR_FUNCTION_NOT_PARALLEL ");
    break;
  case CKR_FUNCTION_NOT_SUPPORTED:
    printf("CKR_FUNCTION_NOT_SUPPORTED ");
    break;
  case CKR_KEY_HANDLE_INVALID:
    printf("CKR_KEY_HANDLE_INVALID  ");
    break;
  case CKR_KEY_SIZE_RANGE:
    printf("CKR_KEY_SIZE_RANGE  ");
    break;
  case CKR_KEY_TYPE_INCONSISTENT:
    printf("CKR_KEY_TYPE_INCONSISTENT ");
    break;
  case CKR_KEY_NOT_NEEDED:
    printf("CKR_KEY_NOT_NEEDED  ");
    break;
  case CKR_KEY_CHANGED:
    printf("CKR_KEY_CHANGED   ");
    break;
  case CKR_KEY_NEEDED:
    printf("CKR_KEY_NEEDED   ");
    break;
  case CKR_KEY_INDIGESTIBLE:
    printf("CKR_KEY_INDIGESTIBLE  ");
    break;
  case CKR_KEY_FUNCTION_NOT_PERMITTED:
    printf("CKR_KEY_FUNCTION_NOT_PERMITTED ");
    break;
  case CKR_KEY_NOT_WRAPPABLE:
    printf("CKR_KEY_NOT_WRAPPABLE  ");
    break;
  case CKR_KEY_UNEXTRACTABLE:
    printf("CKR_KEY_UNEXTRACTABLE  ");
    break;
  case CKR_MECHANISM_INVALID:
    printf("CKR_MECHANISM_INVALID  ");
    break;
  case CKR_MECHANISM_PARAM_INVALID:
    printf("CKR_MECHANISM_PARAM_INVALID ");
    break;
  case CKR_OBJECT_HANDLE_INVALID:
    printf("CKR_OBJECT_HANDLE_INVALID ");
    break;
  case CKR_OPERATION_ACTIVE:
    printf("CKR_OPERATION_ACTIVE  ");
    break;
  case CKR_OPERATION_NOT_INITIALIZED:
    printf("CKR_OPERATION_NOT_INITIALIZED ");
    break;
  case CKR_PIN_INCORRECT:
    printf("CKR_PIN_INCORRECT  ");
    break;
  case CKR_PIN_INVALID:
    printf("CKR_PIN_INVALID   ");
    break;
  case CKR_PIN_LEN_RANGE:
    printf("CKR_PIN_LEN_RANGE  ");
    break;
  case CKR_PIN_EXPIRED:
    printf("CKR_PIN_EXPIRED   ");
    break;
  case CKR_PIN_LOCKED:
    printf("CKR_PIN_LOCKED   ");
    break;
  case CKR_SESSION_CLOSED:
    printf("CKR_SESSION_CLOSED  ");
    break;
  case CKR_SESSION_COUNT:
    printf("CKR_SESSION_COUNT  ");
    break;
  case CKR_SESSION_HANDLE_INVALID:
    printf("CKR_SESSION_HANDLE_INVALID ");
    break;
  case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
    printf("CKR_SESSION_PARALLEL_NOT_SUPPORTED");
    break;
  case CKR_SESSION_READ_ONLY:
    printf("CKR_SESSION_READ_ONLY  ");
    break;
  case CKR_SESSION_EXISTS:
    printf("CKR_SESSION_EXISTS  ");
    break;
  case CKR_SESSION_READ_ONLY_EXISTS:
    printf("CKR_SESSION_READ_ONLY_EXISTS ");
    break;
  case CKR_SESSION_READ_WRITE_SO_EXISTS:
    printf("CKR_SESSION_READ_WRITE_SO_EXISTS");
    break;
  case CKR_SIGNATURE_INVALID:
    printf("CKR_SIGNATURE_INVALID  ");
    break;
  case CKR_SIGNATURE_LEN_RANGE:
    printf("CKR_SIGNATURE_LEN_RANGE  ");
    break;
  case CKR_TEMPLATE_INCOMPLETE:
    printf("CKR_TEMPLATE_INCOMPLETE  ");
    break;
  case CKR_TEMPLATE_INCONSISTENT:
    printf("CKR_TEMPLATE_INCONSISTENT ");
    break;
  case CKR_TOKEN_NOT_PRESENT:
    printf("CKR_TOKEN_NOT_PRESENT  ");
    break;
  case CKR_TOKEN_NOT_RECOGNIZED:
    printf("CKR_TOKEN_NOT_RECOGNIZED ");
    break;
  case CKR_TOKEN_WRITE_PROTECTED:
    printf("CKR_TOKEN_WRITE_PROTECTED ");
    break;
  case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
    printf("CKR_UNWRAPPING_KEY_HANDLE_INVALID");
    break;
  case CKR_UNWRAPPING_KEY_SIZE_RANGE:
    printf("CKR_UNWRAPPING_KEY_SIZE_RANGE ");
    break;
  case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
    printf("CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
    break;
  case CKR_USER_ALREADY_LOGGED_IN:
    printf("CKR_USER_ALREADY_LOGGED_IN ");
    break;
  case CKR_USER_NOT_LOGGED_IN:
    printf("CKR_USER_NOT_LOGGED_IN  ");
    break;
  case CKR_USER_PIN_NOT_INITIALIZED:
    printf("CKR_USER_PIN_NOT_INITIALIZED ");
    break;
  case CKR_USER_TYPE_INVALID:
    printf("CKR_USER_TYPE_INVALID  ");
    break;
  case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
    printf("CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
    break;
  case CKR_USER_TOO_MANY_TYPES:
    printf("CKR_USER_TOO_MANY_TYPES  ");
    break;
  case CKR_WRAPPED_KEY_INVALID:
    printf("CKR_WRAPPED_KEY_INVALID  ");
    break;
  case CKR_WRAPPED_KEY_LEN_RANGE:
    printf("CKR_WRAPPED_KEY_LEN_RANGE ");
    break;
  case CKR_WRAPPING_KEY_HANDLE_INVALID:
    printf("CKR_WRAPPING_KEY_HANDLE_INVALID ");
    break;
  case CKR_WRAPPING_KEY_SIZE_RANGE:
    printf("CKR_WRAPPING_KEY_SIZE_RANGE ");
    break;
  case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
    printf("CKR_WRAPPING_KEY_TYPE_INCONSISTENT");
    break;
  case CKR_RANDOM_SEED_NOT_SUPPORTED:
    printf("CKR_RANDOM_SEED_NOT_SUPPORTED ");
    break;
  case CKR_RANDOM_NO_RNG:
    printf("CKR_RANDOM_NO_RNG  ");
    break;
  case CKR_DOMAIN_PARAMS_INVALID:
    printf("CKR_DOMAIN_PARAMS_INVALID ");
    break;
  case CKR_BUFFER_TOO_SMALL:
    printf("CKR_BUFFER_TOO_SMALL  ");
    break;
  case CKR_SAVED_STATE_INVALID:
    printf("CKR_SAVED_STATE_INVALID  ");
    break;
  case CKR_INFORMATION_SENSITIVE:
    printf("CKR_INFORMATION_SENSITIVE ");
    break;
  case CKR_STATE_UNSAVEABLE:
    printf("CKR_STATE_UNSAVEABLE  ");
    break;
  case CKR_CRYPTOKI_NOT_INITIALIZED:
    printf("CKR_CRYPTOKI_NOT_INITIALIZED ");
    break;
  case CKR_CRYPTOKI_ALREADY_INITIALIZED:
    printf("CKR_CRYPTOKI_ALREADY_INITIALIZED");
    break;
  case CKR_MUTEX_BAD:
    printf("CKR_MUTEX_BAD   ");
    break;
  case CKR_MUTEX_NOT_LOCKED:
    printf("CKR_MUTEX_NOT_LOCKED  ");
    break;
  case CKR_FUNCTION_REJECTED:
    printf("CKR_FUNCTION_REJECTED  ");
    break;
  case CKR_VENDOR_DEFINED:
    printf("CKR_VENDOR_DEFINED  ");
    break;
  }
}

#define CHECK_MODULE_FUNCTION_INITIALIZE(pointer) do {\
	if(pkcs11 == NULL){\
		fprintf(stderr, "PKCS11 module not loaded!\n");\
		return CKR_GENERAL_ERROR;\
	}\
	if(pkcs11->pointer == NULL){\
		fprintf(stderr, "PKCS11 function "#pointer" not supported\n");\
		return CKR_FUNCTION_NOT_SUPPORTED;\
	}\
} while(0);

#define CHECK_MODULE_FUNCTION(pointer) do {\
	if(pkcs11 == NULL){\
		fprintf(stderr, "PKCS11 module not loaded!\n");\
		return CKR_CRYPTOKI_NOT_INITIALIZED;\
	}\
	if(pkcs11->pointer == NULL){\
		fprintf(stderr, "PKCS11 function "#pointer" not supported\n");\
		return CKR_FUNCTION_NOT_SUPPORTED;\
	}\
} while(0);

#endif				/* end of !(CRPC || CAMLRPC) */

/* ISO C compliance: Ugly but necessary since variadic macros */
/* have been introduced in ISO C 99                           */
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#endif

/* The ##__VA_ARGS__ has been introduced with C++, so we have to */
/* use tricks to avoid it and remain ISO C compiant              */
#ifdef DEBUG
#ifdef WIN32 /* WIN32 __VA_ARGS__ support is crap, this debug is disabled */
#define _DEBUG_CALL(name, string, ...) do {\
} while(0);
#define DEBUG_CALL(...) _DEBUG_CALL(__VA_ARGS__, "")
#else
#define __DEBUG_CALL(name, string, ...) do {\
	printf(#name string, __VA_ARGS__);\
} while(0);
#define _DEBUG_CALL(name, string, ...) __DEBUG_CALL(name, string "%s",  __VA_ARGS__)
#define DEBUG_CALL(...) _DEBUG_CALL(__VA_ARGS__, "")
#endif
#else
#define _DEBUG_CALL(name, string, ...) do {\
} while(0);
#define DEBUG_CALL(...) _DEBUG_CALL(__VA_ARGS__, "")
#endif

#ifdef DEBUG
#define __DEBUG_RET(name, rv, string, ...) do {\
	if(rv == CKR_OK){\
		printf(#name": Succeed ");\
		printf(string, __VA_ARGS__);\
	}\
	else{\
		printf(#name": Error ");\
		print_pkcs11_error(rv);\
		printf(string, __VA_ARGS__);\
	}\
} while(0);
#define _DEBUG_RET(name, rv, string, ...)  __DEBUG_RET(name, rv, string "%s", __VA_ARGS__)
#define DEBUG_RET(...) _DEBUG_RET(__VA_ARGS__, "")
#else
#define _DEBUG_RET(name, rv, string, ...) do {\
} while(0);
#define DEBUG_RET(...) _DEBUG_RET(__VA_ARGS__, "")
#endif

#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
