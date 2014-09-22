(************************* CeCILL-B HEADER ************************************
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
    File:    src/bindings-pkcs11/pkcs11.ml

************************** CeCILL-B HEADER ***********************************)
(* File generated from pkcs11.idl *)

type ck_flags_t = nativeint
and ck_version = {
  major: char;
  minor: char;
}
and ck_info = {
  ck_info_cryptoki_version: ck_version;
  ck_info_manufacturer_id: char array;
  ck_info_flags: ck_flags_t;
  ck_info_library_description: char array;
  ck_info_library_version: ck_version;
}
and ck_notification_t = nativeint
and ck_slot_id_t = nativeint
and ck_slot_info = {
  ck_slot_info_slot_description: char array;
  ck_slot_info_manufacturer_id: char array;
  ck_slot_info_flags: ck_flags_t;
  ck_slot_info_hardware_version: ck_version;
  ck_slot_info_firmware_version: ck_version;
}
and ck_token_info = {
  ck_token_info_label: char array;
  ck_token_info_manufacturer_id: char array;
  ck_token_info_model: char array;
  ck_token_info_serial_number: char array;
  ck_token_info_flags: ck_flags_t;
  ck_token_info_max_session_count: nativeint;
  ck_token_info_session_count: nativeint;
  ck_token_info_max_rw_session_count: nativeint;
  ck_token_info_rw_session_count: nativeint;
  ck_token_info_max_pin_len: nativeint;
  ck_token_info_min_pin_len: nativeint;
  ck_token_info_total_public_memory: nativeint;
  ck_token_info_free_public_memory: nativeint;
  ck_token_info_total_private_memory: nativeint;
  ck_token_info_free_private_memory: nativeint;
  ck_token_info_hardware_version: ck_version;
  ck_token_info_firmware_version: ck_version;
  ck_token_info_utc_time: char array;
}
and ck_session_handle_t = nativeint
and ck_user_type_t = nativeint
and ck_state_t = nativeint
and ck_session_info = {
  ck_session_info_slot_id: ck_slot_id_t;
  ck_session_info_state: ck_state_t;
  ck_session_info_flags: ck_flags_t;
  ck_session_info_device_error: nativeint;
}
and ck_object_handle_t = nativeint
and ck_object_class_t = nativeint
and ck_hw_feature_type_t = nativeint
and ck_key_type_t = nativeint
and ck_certificate_type_t = nativeint
and ck_attribute_type_t = nativeint
and ck_attribute = {
  type_: ck_attribute_type_t;
  value: char array;
}
and ck_date = {
  year: char array;
  month: char array;
  day: char array;
}
and ck_mechanism_type_t = nativeint
and ck_mechanism = {
  mechanism: ck_mechanism_type_t;
  parameter: char array;
}
and ck_mechanism_info = {
  ck_mechanism_info_min_key_size: nativeint;
  ck_mechanism_info_max_key_size: nativeint;
  ck_mechanism_info_flags: ck_flags_t;
}
and cK_BYTE = char
and cK_CHAR = char
and cK_UTF8CHAR = char
and cK_BBOOL = char
and cK_ULONG = nativeint
and cK_LONG = nativeint
and cK_BYTE_PTR = cK_BYTE option
and cK_CHAR_PTR = cK_CHAR option
and cK_UTF8CHAR_PTR = cK_UTF8CHAR option
and cK_ULONG_PTR = cK_ULONG option
and cK_VERSION = ck_version
and cK_VERSION_PTR = ck_version option
and cK_INFO = ck_info
and cK_INFO_PTR = ck_info option
and cK_SLOT_ID_PTR = ck_slot_id_t option
and cK_SLOT_INFO = ck_slot_info
and cK_SLOT_INFO_PTR = ck_slot_info option
and cK_TOKEN_INFO = ck_token_info
and cK_TOKEN_INFO_PTR = ck_token_info option
and cK_SESSION_HANDLE_PTR = ck_session_handle_t option
and cK_SESSION_INFO = ck_session_info
and cK_SESSION_INFO_PTR = ck_session_info option
and cK_OBJECT_HANDLE_PTR = ck_object_handle_t option
and cK_OBJECT_CLASS_PTR = ck_object_class_t option
and cK_ATTRIBUTE = ck_attribute
and cK_ATTRIBUTE_PTR = ck_attribute option
and cK_DATE = ck_date
and cK_DATE_PTR = ck_date option
and cK_MECHANISM_TYPE_PTR = ck_mechanism_type_t option
and cK_MECHANISM = ck_mechanism
and cK_MECHANISM_PTR = ck_mechanism option
and cK_MECHANISM_INFO = ck_mechanism_info
and cK_MECHANISM_INFO_PTR = ck_mechanism_info option
and cK_C_INITIALIZE_ARGS = ck_c_initialize_args
and cK_C_INITIALIZE_ARGS_PTR = ck_c_initialize_args option
and ck_rv_t = nativeint
and ck_createmutex_t = unit->nativeint
and ck_destroymutex_t = unit->nativeint
and ck_lockmutex_t = unit->nativeint
and ck_unlockmutex_t = unit->nativeint
and ck_c_initialize_args = {
  ck_c_initialize_args_create_mutex: ck_createmutex_t;
  ck_c_initialize_args_destroy_mutex: ck_destroymutex_t;
  ck_c_initialize_args_lock_mutex: ck_lockmutex_t;
  ck_c_initialize_args_unlock_mutex: ck_unlockmutex_t;
  ck_c_initialize_args_flags: ck_flags_t;
}

let lITTLE_ENDIAN_64  = 1n
let lITTLE_ENDIAN_32  = 2n
let bIG_ENDIAN_64  = 3n
let bIG_ENDIAN_32  = 4n
let uNSUPPORTED_ARCHITECTURE  = 5n
let nOT_INITIALIZED  = 6n
let match_arch_value a = match a with
   1n -> "LITTLE_ENDIAN_64"
 | 2n -> "LITTLE_ENDIAN_32"
 | 3n -> "BIG_ENDIAN_64"
 | 4n -> "BIG_ENDIAN_32"
 | 5n -> "UNSUPPORTED_ARCHITECTURE"
 | 6n -> "NOT_INITIALIZED"
 | _  -> "UNKNOWN_ERROR"
let cRYPTOKI_VERSION_MAJOR  = 2n
let cRYPTOKI_VERSION_MINOR  = 20n
let cRYPTOKI_VERSION_REVISION = 6n
let cKN_SURRENDER = 0n
let cKN_OTP_CHANGED = 1n
let cKF_TOKEN_PRESENT = 1n
let cKF_REMOVABLE_DEVICE = 2n
let cKF_HW_SLOT  = 4n
let cKF_ARRAY_ATTRIBUTE = 1073741824n
let cKF_RNG     = 1n
let cKF_WRITE_PROTECTED   = 2n
let cKF_LOGIN_REQUIRED   = 4n
let cKF_USER_PIN_INITIALIZED  = 8n
let cKF_RESTORE_KEY_NOT_NEEDED  = 32n
let cKF_CLOCK_ON_TOKEN   = 64n
let cKF_PROTECTED_AUTHENTICATION_PATH = 256n
let cKF_DUAL_CRYPTO_OPERATIONS  = 512n
let cKF_TOKEN_INITIALIZED   = 1024n
let cKF_SECONDARY_AUTHENTICATION  = 2048n
let cKF_USER_PIN_COUNT_LOW   = 65536n
let cKF_USER_PIN_FINAL_TRY   = 131072n
let cKF_USER_PIN_LOCKED   = 262144n
let cKF_USER_PIN_TO_BE_CHANGED  = 524288n
let cKF_SO_PIN_COUNT_LOW   = 1048576n
let cKF_SO_PIN_FINAL_TRY   = 2097152n
let cKF_SO_PIN_LOCKED   = 4194304n
let cKF_SO_PIN_TO_BE_CHANGED  = 8388608n
let cK_UNAVAILABLE_INFORMATION = (Nativeint.minus_one)
let cK_EFFECTIVELY_INFINITE  = 0n
let cK_INVALID_HANDLE = 0n
let cKU_SO   = 0n
let cKU_USER  = 1n
let cKU_CONTEXT_SPECIFIC = 2n
let cKS_RO_PUBLIC_SESSION = 0n
let cKS_RO_USER_FUNCTIONS = 1n
let cKS_RW_PUBLIC_SESSION = 2n
let cKS_RW_USER_FUNCTIONS = 3n
let cKS_RW_SO_FUNCTIONS = 4n
let cKF_RW_SESSION  = 2n
let cKF_SERIAL_SESSION = 4n
let cKO_DATA  = 0n
let cKO_CERTIFICATE  = 1n
let cKO_PUBLIC_KEY  = 2n
let cKO_PRIVATE_KEY  = 3n
let cKO_SECRET_KEY  = 4n
let cKO_HW_FEATURE  = 5n
let cKO_DOMAIN_PARAMETERS = 6n
let cKO_MECHANISM  = 7n
let cKO_OTP_KEY  = 8n
let cKO_VENDOR_DEFINED = 2147483648n
let cKH_MONOTONIC_COUNTER = 1n
let cKH_CLOCK  = 2n
let cKH_USER_INTERFACE = 3n
let cKH_VENDOR_DEFINED = 2147483648n
let cKK_RSA   = 0n
let cKK_DSA   = 1n
let cKK_DH   = 2n
let cKK_ECDSA  = 3n
let cKK_EC   = 3n
let cKK_X9_42_DH  = 4n
let cKK_KEA   = 5n
let cKK_GENERIC_SECRET = 16n
let cKK_RC2   = 17n
let cKK_RC4   = 18n
let cKK_DES   = 19n
let cKK_DES2  = 20n
let cKK_DES3  = 21n
let cKK_CAST  = 22n
let cKK_CAST3  = 23n
let cKK_CAST128  = 24n
let cKK_RC5   = 25n
let cKK_IDEA  = 26n
let cKK_SKIPJACK  = 27n
let cKK_BATON  = 28n
let cKK_JUNIPER  = 29n
let cKK_CDMF  = 30n
let cKK_AES   = 31n
let cKK_BLOWFISH  = 32n
let cKK_TWOFISH  = 33n
let cKK_SECURID  = 34n
let cKK_HOTP  = 35n
let cKK_ACTI  = 36n
let cKK_CAMELLIA  = 37n
let cKK_ARIA  = 38n
let cKK_VENDOR_DEFINED = 2147483648n
let cKC_X_509  = 0n
let cKC_X_509_ATTR_CERT = 1n
let cKC_WTLS  = 2n
let cKC_VENDOR_DEFINED = 2147483648n
let cK_OTP_FORMAT_DECIMAL   = 0n
let cK_OTP_FORMAT_HEXADECIMAL   = 1n
let cK_OTP_FORMAT_ALPHANUMERIC   = 2n
let cK_OTP_PARAM_IGNORED   = 0n
let cK_OTP_PARAM_OPTIONAL   = 1n
let cK_OTP_PARAM_MANDATORY   = 2n
let cKA_CLASS   = 0n
let cKA_TOKEN   = 1n
let cKA_PRIVATE   = 2n
let cKA_LABEL   = 3n
let cKA_APPLICATION   = 16n
let cKA_VALUE   = 17n
let cKA_OBJECT_ID   = 18n
let cKA_CERTIFICATE_TYPE  = 128n
let cKA_ISSUER   = 129n
let cKA_SERIAL_NUMBER  = 130n
let cKA_AC_ISSUER   = 131n
let cKA_OWNER   = 132n
let cKA_ATTR_TYPES   = 133n
let cKA_TRUSTED   = 134n
let cKA_CERTIFICATE_CATEGORY = 135n
let cKA_JAVA_MIDP_SECURITY_DOMAIN = 136n
let cKA_URL    = 137n
let cKA_HASH_OF_SUBJECT_PUBLIC_KEY = 138n
let cKA_HASH_OF_ISSUER_PUBLIC_KEY = 139n
let cKA_CHECK_VALUE   = 144n
let cKA_KEY_TYPE   = 256n
let cKA_SUBJECT   = 257n
let cKA_ID    = 258n
let cKA_SENSITIVE   = 259n
let cKA_ENCRYPT   = 260n
let cKA_DECRYPT   = 261n
let cKA_WRAP   = 262n
let cKA_UNWRAP   = 263n
let cKA_SIGN   = 264n
let cKA_SIGN_RECOVER  = 265n
let cKA_VERIFY   = 266n
let cKA_VERIFY_RECOVER  = 267n
let cKA_DERIVE   = 268n
let cKA_START_DATE   = 272n
let cKA_END_DATE   = 273n
let cKA_MODULUS   = 288n
let cKA_MODULUS_BITS  = 289n
let cKA_PUBLIC_EXPONENT  = 290n
let cKA_PRIVATE_EXPONENT  = 291n
let cKA_PRIME_1   = 292n
let cKA_PRIME_2   = 293n
let cKA_EXPONENT_1   = 294n
let cKA_EXPONENT_2   = 295n
let cKA_COEFFICIENT   = 296n
let cKA_PRIME   = 304n
let cKA_SUBPRIME   = 305n
let cKA_BASE   = 306n
let cKA_PRIME_BITS   = 307n
let cKA_SUB_PRIME_BITS  = 308n
let cKA_VALUE_BITS   = 352n
let cKA_VALUE_LEN   = 353n
let cKA_EXTRACTABLE   = 354n
let cKA_LOCAL   = 355n
let cKA_NEVER_EXTRACTABLE  = 356n
let cKA_ALWAYS_SENSITIVE  = 357n
let cKA_KEY_GEN_MECHANISM  = 358n
let cKA_MODIFIABLE   = 368n
let cKA_ECDSA_PARAMS  = 384n
let cKA_EC_PARAMS   = 384n
let cKA_EC_POINT   = 385n
let cKA_SECONDARY_AUTH  = 512n
let cKA_AUTH_PIN_FLAGS  = 513n
let cKA_ALWAYS_AUTHENTICATE  = 514n
let cKA_WRAP_WITH_TRUSTED  = 528n
let cKA_OTP_FORMAT                   = 544n
let cKA_OTP_LENGTH                   = 545n
let cKA_OTP_TIME_INTERVAL            = 546n
let cKA_OTP_USER_FRIENDLY_MODE       = 547n
let cKA_OTP_CHALLENGE_REQUIREMENT    = 548n
let cKA_OTP_TIME_REQUIREMENT         = 549n
let cKA_OTP_COUNTER_REQUIREMENT      = 550n
let cKA_OTP_PIN_REQUIREMENT          = 551n
let cKA_OTP_COUNTER                  = 552n
let cKA_OTP_TIME                     = 553n
let cKA_OTP_USER_IDENTIFIER          = 554n
let cKA_OTP_SERVICE_IDENTIFIER       = 555n
let cKA_OTP_SERVICE_LOGO             = 556n
let cKA_OTP_SERVICE_LOGO_TYPE        = 557n
let cKA_HW_FEATURE_TYPE  = 768n
let cKA_RESET_ON_INIT  = 769n
let cKA_HAS_RESET   = 770n
let cKA_PIXEL_X   = 1024n
let cKA_PIXEL_Y   = 1025n
let cKA_RESOLUTION   = 1026n
let cKA_CHAR_ROWS   = 1027n
let cKA_CHAR_COLUMNS  = 1028n
let cKA_COLOR   = 1029n
let cKA_BITS_PER_PIXEL  = 1030n
let cKA_CHAR_SETS   = 1152n
let cKA_ENCODING_METHODS  = 1153n
let cKA_MIME_TYPES   = 1154n
let cKA_MECHANISM_TYPE  = 1280n
let cKA_REQUIRED_CMS_ATTRIBUTES = 1281n
let cKA_DEFAULT_CMS_ATTRIBUTES = 1282n
let cKA_SUPPORTED_CMS_ATTRIBUTES = 1283n
let cKA_WRAP_TEMPLATE  = 1073742353n
let cKA_UNWRAP_TEMPLATE  = 1073742354n
let cKA_ALLOWED_MECHANISMS  = 1073743360n
let cKA_VENDOR_DEFINED  = 2147483648n
let cKM_RSA_PKCS_KEY_PAIR_GEN = 0n
let cKM_RSA_PKCS   = 1n
let cKM_RSA_9796   = 2n
let cKM_RSA_X_509   = 3n
let cKM_MD2_RSA_PKCS  = 4n
let cKM_MD5_RSA_PKCS  = 5n
let cKM_SHA1_RSA_PKCS  = 6n
let cKM_RIPEMD128_RSA_PKCS  = 7n
let cKM_RIPEMD160_RSA_PKCS  = 8n
let cKM_RSA_PKCS_OAEP  = 9n
let cKM_RSA_X9_31_KEY_PAIR_GEN = 10n
let cKM_RSA_X9_31   = 11n
let cKM_SHA1_RSA_X9_31  = 12n
let cKM_RSA_PKCS_PSS  = 13n
let cKM_SHA1_RSA_PKCS_PSS  = 14n
let cKM_DSA_KEY_PAIR_GEN  = 16n
let cKM_DSA    = 17n
let cKM_DSA_SHA1   = 18n
let cKM_DH_PKCS_KEY_PAIR_GEN = 32n
let cKM_DH_PKCS_DERIVE  = 33n
let cKM_X9_42_DH_KEY_PAIR_GEN = 48n
let cKM_X9_42_DH_DERIVE  = 49n
let cKM_X9_42_DH_HYBRID_DERIVE = 50n
let cKM_X9_42_MQV_DERIVE  = 51n
let cKM_SHA256_RSA_PKCS  = 64n
let cKM_SHA384_RSA_PKCS  = 65n
let cKM_SHA512_RSA_PKCS  = 66n
let cKM_SHA256_RSA_PKCS_PSS  = 67n
let cKM_SHA384_RSA_PKCS_PSS  = 68n
let cKM_SHA512_RSA_PKCS_PSS  = 69n
let cKM_RC2_KEY_GEN   = 256n
let cKM_RC2_ECB   = 257n
let cKM_RC2_CBC   = 258n
let cKM_RC2_MAC   = 259n
let cKM_RC2_MAC_GENERAL  = 260n
let cKM_RC2_CBC_PAD   = 261n
let cKM_RC4_KEY_GEN   = 272n
let cKM_RC4    = 273n
let cKM_DES_KEY_GEN   = 288n
let cKM_DES_ECB   = 289n
let cKM_DES_CBC   = 290n
let cKM_DES_MAC   = 291n
let cKM_DES_MAC_GENERAL  = 292n
let cKM_DES_CBC_PAD   = 293n
let cKM_DES2_KEY_GEN  = 304n
let cKM_DES3_KEY_GEN  = 305n
let cKM_DES3_ECB   = 306n
let cKM_DES3_CBC   = 307n
let cKM_DES3_MAC   = 308n
let cKM_DES3_MAC_GENERAL  = 309n
let cKM_DES3_CBC_PAD  = 310n
let cKM_CDMF_KEY_GEN  = 320n
let cKM_CDMF_ECB   = 321n
let cKM_CDMF_CBC   = 322n
let cKM_CDMF_MAC   = 323n
let cKM_CDMF_MAC_GENERAL  = 324n
let cKM_CDMF_CBC_PAD  = 325n
let cKM_MD2    = 512n
let cKM_MD2_HMAC   = 513n
let cKM_MD2_HMAC_GENERAL  = 514n
let cKM_MD5    = 528n
let cKM_MD5_HMAC   = 529n
let cKM_MD5_HMAC_GENERAL  = 530n
let cKM_SHA_1   = 544n
let cKM_SHA_1_HMAC   = 545n
let cKM_SHA_1_HMAC_GENERAL  = 546n
let cKM_RIPEMD128   = 560n
let cKM_RIPEMD128_HMAC  = 561n
let cKM_RIPEMD128_HMAC_GENERAL = 562n
let cKM_RIPEMD160   = 576n
let cKM_RIPEMD160_HMAC  = 577n
let cKM_RIPEMD160_HMAC_GENERAL = 578n
let cKM_SHA256   = 592n
let cKM_SHA256_HMAC   = 593n
let cKM_SHA256_HMAC_GENERAL  = 594n
let cKM_SHA384   = 608n
let cKM_SHA384_HMAC   = 609n
let cKM_SHA384_HMAC_GENERAL  = 610n
let cKM_SHA512   = 624n
let cKM_SHA512_HMAC   = 625n
let cKM_SHA512_HMAC_GENERAL  = 626n
let cKM_CAST_KEY_GEN  = 768n
let cKM_CAST_ECB   = 769n
let cKM_CAST_CBC   = 770n
let cKM_CAST_MAC   = 771n
let cKM_CAST_MAC_GENERAL  = 772n
let cKM_CAST_CBC_PAD  = 773n
let cKM_CAST3_KEY_GEN  = 784n
let cKM_CAST3_ECB   = 785n
let cKM_CAST3_CBC   = 786n
let cKM_CAST3_MAC   = 787n
let cKM_CAST3_MAC_GENERAL  = 788n
let cKM_CAST3_CBC_PAD  = 789n
let cKM_CAST5_KEY_GEN  = 800n
let cKM_CAST128_KEY_GEN  = 800n
let cKM_CAST5_ECB   = 801n
let cKM_CAST128_ECB   = 801n
let cKM_CAST5_CBC   = 802n
let cKM_CAST128_CBC   = 802n
let cKM_CAST5_MAC   = 803n
let cKM_CAST128_MAC   = 803n
let cKM_CAST5_MAC_GENERAL  = 804n
let cKM_CAST128_MAC_GENERAL  = 804n
let cKM_CAST5_CBC_PAD  = 805n
let cKM_CAST128_CBC_PAD  = 805n
let cKM_RC5_KEY_GEN   = 816n
let cKM_RC5_ECB   = 817n
let cKM_RC5_CBC   = 818n
let cKM_RC5_MAC   = 819n
let cKM_RC5_MAC_GENERAL  = 820n
let cKM_RC5_CBC_PAD   = 821n
let cKM_IDEA_KEY_GEN  = 832n
let cKM_IDEA_ECB   = 833n
let cKM_IDEA_CBC   = 834n
let cKM_IDEA_MAC   = 835n
let cKM_IDEA_MAC_GENERAL  = 836n
let cKM_IDEA_CBC_PAD  = 837n
let cKM_GENERIC_SECRET_KEY_GEN = 848n
let cKM_CONCATENATE_BASE_AND_KEY = 864n
let cKM_CONCATENATE_BASE_AND_DATA = 866n
let cKM_CONCATENATE_DATA_AND_BASE = 867n
let cKM_XOR_BASE_AND_DATA  = 868n
let cKM_EXTRACT_KEY_FROM_KEY = 869n
let cKM_SSL3_PRE_MASTER_KEY_GEN = 880n
let cKM_SSL3_MASTER_KEY_DERIVE = 881n
let cKM_SSL3_KEY_AND_MAC_DERIVE = 882n
let cKM_SSL3_MASTER_KEY_DERIVE_DH = 883n
let cKM_TLS_PRE_MASTER_KEY_GEN = 884n
let cKM_TLS_MASTER_KEY_DERIVE = 885n
let cKM_TLS_KEY_AND_MAC_DERIVE = 886n
let cKM_TLS_MASTER_KEY_DERIVE_DH = 887n
let cKM_SSL3_MD5_MAC  = 896n
let cKM_SSL3_SHA1_MAC  = 897n
let cKM_MD5_KEY_DERIVATION  = 912n
let cKM_MD2_KEY_DERIVATION  = 913n
let cKM_SHA1_KEY_DERIVATION  = 914n
let cKM_SHA256_KEY_DERIVATION  = 915n
let cKM_SHA384_KEY_DERIVATION  = 916n
let cKM_SHA512_KEY_DERIVATION  = 917n
let cKM_SHA224_KEY_DERIVATION  = 918n
let cKM_PBE_MD2_DES_CBC  = 928n
let cKM_PBE_MD5_DES_CBC  = 929n
let cKM_PBE_MD5_CAST_CBC  = 930n
let cKM_PBE_MD5_CAST3_CBC  = 931n
let cKM_PBE_MD5_CAST5_CBC  = 932n
let cKM_PBE_MD5_CAST128_CBC  = 932n
let cKM_PBE_SHA1_CAST5_CBC  = 933n
let cKM_PBE_SHA1_CAST128_CBC = 933n
let cKM_PBE_SHA1_RC4_128  = 934n
let cKM_PBE_SHA1_RC4_40  = 935n
let cKM_PBE_SHA1_DES3_EDE_CBC = 936n
let cKM_PBE_SHA1_DES2_EDE_CBC = 937n
let cKM_PBE_SHA1_RC2_128_CBC = 938n
let cKM_PBE_SHA1_RC2_40_CBC  = 939n
let cKM_PKCS5_PBKD2   = 944n
let cKM_PBA_SHA1_WITH_SHA1_HMAC = 960n
let cKM_WTLS_PRE_MASTER_KEY_GEN = 976n
let cKM_WTLS_MASTER_KEY_DERIVE = 977n
let cKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 978n
let cKM_WTLS_PRF = 979n
let cKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 980n
let cKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = 981n
let cKM_KEY_WRAP_LYNKS  = 1024n
let cKM_KEY_WRAP_SET_OAEP  = 1025n
let cKM_CMS_SIG = 1280n
let cKM_KIP_DERIVE = 1296n
let cKM_KIP_WRAP = 1297n
let cKM_KIP_MAC = 1298n
let cKM_CAMELLIA_KEY_GEN = 1360n
let cKM_CAMELLIA_ECB = 1361n
let cKM_CAMELLIA_CBC = 1362n
let cKM_CAMELLIA_MAC = 1363n
let cKM_CAMELLIA_MAC_GENERAL = 1364n
let cKM_CAMELLIA_CBC_PAD = 1365n
let cKM_CAMELLIA_ECB_ENCRYPT_DATA = 1366n
let cKM_CAMELLIA_CBC_ENCRYPT_DATA = 1367n
let cKM_CAMELLIA_CTR = 1368n
let cKM_ARIA_KEY_GEN = 1376n
let cKM_ARIA_ECB = 1377n
let cKM_ARIA_CBC = 1378n
let cKM_ARIA_MAC = 1379n
let cKM_ARIA_MAC_GENERAL = 1380n
let cKM_ARIA_CBC_PAD = 1381n
let cKM_ARIA_ECB_ENCRYPT_DATA = 1382n
let cKM_ARIA_CBC_ENCRYPT_DATA = 1383n
let cKM_SKIPJACK_KEY_GEN  = 4096n
let cKM_SKIPJACK_ECB64  = 4097n
let cKM_SKIPJACK_CBC64  = 4098n
let cKM_SKIPJACK_OFB64  = 4099n
let cKM_SKIPJACK_CFB64  = 4100n
let cKM_SKIPJACK_CFB32  = 4101n
let cKM_SKIPJACK_CFB16  = 4102n
let cKM_SKIPJACK_CFB8  = 4103n
let cKM_SKIPJACK_WRAP  = 4104n
let cKM_SKIPJACK_PRIVATE_WRAP = 4105n
let cKM_SKIPJACK_RELAYX  = 4106n
let cKM_KEA_KEY_PAIR_GEN  = 4112n
let cKM_KEA_KEY_DERIVE  = 4113n
let cKM_FORTEZZA_TIMESTAMP  = 4128n
let cKM_BATON_KEY_GEN  = 4144n
let cKM_BATON_ECB128  = 4145n
let cKM_BATON_ECB96   = 4146n
let cKM_BATON_CBC128  = 4147n
let cKM_BATON_COUNTER  = 4148n
let cKM_BATON_SHUFFLE  = 4149n
let cKM_BATON_WRAP   = 4150n
let cKM_ECDSA_KEY_PAIR_GEN  = 4160n
let cKM_EC_KEY_PAIR_GEN  = 4160n
let cKM_ECDSA   = 4161n
let cKM_ECDSA_SHA1   = 4162n
let cKM_ECDH1_DERIVE  = 4176n
let cKM_ECDH1_COFACTOR_DERIVE = 4177n
let cKM_ECMQV_DERIVE  = 4178n
let cKM_JUNIPER_KEY_GEN  = 4192n
let cKM_JUNIPER_ECB128  = 4193n
let cKM_JUNIPER_CBC128  = 4194n
let cKM_JUNIPER_COUNTER  = 4195n
let cKM_JUNIPER_SHUFFLE  = 4196n
let cKM_JUNIPER_WRAP  = 4197n
let cKM_FASTHASH   = 4208n
let cKM_AES_KEY_GEN   = 4224n
let cKM_AES_ECB   = 4225n
let cKM_AES_CBC   = 4226n
let cKM_AES_MAC   = 4227n
let cKM_AES_MAC_GENERAL  = 4228n
let cKM_AES_CBC_PAD   = 4229n
let cKM_AES_CTR   = 4230n
let cKM_BLOWFISH_KEY_GEN = 4240n
let cKM_BLOWFISH_CBC = 4241n
let cKM_TWOFISH_KEY_GEN = 4242n
let cKM_TWOFISH_CBC = 4243n
let cKM_DES_ECB_ENCRYPT_DATA = 4352n
let cKM_DES_CBC_ENCRYPT_DATA = 4353n
let cKM_DES3_ECB_ENCRYPT_DATA = 4354n
let cKM_DES3_CBC_ENCRYPT_DATA = 4355n
let cKM_AES_ECB_ENCRYPT_DATA = 4356n
let cKM_AES_CBC_ENCRYPT_DATA = 4357n
let cKM_DSA_PARAMETER_GEN  = 8192n
let cKM_DH_PKCS_PARAMETER_GEN = 8193n
let cKM_X9_42_DH_PARAMETER_GEN = 8194n
let cKM_VENDOR_DEFINED  = 2147483648n
let cKF_HW   = 1n
let cKF_ENCRYPT  = 256n
let cKF_DECRYPT  = 512n
let cKF_DIGEST  = 1024n
let cKF_SIGN  = 2048n
let cKF_SIGN_RECOVER = 4096n
let cKF_VERIFY  = 8192n
let cKF_VERIFY_RECOVER = 16384n
let cKF_GENERATE  = 32768n
let cKF_GENERATE_KEY_PAIR = 65536n
let cKF_WRAP  = 131072n
let cKF_UNWRAP  = 262144n
let cKF_DERIVE  = 524288n
let cKF_EC_F_P  = 1048576n
let cKF_EC_F_2M  = 2097152n
let cKF_EC_ECPARAMETERS  = 4194304n
let cKF_EC_NAMEDCURVE  = 8388608n
let cKF_EC_UNCOMPRESS  = 16777216n
let cKF_EC_COMPRESS  = 33554432n
let cKF_EXTENSION  = 2147483648n
let cKF_DONT_BLOCK    = 1n
let cKF_LIBRARY_CANT_CREATE_OS_THREADS = 1n
let cKF_OS_LOCKING_OK   = 2n
let cKR_OK     = 0n
let cKR_CANCEL    = 1n
let cKR_HOST_MEMORY    = 2n
let cKR_SLOT_ID_INVALID   = 3n
let cKR_GENERAL_ERROR   = 5n
let cKR_FUNCTION_FAILED   = 6n
let cKR_ARGUMENTS_BAD   = 7n
let cKR_NO_EVENT    = 8n
let cKR_NEED_TO_CREATE_THREADS  = 9n
let cKR_CANT_LOCK    = 10n
let cKR_ATTRIBUTE_READ_ONLY   = 16n
let cKR_ATTRIBUTE_SENSITIVE   = 17n
let cKR_ATTRIBUTE_TYPE_INVALID  = 18n
let cKR_ATTRIBUTE_VALUE_INVALID  = 19n
let cKR_DATA_INVALID   = 32n
let cKR_DATA_LEN_RANGE   = 33n
let cKR_DEVICE_ERROR   = 48n
let cKR_DEVICE_MEMORY   = 49n
let cKR_DEVICE_REMOVED   = 50n
let cKR_ENCRYPTED_DATA_INVALID  = 64n
let cKR_ENCRYPTED_DATA_LEN_RANGE  = 65n
let cKR_FUNCTION_CANCELED   = 80n
let cKR_FUNCTION_NOT_PARALLEL  = 81n
let cKR_FUNCTION_NOT_SUPPORTED  = 84n
let cKR_KEY_HANDLE_INVALID   = 96n
let cKR_KEY_SIZE_RANGE   = 98n
let cKR_KEY_TYPE_INCONSISTENT  = 99n
let cKR_KEY_NOT_NEEDED   = 100n
let cKR_KEY_CHANGED    = 101n
let cKR_KEY_NEEDED    = 102n
let cKR_KEY_INDIGESTIBLE   = 103n
let cKR_KEY_FUNCTION_NOT_PERMITTED  = 104n
let cKR_KEY_NOT_WRAPPABLE   = 105n
let cKR_KEY_UNEXTRACTABLE   = 106n
let cKR_MECHANISM_INVALID   = 112n
let cKR_MECHANISM_PARAM_INVALID  = 113n
let cKR_OBJECT_HANDLE_INVALID  = 130n
let cKR_OPERATION_ACTIVE   = 144n
let cKR_OPERATION_NOT_INITIALIZED  = 145n
let cKR_PIN_INCORRECT   = 160n
let cKR_PIN_INVALID    = 161n
let cKR_PIN_LEN_RANGE   = 162n
let cKR_PIN_EXPIRED    = 163n
let cKR_PIN_LOCKED    = 164n
let cKR_SESSION_CLOSED   = 176n
let cKR_SESSION_COUNT   = 177n
let cKR_SESSION_HANDLE_INVALID  = 179n
let cKR_SESSION_PARALLEL_NOT_SUPPORTED = 180n
let cKR_SESSION_READ_ONLY   = 181n
let cKR_SESSION_EXISTS   = 182n
let cKR_SESSION_READ_ONLY_EXISTS  = 183n
let cKR_SESSION_READ_WRITE_SO_EXISTS = 184n
let cKR_SIGNATURE_INVALID   = 192n
let cKR_SIGNATURE_LEN_RANGE   = 193n
let cKR_TEMPLATE_INCOMPLETE   = 208n
let cKR_TEMPLATE_INCONSISTENT  = 209n
let cKR_TOKEN_NOT_PRESENT   = 224n
let cKR_TOKEN_NOT_RECOGNIZED  = 225n
let cKR_TOKEN_WRITE_PROTECTED  = 226n
let cKR_UNWRAPPING_KEY_HANDLE_INVALID = 240n
let cKR_UNWRAPPING_KEY_SIZE_RANGE  = 241n
let cKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 242n
let cKR_USER_ALREADY_LOGGED_IN  = 256n
let cKR_USER_NOT_LOGGED_IN   = 257n
let cKR_USER_PIN_NOT_INITIALIZED  = 258n
let cKR_USER_TYPE_INVALID   = 259n
let cKR_USER_ANOTHER_ALREADY_LOGGED_IN = 260n
let cKR_USER_TOO_MANY_TYPES   = 261n
let cKR_WRAPPED_KEY_INVALID   = 272n
let cKR_WRAPPED_KEY_LEN_RANGE  = 274n
let cKR_WRAPPING_KEY_HANDLE_INVALID  = 275n
let cKR_WRAPPING_KEY_SIZE_RANGE  = 276n
let cKR_WRAPPING_KEY_TYPE_INCONSISTENT = 277n
let cKR_RANDOM_SEED_NOT_SUPPORTED  = 288n
let cKR_RANDOM_NO_RNG   = 289n
let cKR_DOMAIN_PARAMS_INVALID  = 304n
let cKR_BUFFER_TOO_SMALL   = 336n
let cKR_SAVED_STATE_INVALID   = 352n
let cKR_INFORMATION_SENSITIVE  = 368n
let cKR_STATE_UNSAVEABLE   = 384n
let cKR_CRYPTOKI_NOT_INITIALIZED  = 400n
let cKR_CRYPTOKI_ALREADY_INITIALIZED = 401n
let cKR_MUTEX_BAD    = 416n
let cKR_MUTEX_NOT_LOCKED   = 417n
let cKR_NEW_PIN_MODE   = 432n
let cKR_NEXT_OTP   = 433n
let cKR_FUNCTION_REJECTED   = 512n
let cKR_VENDOR_DEFINED   = 2147483648n
let cK_FALSE = 0n
let cK_TRUE = 1n
let fALSE = 0n
let tRUE = 1n
let nULL_PTR = 0n
let false_ = Array.make 1 (Char.chr 0)
let true_ = Array.make 1 (Char.chr 1)
(* Helpers for information printing *)

let match_cKR_value a = match a with
  0n -> "cKR_OK"
| 1n -> "cKR_CANCEL"
| 2n -> "cKR_HOST_MEMORY"
| 3n -> "cKR_SLOT_ID_INVALID"
| 5n -> "cKR_GENERAL_ERROR"
| 6n -> "cKR_FUNCTION_FAILED"
| 7n -> "cKR_ARGUMENTS_BAD"
| 8n -> "cKR_NO_EVENT"
| 9n -> "cKR_NEED_TO_CREATE_THREADS"
| 10n -> "cKR_CANT_LOCK"
| 16n -> "cKR_ATTRIBUTE_READ_ONLY"
| 17n -> "cKR_ATTRIBUTE_SENSITIVE"
| 18n -> "cKR_ATTRIBUTE_TYPE_INVALID"
| 19n -> "cKR_ATTRIBUTE_VALUE_INVALID"
| 32n -> "cKR_DATA_INVALID"
| 33n -> "cKR_DATA_LEN_RANGE"
| 48n -> "cKR_DEVICE_ERROR"
| 49n -> "cKR_DEVICE_MEMORY"
| 50n -> "cKR_DEVICE_REMOVED"
| 64n -> "cKR_ENCRYPTED_DATA_INVALID"
| 65n -> "cKR_ENCRYPTED_DATA_LEN_RANGE"
| 80n -> "cKR_FUNCTION_CANCELED"
| 81n -> "cKR_FUNCTION_NOT_PARALLEL"
| 84n -> "cKR_FUNCTION_NOT_SUPPORTED"
| 96n -> "cKR_KEY_HANDLE_INVALID"
| 98n -> "cKR_KEY_SIZE_RANGE"
| 99n -> "cKR_KEY_TYPE_INCONSISTENT"
| 100n -> "cKR_KEY_NOT_NEEDED"
| 101n -> "cKR_KEY_CHANGED"
| 102n -> "cKR_KEY_NEEDED"
| 103n -> "cKR_KEY_INDIGESTIBLE"
| 104n -> "cKR_KEY_FUNCTION_NOT_PERMITTED"
| 105n -> "cKR_KEY_NOT_WRAPPABLE"
| 106n -> "cKR_KEY_UNEXTRACTABLE"
| 112n -> "cKR_MECHANISM_INVALID"
| 113n -> "cKR_MECHANISM_PARAM_INVALID"
| 130n -> "cKR_OBJECT_HANDLE_INVALID"
| 144n -> "cKR_OPERATION_ACTIVE"
| 145n -> "cKR_OPERATION_NOT_INITIALIZED"
| 160n -> "cKR_PIN_INCORRECT"
| 161n -> "cKR_PIN_INVALID"
| 162n -> "cKR_PIN_LEN_RANGE"
| 163n -> "cKR_PIN_EXPIRED"
| 164n -> "cKR_PIN_LOCKED"
| 176n -> "cKR_SESSION_CLOSED"
| 177n -> "cKR_SESSION_COUNT"
| 179n -> "cKR_SESSION_HANDLE_INVALID"
| 180n -> "cKR_SESSION_PARALLEL_NOT_SUPPORTED"
| 181n -> "cKR_SESSION_READ_ONLY"
| 182n -> "cKR_SESSION_EXISTS"
| 183n -> "cKR_SESSION_READ_ONLY_EXISTS"
| 184n -> "cKR_SESSION_READ_WRITE_SO_EXISTS"
| 192n -> "cKR_SIGNATURE_INVALID"
| 193n -> "cKR_SIGNATURE_LEN_RANGE"
| 208n -> "cKR_TEMPLATE_INCOMPLETE"
| 209n -> "cKR_TEMPLATE_INCONSISTENT"
| 224n -> "cKR_TOKEN_NOT_PRESENT"
| 225n -> "cKR_TOKEN_NOT_RECOGNIZED"
| 226n -> "cKR_TOKEN_WRITE_PROTECTED"
| 240n -> "cKR_UNWRAPPING_KEY_HANDLE_INVALID"
| 241n -> "cKR_UNWRAPPING_KEY_SIZE_RANGE"
| 242n -> "cKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
| 256n -> "cKR_USER_ALREADY_LOGGED_IN"
| 257n -> "cKR_USER_NOT_LOGGED_IN"
| 258n -> "cKR_USER_PIN_NOT_INITIALIZED"
| 259n -> "cKR_USER_TYPE_INVALID"
| 260n -> "cKR_USER_ANOTHER_ALREADY_LOGGED_IN"
| 261n -> "cKR_USER_TOO_MANY_TYPES"
| 272n -> "cKR_WRAPPED_KEY_INVALID"
| 274n -> "cKR_WRAPPED_KEY_LEN_RANGE"
| 275n -> "cKR_WRAPPING_KEY_HANDLE_INVALID"
| 276n -> "cKR_WRAPPING_KEY_SIZE_RANGE"
| 277n -> "cKR_WRAPPING_KEY_TYPE_INCONSISTENT"
| 288n -> "cKR_RANDOM_SEED_NOT_SUPPORTED"
| 289n -> "cKR_RANDOM_NO_RNG"
| 304n -> "cKR_DOMAIN_PARAMS_INVALID"
| 336n -> "cKR_BUFFER_TOO_SMALL"
| 352n -> "cKR_SAVED_STATE_INVALID"
| 368n -> "cKR_INFORMATION_SENSITIVE"
| 384n -> "cKR_STATE_UNSAVEABLE"
| 400n -> "cKR_CRYPTOKI_NOT_INITIALIZED"
| 401n -> "cKR_CRYPTOKI_ALREADY_INITIALIZED"
| 416n -> "cKR_MUTEX_BAD"
| 417n -> "cKR_MUTEX_NOT_LOCKED"
| 432n -> "cKR_NEW_PIN_MODE"
| 433n -> "cKR_NEXT_OTP"
| 512n -> "cKR_FUNCTION_REJECTED"
| 2147483648n -> "cKR_VENDOR_DEFINED"
| _ -> "cKR_UNKNOWN!"
let match_cKM_value a = match a with
  0n -> "cKM_RSA_PKCS_KEY_PAIR_GEN"
| 1n -> "cKM_RSA_PKCS"
| 2n -> "cKM_RSA_9796"
| 3n -> "cKM_RSA_X_509"
| 4n -> "cKM_MD2_RSA_PKCS"
| 5n -> "cKM_MD5_RSA_PKCS"
| 6n -> "cKM_SHA1_RSA_PKCS"
| 7n -> "cKM_RIPEMD128_RSA_PKCS"
| 8n -> "cKM_RIPEMD160_RSA_PKCS"
| 9n -> "cKM_RSA_PKCS_OAEP"
| 10n -> "cKM_RSA_X9_31_KEY_PAIR_GEN"
| 11n -> "cKM_RSA_X9_31"
| 12n -> "cKM_SHA1_RSA_X9_31"
| 13n -> "cKM_RSA_PKCS_PSS"
| 14n -> "cKM_SHA1_RSA_PKCS_PSS"
| 16n -> "cKM_DSA_KEY_PAIR_GEN"
| 17n -> "cKM_DSA"
| 18n -> "cKM_DSA_SHA1"
| 32n -> "cKM_DH_PKCS_KEY_PAIR_GEN"
| 33n -> "cKM_DH_PKCS_DERIVE"
| 48n -> "cKM_X9_42_DH_KEY_PAIR_GEN"
| 49n -> "cKM_X9_42_DH_DERIVE"
| 50n -> "cKM_X9_42_DH_HYBRID_DERIVE"
| 51n -> "cKM_X9_42_MQV_DERIVE"
| 64n -> "cKM_SHA256_RSA_PKCS"
| 65n -> "cKM_SHA384_RSA_PKCS"
| 66n -> "cKM_SHA512_RSA_PKCS"
| 67n -> "cKM_SHA256_RSA_PKCS_PSS"
| 68n -> "cKM_SHA384_RSA_PKCS_PSS"
| 69n -> "cKM_SHA512_RSA_PKCS_PSS"
| 256n -> "cKM_RC2_KEY_GEN"
| 257n -> "cKM_RC2_ECB"
| 258n -> "cKM_RC2_CBC"
| 259n -> "cKM_RC2_MAC"
| 260n -> "cKM_RC2_MAC_GENERAL"
| 261n -> "cKM_RC2_CBC_PAD"
| 272n -> "cKM_RC4_KEY_GEN"
| 273n -> "cKM_RC4"
| 288n -> "cKM_DES_KEY_GEN"
| 289n -> "cKM_DES_ECB"
| 290n -> "cKM_DES_CBC"
| 291n -> "cKM_DES_MAC"
| 292n -> "cKM_DES_MAC_GENERAL"
| 293n -> "cKM_DES_CBC_PAD"
| 304n -> "cKM_DES2_KEY_GEN"
| 305n -> "cKM_DES3_KEY_GEN"
| 306n -> "cKM_DES3_ECB"
| 307n -> "cKM_DES3_CBC"
| 308n -> "cKM_DES3_MAC"
| 309n -> "cKM_DES3_MAC_GENERAL"
| 310n -> "cKM_DES3_CBC_PAD"
| 320n -> "cKM_CDMF_KEY_GEN"
| 321n -> "cKM_CDMF_ECB"
| 322n -> "cKM_CDMF_CBC"
| 323n -> "cKM_CDMF_MAC"
| 324n -> "cKM_CDMF_MAC_GENERAL"
| 325n -> "cKM_CDMF_CBC_PAD"
| 512n -> "cKM_MD2"
| 513n -> "cKM_MD2_HMAC"
| 514n -> "cKM_MD2_HMAC_GENERAL"
| 528n -> "cKM_MD5"
| 529n -> "cKM_MD5_HMAC"
| 530n -> "cKM_MD5_HMAC_GENERAL"
| 544n -> "cKM_SHA_1"
| 545n -> "cKM_SHA_1_HMAC"
| 546n -> "cKM_SHA_1_HMAC_GENERAL"
| 560n -> "cKM_RIPEMD128"
| 561n -> "cKM_RIPEMD128_HMAC"
| 562n -> "cKM_RIPEMD128_HMAC_GENERAL"
| 576n -> "cKM_RIPEMD160"
| 577n -> "cKM_RIPEMD160_HMAC"
| 578n -> "cKM_RIPEMD160_HMAC_GENERAL"
| 592n -> "cKM_SHA256"
| 593n -> "cKM_SHA256_HMAC"
| 594n -> "cKM_SHA256_HMAC_GENERAL"
| 608n -> "cKM_SHA384"
| 609n -> "cKM_SHA384_HMAC"
| 610n -> "cKM_SHA384_HMAC_GENERAL"
| 624n -> "cKM_SHA512"
| 625n -> "cKM_SHA512_HMAC"
| 626n -> "cKM_SHA512_HMAC_GENERAL"
| 768n -> "cKM_CAST_KEY_GEN"
| 769n -> "cKM_CAST_ECB"
| 770n -> "cKM_CAST_CBC"
| 771n -> "cKM_CAST_MAC"
| 772n -> "cKM_CAST_MAC_GENERAL"
| 773n -> "cKM_CAST_CBC_PAD"
| 784n -> "cKM_CAST3_KEY_GEN"
| 785n -> "cKM_CAST3_ECB"
| 786n -> "cKM_CAST3_CBC"
| 787n -> "cKM_CAST3_MAC"
| 788n -> "cKM_CAST3_MAC_GENERAL"
| 789n -> "cKM_CAST3_CBC_PAD"
| 800n -> "cKM_CAST5_KEY_GEN"
| 801n -> "cKM_CAST5_ECB"
| 802n -> "cKM_CAST5_CBC"
| 803n -> "cKM_CAST5_MAC"
| 804n -> "cKM_CAST5_MAC_GENERAL"
| 805n -> "cKM_CAST5_CBC_PAD"
| 816n -> "cKM_RC5_KEY_GEN"
| 817n -> "cKM_RC5_ECB"
| 818n -> "cKM_RC5_CBC"
| 819n -> "cKM_RC5_MAC"
| 820n -> "cKM_RC5_MAC_GENERAL"
| 821n -> "cKM_RC5_CBC_PAD"
| 832n -> "cKM_IDEA_KEY_GEN"
| 833n -> "cKM_IDEA_ECB"
| 834n -> "cKM_IDEA_CBC"
| 835n -> "cKM_IDEA_MAC"
| 836n -> "cKM_IDEA_MAC_GENERAL"
| 837n -> "cKM_IDEA_CBC_PAD"
| 848n -> "cKM_GENERIC_SECRET_KEY_GEN"
| 864n -> "cKM_CONCATENATE_BASE_AND_KEY"
| 866n -> "cKM_CONCATENATE_BASE_AND_DATA"
| 867n -> "cKM_CONCATENATE_DATA_AND_BASE"
| 868n -> "cKM_XOR_BASE_AND_DATA"
| 869n -> "cKM_EXTRACT_KEY_FROM_KEY"
| 880n -> "cKM_SSL3_PRE_MASTER_KEY_GEN"
| 881n -> "cKM_SSL3_MASTER_KEY_DERIVE"
| 882n -> "cKM_SSL3_KEY_AND_MAC_DERIVE"
| 883n -> "cKM_SSL3_MASTER_KEY_DERIVE_DH"
| 884n -> "cKM_TLS_PRE_MASTER_KEY_GEN"
| 885n -> "cKM_TLS_MASTER_KEY_DERIVE"
| 886n -> "cKM_TLS_KEY_AND_MAC_DERIVE"
| 887n -> "cKM_TLS_MASTER_KEY_DERIVE_DH"
| 896n -> "cKM_SSL3_MD5_MAC"
| 897n -> "cKM_SSL3_SHA1_MAC"
| 912n -> "cKM_MD5_KEY_DERIVATION"
| 913n -> "cKM_MD2_KEY_DERIVATION"
| 914n -> "cKM_SHA1_KEY_DERIVATION"
| 915n -> "cKM_SHA256_KEY_DERIVATION"
| 916n -> "cKM_SHA384_KEY_DERIVATION"
| 917n -> "cKM_SHA512_KEY_DERIVATION"
| 918n -> "cKM_SHA224_KEY_DERIVATION"
| 928n -> "cKM_PBE_MD2_DES_CBC"
| 929n -> "cKM_PBE_MD5_DES_CBC"
| 930n -> "cKM_PBE_MD5_CAST_CBC"
| 931n -> "cKM_PBE_MD5_CAST3_CBC"
| 932n -> "cKM_PBE_MD5_CAST5_CBC"
| 933n -> "cKM_PBE_SHA1_CAST5_CBC"
| 934n -> "cKM_PBE_SHA1_RC4_128"
| 935n -> "cKM_PBE_SHA1_RC4_40"
| 936n -> "cKM_PBE_SHA1_DES3_EDE_CBC"
| 937n -> "cKM_PBE_SHA1_DES2_EDE_CBC"
| 938n -> "cKM_PBE_SHA1_RC2_128_CBC"
| 939n -> "cKM_PBE_SHA1_RC2_40_CBC "
| 944n -> "cKM_PKCS5_PBKD2"
| 960n -> "cKM_PBA_SHA1_WITH_SHA1_HMAC"
| 976n -> "cKM_WTLS_PRE_MASTER_KEY_GEN"
| 977n -> "cKM_WTLS_MASTER_KEY_DERIVE"
| 978n -> "cKM_WTLS_MASTER_KEY_DERIVE_DH_ECC"
| 979n -> "cKM_WTLS_PRF"
| 980n -> "cKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
| 981n -> "cKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
| 1024n -> "cKM_KEY_WRAP_LYNKS"
| 1025n -> "cKM_KEY_WRAP_SET_OAEP"
| 1280n -> "cKM_CMS_SIG"
| 1296n -> "cKM_KIP_DERIVE"
| 1297n -> "cKM_KIP_WRAP"
| 1298n -> "cKM_KIP_MAC"
| 1360n -> "cKM_CAMELLIA_KEY_GEN"
| 1361n -> "cKM_CAMELLIA_ECB"
| 1362n -> "cKM_CAMELLIA_CBC"
| 1363n -> "cKM_CAMELLIA_MAC"
| 1364n -> "cKM_CAMELLIA_MAC_GENERAL"
| 1365n -> "cKM_CAMELLIA_CBC_PAD"
| 1366n -> "cKM_CAMELLIA_ECB_ENCRYPT_DATA"
| 1367n -> "cKM_CAMELLIA_CBC_ENCRYPT_DATA"
| 1368n -> "cKM_CAMELLIA_CTR"
| 1376n -> "cKM_ARIA_KEY_GEN"
| 1377n -> "cKM_ARIA_ECB"
| 1378n -> "cKM_ARIA_CBC"
| 1379n -> "cKM_ARIA_MAC"
| 1380n -> "cKM_ARIA_MAC_GENERAL"
| 1381n -> "cKM_ARIA_CBC_PAD"
| 1382n -> "cKM_ARIA_ECB_ENCRYPT_DATA"
| 1383n -> "cKM_ARIA_CBC_ENCRYPT_DATA"
| 4096n -> "cKM_SKIPJACK_KEY_GEN"
| 4097n -> "cKM_SKIPJACK_ECB64"
| 4098n -> "cKM_SKIPJACK_CBC64"
| 4099n -> "cKM_SKIPJACK_OFB64"
| 4100n -> "cKM_SKIPJACK_CFB64"
| 4101n -> "cKM_SKIPJACK_CFB32"
| 4102n -> "cKM_SKIPJACK_CFB16"
| 4103n -> "cKM_SKIPJACK_CFB8"
| 4104n -> "cKM_SKIPJACK_WRAP"
| 4105n -> "cKM_SKIPJACK_PRIVATE_WRAP"
| 4106n -> "cKM_SKIPJACK_RELAYX"
| 4112n -> "cKM_KEA_KEY_PAIR_GEN"
| 4113n -> "cKM_KEA_KEY_DERIVE"
| 4128n -> "cKM_FORTEZZA_TIMESTAMP"
| 4144n -> "cKM_BATON_KEY_GEN"
| 4145n -> "cKM_BATON_ECB128"
| 4146n -> "cKM_BATON_ECB96"
| 4147n -> "cKM_BATON_CBC128"
| 4148n -> "cKM_BATON_COUNTER"
| 4149n -> "cKM_BATON_SHUFFLE"
| 4150n -> "cKM_BATON_WRAP"
| 4160n -> "cKM_EC_KEY_PAIR_GEN"
| 4161n -> "cKM_ECDSA"
| 4162n -> "cKM_ECDSA_SHA1"
| 4176n -> "cKM_ECDH1_DERIVE"
| 4177n -> "cKM_ECDH1_COFACTOR_DERIVE"
| 4178n -> "cKM_ECMQV_DERIVE"
| 4192n -> "cKM_JUNIPER_KEY_GEN"
| 4193n -> "cKM_JUNIPER_ECB128"
| 4194n -> "cKM_JUNIPER_CBC128"
| 4195n -> "cKM_JUNIPER_COUNTER"
| 4196n -> "cKM_JUNIPER_SHUFFLE"
| 4197n -> "cKM_JUNIPER_WRAP"
| 4208n -> "cKM_FASTHASH"
| 4224n -> "cKM_AES_KEY_GEN"
| 4225n -> "cKM_AES_ECB"
| 4226n -> "cKM_AES_CBC"
| 4227n -> "cKM_AES_MAC"
| 4228n -> "cKM_AES_MAC_GENERAL"
| 4229n -> "cKM_AES_CBC_PAD"
| 4230n -> "cKM_AES_CTR"
| 4240n -> "cKM_BLOWFISH_KEY_GEN"
| 4241n -> "cKM_BLOWFISH_CBC"
| 4242n -> "cKM_TWOFISH_KEY_GEN"
| 4243n -> "cKM_TWOFISH_CBC"
| 4352n -> "cKM_DES_ECB_ENCRYPT_DATA"
| 4353n -> "cKM_DES_CBC_ENCRYPT_DATA"
| 4354n -> "cKM_DES3_ECB_ENCRYPT_DATA"
| 4355n -> "cKM_DES3_CBC_ENCRYPT_DATA"
| 4356n -> "cKM_AES_ECB_ENCRYPT_DATA"
| 4357n -> "cKM_AES_CBC_ENCRYPT_DATA"
| 8192n -> "cKM_DSA_PARAMETER_GEN"
| 8193n -> "cKM_DH_PKCS_PARAMETER_GEN"
| 8194n -> "cKM_X9_42_DH_PARAMETER_GEN"
| 2147483648n -> "cKM_VENDOR_DEFINED"
| _ -> "cKM_UNKNOWN!"
exception Mechanism_unknown of string
(* Our mechanisms for getting a mechanism from a string *)
let string_to_cKM_value a = match a with
  "CKM_RSA_PKCS_KEY_PAIR_GEN" -> 0n
| "CKM_RSA_PKCS" -> 1n
| "CKM_RSA_9796" -> 2n
| "CKM_RSA_X_509" -> 3n
| "CKM_MD2_RSA_PKCS" -> 4n
| "CKM_MD5_RSA_PKCS" -> 5n
| "CKM_SHA1_RSA_PKCS" -> 6n
| "CKM_RIPEMD128_RSA_PKCS" -> 7n
| "CKM_RIPEMD160_RSA_PKCS" -> 8n
| "CKM_RSA_PKCS_OAEP" -> 9n
| "CKM_RSA_X9_31_KEY_PAIR_GEN" -> 10n
| "CKM_RSA_X9_31" -> 11n
| "CKM_SHA1_RSA_X9_31" -> 12n
| "CKM_RSA_PKCS_PSS" -> 13n
| "CKM_SHA1_RSA_PKCS_PSS" -> 14n
| "CKM_DSA_KEY_PAIR_GEN" -> 16n
| "CKM_DSA" -> 17n
| "CKM_DSA_SHA1" -> 18n
| "CKM_DH_PKCS_KEY_PAIR_GEN" -> 32n
| "CKM_DH_PKCS_DERIVE" -> 33n
| "CKM_X9_42_DH_KEY_PAIR_GEN" -> 48n
| "CKM_X9_42_DH_DERIVE" -> 49n
| "CKM_X9_42_DH_HYBRID_DERIVE" -> 50n
| "CKM_X9_42_MQV_DERIVE" -> 51n
| "CKM_SHA256_RSA_PKCS" -> 64n
| "CKM_SHA384_RSA_PKCS" -> 65n
| "CKM_SHA512_RSA_PKCS" -> 66n
| "CKM_SHA256_RSA_PKCS_PSS" -> 67n
| "CKM_SHA384_RSA_PKCS_PSS" -> 68n
| "CKM_SHA512_RSA_PKCS_PSS" -> 69n
| "CKM_RC2_KEY_GEN" -> 256n
| "CKM_RC2_ECB" -> 257n
| "CKM_RC2_CBC" -> 258n
| "CKM_RC2_MAC" -> 259n
| "CKM_RC2_MAC_GENERAL" -> 260n
| "CKM_RC2_CBC_PAD" -> 261n
| "CKM_RC4_KEY_GEN" -> 272n
| "CKM_RC4" -> 273n
| "CKM_DES_KEY_GEN" -> 288n
| "CKM_DES_ECB" -> 289n
| "CKM_DES_CBC" -> 290n
| "CKM_DES_MAC" -> 291n
| "CKM_DES_MAC_GENERAL" -> 292n
| "CKM_DES_CBC_PAD" -> 293n
| "CKM_DES2_KEY_GEN" -> 304n
| "CKM_DES3_KEY_GEN" -> 305n
| "CKM_DES3_ECB" -> 306n
| "CKM_DES3_CBC" -> 307n
| "CKM_DES3_MAC" -> 308n
| "CKM_DES3_MAC_GENERAL" -> 309n
| "CKM_DES3_CBC_PAD" -> 310n
| "CKM_CDMF_KEY_GEN" -> 320n
| "CKM_CDMF_ECB" -> 321n
| "CKM_CDMF_CBC" -> 322n
| "CKM_CDMF_MAC" -> 323n
| "CKM_CDMF_MAC_GENERAL" -> 324n
| "CKM_CDMF_CBC_PAD" -> 325n
| "CKM_MD2" -> 512n
| "CKM_MD2_HMAC" -> 513n
| "CKM_MD2_HMAC_GENERAL" -> 514n
| "CKM_MD5" -> 528n
| "CKM_MD5_HMAC" -> 529n
| "CKM_MD5_HMAC_GENERAL" -> 530n
| "CKM_SHA_1" -> 544n
| "CKM_SHA_1_HMAC" -> 545n
| "CKM_SHA_1_HMAC_GENERAL" -> 546n
| "CKM_RIPEMD128" -> 560n
| "CKM_RIPEMD128_HMAC" -> 561n
| "CKM_RIPEMD128_HMAC_GENERAL" -> 562n
| "CKM_RIPEMD160" -> 576n
| "CKM_RIPEMD160_HMAC" -> 577n
| "CKM_RIPEMD160_HMAC_GENERAL" -> 578n
| "CKM_SHA256" -> 592n
| "CKM_SHA256_HMAC" -> 593n
| "CKM_SHA256_HMAC_GENERAL" -> 594n
| "CKM_SHA384" -> 608n
| "CKM_SHA384_HMAC" -> 609n
| "CKM_SHA384_HMAC_GENERAL" -> 610n
| "CKM_SHA512" -> 624n
| "CKM_SHA512_HMAC" -> 625n
| "CKM_SHA512_HMAC_GENERAL" -> 626n
| "CKM_CAST_KEY_GEN" -> 768n
| "CKM_CAST_ECB" -> 769n
| "CKM_CAST_CBC" -> 770n
| "CKM_CAST_MAC" -> 771n
| "CKM_CAST_MAC_GENERAL" -> 772n
| "CKM_CAST_CBC_PAD" -> 773n
| "CKM_CAST3_KEY_GEN" -> 784n
| "CKM_CAST3_ECB" -> 785n
| "CKM_CAST3_CBC" -> 786n
| "CKM_CAST3_MAC" -> 787n
| "CKM_CAST3_MAC_GENERAL" -> 788n
| "CKM_CAST3_CBC_PAD" -> 789n
| "CKM_CAST5_KEY_GEN" -> 800n
| "CKM_CAST5_ECB" -> 801n
| "CKM_CAST5_CBC" -> 802n
| "CKM_CAST5_MAC" -> 803n
| "CKM_CAST5_MAC_GENERAL" -> 804n
| "CKM_CAST5_CBC_PAD" -> 805n
| "CKM_RC5_KEY_GEN" -> 816n
| "CKM_RC5_ECB" -> 817n
| "CKM_RC5_CBC" -> 818n
| "CKM_RC5_MAC" -> 819n
| "CKM_RC5_MAC_GENERAL" -> 820n
| "CKM_RC5_CBC_PAD" -> 821n
| "CKM_IDEA_KEY_GEN" -> 832n
| "CKM_IDEA_ECB" -> 833n
| "CKM_IDEA_CBC" -> 834n
| "CKM_IDEA_MAC" -> 835n
| "CKM_IDEA_MAC_GENERAL" -> 836n
| "CKM_IDEA_CBC_PAD" -> 837n
| "CKM_GENERIC_SECRET_KEY_GEN" -> 848n
| "CKM_CONCATENATE_BASE_AND_KEY" -> 864n
| "CKM_CONCATENATE_BASE_AND_DATA" -> 866n
| "CKM_CONCATENATE_DATA_AND_BASE" -> 867n
| "CKM_XOR_BASE_AND_DATA" -> 868n
| "CKM_EXTRACT_KEY_FROM_KEY" -> 869n
| "CKM_SSL3_PRE_MASTER_KEY_GEN" -> 880n
| "CKM_SSL3_MASTER_KEY_DERIVE" -> 881n
| "CKM_SSL3_KEY_AND_MAC_DERIVE" -> 882n
| "CKM_SSL3_MASTER_KEY_DERIVE_DH" -> 883n
| "CKM_TLS_PRE_MASTER_KEY_GEN" -> 884n
| "CKM_TLS_MASTER_KEY_DERIVE" -> 885n
| "CKM_TLS_KEY_AND_MAC_DERIVE" -> 886n
| "CKM_TLS_MASTER_KEY_DERIVE_DH" -> 887n
| "CKM_SSL3_MD5_MAC" -> 896n
| "CKM_SSL3_SHA1_MAC" -> 897n
| "CKM_MD5_KEY_DERIVATION" -> 912n
| "CKM_MD2_KEY_DERIVATION" -> 913n
| "CKM_SHA1_KEY_DERIVATION" -> 914n
| "CKM_SHA256_KEY_DERIVATION" -> 915n
| "CKM_SHA384_KEY_DERIVATION" -> 916n
| "CKM_SHA512_KEY_DERIVATION" -> 917n
| "CKM_SHA224_KEY_DERIVATION" -> 918n
| "CKM_PBE_MD2_DES_CBC" -> 928n
| "CKM_PBE_MD5_DES_CBC" -> 929n
| "CKM_PBE_MD5_CAST_CBC" -> 930n
| "CKM_PBE_MD5_CAST3_CBC" -> 931n
| "CKM_PBE_MD5_CAST5_CBC" -> 932n
| "CKM_PBE_SHA1_CAST5_CBC" -> 933n
| "CKM_PBE_SHA1_RC4_128" -> 934n
| "CKM_PBE_SHA1_RC4_40" -> 935n
| "CKM_PBE_SHA1_DES3_EDE_CBC" -> 936n
| "CKM_PBE_SHA1_DES2_EDE_CBC" -> 937n
| "CKM_PBE_SHA1_RC2_128_CBC" -> 938n
| "CKM_PBE_SHA1_RC2_40_CBC" -> 939n
| "CKM_PKCS5_PBKD2" -> 944n
| "CKM_PBA_SHA1_WITH_SHA1_HMAC" -> 960n
| "CKM_WTLS_PRE_MASTER_KEY_GEN" -> 976n
| "CKM_WTLS_MASTER_KEY_DERIVE" -> 977n
| "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC" -> 978n
| "CKM_WTLS_PRF" -> 979n
| "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE" -> 980n
| "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE" -> 981n
| "CKM_KEY_WRAP_LYNKS" -> 1024n
| "CKM_KEY_WRAP_SET_OAEP" -> 1025n
| "CKM_CMS_SIG" -> 1280n
| "CKM_KIP_DERIVE" -> 1296n
| "CKM_KIP_WRAP" -> 1297n
| "CKM_KIP_MAC" -> 1298n
| "CKM_CAMELLIA_KEY_GEN" -> 1360n
| "CKM_CAMELLIA_ECB" -> 1361n
| "CKM_CAMELLIA_CBC" -> 1362n
| "CKM_CAMELLIA_MAC" -> 1363n
| "CKM_CAMELLIA_MAC_GENERAL" -> 1364n
| "CKM_CAMELLIA_CBC_PAD" -> 1365n
| "CKM_CAMELLIA_ECB_ENCRYPT_DATA" -> 1366n
| "CKM_CAMELLIA_CBC_ENCRYPT_DATA" -> 1367n
| "CKM_CAMELLIA_CTR" -> 1368n
| "CKM_ARIA_KEY_GEN" -> 1376n
| "CKM_ARIA_ECB" -> 1377n
| "CKM_ARIA_CBC" -> 1378n
| "CKM_ARIA_MAC" -> 1379n
| "CKM_ARIA_MAC_GENERAL" -> 1380n
| "CKM_ARIA_CBC_PAD" -> 1381n
| "CKM_ARIA_ECB_ENCRYPT_DATA" -> 1382n
| "CKM_ARIA_CBC_ENCRYPT_DATA" -> 1383n
| "CKM_SKIPJACK_KEY_GEN" -> 4096n
| "CKM_SKIPJACK_ECB64" -> 4097n
| "CKM_SKIPJACK_CBC64" -> 4098n
| "CKM_SKIPJACK_OFB64" -> 4099n
| "CKM_SKIPJACK_CFB64" -> 4100n
| "CKM_SKIPJACK_CFB32" -> 4101n
| "CKM_SKIPJACK_CFB16" -> 4102n
| "CKM_SKIPJACK_CFB8" -> 4103n
| "CKM_SKIPJACK_WRAP" -> 4104n
| "CKM_SKIPJACK_PRIVATE_WRAP" -> 4105n
| "CKM_SKIPJACK_RELAYX" -> 4106n
| "CKM_KEA_KEY_PAIR_GEN" -> 4112n
| "CKM_KEA_KEY_DERIVE" -> 4113n
| "CKM_FORTEZZA_TIMESTAMP" -> 4128n
| "CKM_BATON_KEY_GEN" -> 4144n
| "CKM_BATON_ECB128" -> 4145n
| "CKM_BATON_ECB96" -> 4146n
| "CKM_BATON_CBC128" -> 4147n
| "CKM_BATON_COUNTER" -> 4148n
| "CKM_BATON_SHUFFLE" -> 4149n
| "CKM_BATON_WRAP" -> 4150n
| "CKM_ECDSA_KEY_PAIR_GEN" -> 4160n
| "CKM_ECDSA" -> 4161n
| "CKM_ECDSA_SHA1" -> 4162n
| "CKM_ECDH1_DERIVE" -> 4176n
| "CKM_ECDH1_COFACTOR_DERIVE" -> 4177n
| "CKM_ECMQV_DERIVE" -> 4178n
| "CKM_JUNIPER_KEY_GEN" -> 4192n
| "CKM_JUNIPER_ECB128" -> 4193n
| "CKM_JUNIPER_CBC128" -> 4194n
| "CKM_JUNIPER_COUNTER" -> 4195n
| "CKM_JUNIPER_SHUFFLE" -> 4196n
| "CKM_JUNIPER_WRAP" -> 4197n
| "CKM_FASTHASH" -> 4208n
| "CKM_AES_KEY_GEN" -> 4224n
| "CKM_AES_ECB" -> 4225n
| "CKM_AES_CBC" -> 4226n
| "CKM_AES_MAC" -> 4227n
| "CKM_AES_MAC_GENERAL" -> 4228n
| "CKM_AES_CBC_PAD" -> 4229n
| "CKM_AES_CTR" -> 4230n
| "CKM_BLOWFISH_KEY_GEN" -> 4240n
| "CKM_BLOWFISH_CBC" -> 4241n
| "CKM_TWOFISH_KEY_GEN" -> 4242n
| "CKM_TWOFISH_CBC" -> 4243n
| "CKM_DES_ECB_ENCRYPT_DATA" -> 4352n
| "CKM_DES_CBC_ENCRYPT_DATA" -> 4353n
| "CKM_DES3_ECB_ENCRYPT_DATA" -> 4354n
| "CKM_DES3_CBC_ENCRYPT_DATA" -> 4355n
| "CKM_AES_ECB_ENCRYPT_DATA" -> 4356n
| "CKM_AES_CBC_ENCRYPT_DATA" -> 4357n
| "CKM_DSA_PARAMETER_GEN" -> 8192n
| "CKM_DH_PKCS_PARAMETER_GEN" -> 8193n
| "CKM_X9_42_DH_PARAMETER_GEN" -> 8194n
| "CKM_VENDOR_DEFINED" -> 2147483648n
| "cKM_RSA_PKCS_KEY_PAIR_GEN" -> 0n
| "cKM_RSA_PKCS" -> 1n
| "cKM_RSA_9796" -> 2n
| "cKM_RSA_X_509" -> 3n
| "cKM_MD2_RSA_PKCS" -> 4n
| "cKM_MD5_RSA_PKCS" -> 5n
| "cKM_SHA1_RSA_PKCS" -> 6n
| "cKM_RIPEMD128_RSA_PKCS" -> 7n
| "cKM_RIPEMD160_RSA_PKCS" -> 8n
| "cKM_RSA_PKCS_OAEP" -> 9n
| "cKM_RSA_X9_31_KEY_PAIR_GEN" -> 10n
| "cKM_RSA_X9_31" -> 11n
| "cKM_SHA1_RSA_X9_31" -> 12n
| "cKM_RSA_PKCS_PSS" -> 13n
| "cKM_SHA1_RSA_PKCS_PSS" -> 14n
| "cKM_DSA_KEY_PAIR_GEN" -> 16n
| "cKM_DSA" -> 17n
| "cKM_DSA_SHA1" -> 18n
| "cKM_DH_PKCS_KEY_PAIR_GEN" -> 32n
| "cKM_DH_PKCS_DERIVE" -> 33n
| "cKM_X9_42_DH_KEY_PAIR_GEN" -> 48n
| "cKM_X9_42_DH_DERIVE" -> 49n
| "cKM_X9_42_DH_HYBRID_DERIVE" -> 50n
| "cKM_X9_42_MQV_DERIVE" -> 51n
| "cKM_SHA256_RSA_PKCS" -> 64n
| "cKM_SHA384_RSA_PKCS" -> 65n
| "cKM_SHA512_RSA_PKCS" -> 66n
| "cKM_SHA256_RSA_PKCS_PSS" -> 67n
| "cKM_SHA384_RSA_PKCS_PSS" -> 68n
| "cKM_SHA512_RSA_PKCS_PSS" -> 69n
| "cKM_RC2_KEY_GEN" -> 256n
| "cKM_RC2_ECB" -> 257n
| "cKM_RC2_CBC" -> 258n
| "cKM_RC2_MAC" -> 259n
| "cKM_RC2_MAC_GENERAL" -> 260n
| "cKM_RC2_CBC_PAD" -> 261n
| "cKM_RC4_KEY_GEN" -> 272n
| "cKM_RC4" -> 273n
| "cKM_DES_KEY_GEN" -> 288n
| "cKM_DES_ECB" -> 289n
| "cKM_DES_CBC" -> 290n
| "cKM_DES_MAC" -> 291n
| "cKM_DES_MAC_GENERAL" -> 292n
| "cKM_DES_CBC_PAD" -> 293n
| "cKM_DES2_KEY_GEN" -> 304n
| "cKM_DES3_KEY_GEN" -> 305n
| "cKM_DES3_ECB" -> 306n
| "cKM_DES3_CBC" -> 307n
| "cKM_DES3_MAC" -> 308n
| "cKM_DES3_MAC_GENERAL" -> 309n
| "cKM_DES3_CBC_PAD" -> 310n
| "cKM_CDMF_KEY_GEN" -> 320n
| "cKM_CDMF_ECB" -> 321n
| "cKM_CDMF_CBC" -> 322n
| "cKM_CDMF_MAC" -> 323n
| "cKM_CDMF_MAC_GENERAL" -> 324n
| "cKM_CDMF_CBC_PAD" -> 325n
| "cKM_MD2" -> 512n
| "cKM_MD2_HMAC" -> 513n
| "cKM_MD2_HMAC_GENERAL" -> 514n
| "cKM_MD5" -> 528n
| "cKM_MD5_HMAC" -> 529n
| "cKM_MD5_HMAC_GENERAL" -> 530n
| "cKM_SHA_1" -> 544n
| "cKM_SHA_1_HMAC" -> 545n
| "cKM_SHA_1_HMAC_GENERAL" -> 546n
| "cKM_RIPEMD128" -> 560n
| "cKM_RIPEMD128_HMAC" -> 561n
| "cKM_RIPEMD128_HMAC_GENERAL" -> 562n
| "cKM_RIPEMD160" -> 576n
| "cKM_RIPEMD160_HMAC" -> 577n
| "cKM_RIPEMD160_HMAC_GENERAL" -> 578n
| "cKM_SHA256" -> 592n
| "cKM_SHA256_HMAC" -> 593n
| "cKM_SHA256_HMAC_GENERAL" -> 594n
| "cKM_SHA384" -> 608n
| "cKM_SHA384_HMAC" -> 609n
| "cKM_SHA384_HMAC_GENERAL" -> 610n
| "cKM_SHA512" -> 624n
| "cKM_SHA512_HMAC" -> 625n
| "cKM_SHA512_HMAC_GENERAL" -> 626n
| "cKM_CAST_KEY_GEN" -> 768n
| "cKM_CAST_ECB" -> 769n
| "cKM_CAST_CBC" -> 770n
| "cKM_CAST_MAC" -> 771n
| "cKM_CAST_MAC_GENERAL" -> 772n
| "cKM_CAST_CBC_PAD" -> 773n
| "cKM_CAST3_KEY_GEN" -> 784n
| "cKM_CAST3_ECB" -> 785n
| "cKM_CAST3_CBC" -> 786n
| "cKM_CAST3_MAC" -> 787n
| "cKM_CAST3_MAC_GENERAL" -> 788n
| "cKM_CAST3_CBC_PAD" -> 789n
| "cKM_CAST5_KEY_GEN" -> 800n
| "cKM_CAST5_ECB" -> 801n
| "cKM_CAST5_CBC" -> 802n
| "cKM_CAST5_MAC" -> 803n
| "cKM_CAST5_MAC_GENERAL" -> 804n
| "cKM_CAST5_CBC_PAD" -> 805n
| "cKM_RC5_KEY_GEN" -> 816n
| "cKM_RC5_ECB" -> 817n
| "cKM_RC5_CBC" -> 818n
| "cKM_RC5_MAC" -> 819n
| "cKM_RC5_MAC_GENERAL" -> 820n
| "cKM_RC5_CBC_PAD" -> 821n
| "cKM_IDEA_KEY_GEN" -> 832n
| "cKM_IDEA_ECB" -> 833n
| "cKM_IDEA_CBC" -> 834n
| "cKM_IDEA_MAC" -> 835n
| "cKM_IDEA_MAC_GENERAL" -> 836n
| "cKM_IDEA_CBC_PAD" -> 837n
| "cKM_GENERIC_SECRET_KEY_GEN" -> 848n
| "cKM_CONCATENATE_BASE_AND_KEY" -> 864n
| "cKM_CONCATENATE_BASE_AND_DATA" -> 866n
| "cKM_CONCATENATE_DATA_AND_BASE" -> 867n
| "cKM_XOR_BASE_AND_DATA" -> 868n
| "cKM_EXTRACT_KEY_FROM_KEY" -> 869n
| "cKM_SSL3_PRE_MASTER_KEY_GEN" -> 880n
| "cKM_SSL3_MASTER_KEY_DERIVE" -> 881n
| "cKM_SSL3_KEY_AND_MAC_DERIVE" -> 882n
| "cKM_SSL3_MASTER_KEY_DERIVE_DH" -> 883n
| "cKM_TLS_PRE_MASTER_KEY_GEN" -> 884n
| "cKM_TLS_MASTER_KEY_DERIVE" -> 885n
| "cKM_TLS_KEY_AND_MAC_DERIVE" -> 886n
| "cKM_TLS_MASTER_KEY_DERIVE_DH" -> 887n
| "cKM_SSL3_MD5_MAC" -> 896n
| "cKM_SSL3_SHA1_MAC" -> 897n
| "cKM_MD5_KEY_DERIVATION" -> 912n
| "cKM_MD2_KEY_DERIVATION" -> 913n
| "cKM_SHA1_KEY_DERIVATION" -> 914n
| "cKM_SHA256_KEY_DERIVATION" -> 915n
| "cKM_SHA384_KEY_DERIVATION" -> 916n
| "cKM_SHA512_KEY_DERIVATION" -> 917n
| "cKM_SHA224_KEY_DERIVATION" -> 918n
| "cKM_PBE_MD2_DES_CBC" -> 928n
| "cKM_PBE_MD5_DES_CBC" -> 929n
| "cKM_PBE_MD5_CAST_CBC" -> 930n
| "cKM_PBE_MD5_CAST3_CBC" -> 931n
| "cKM_PBE_MD5_CAST5_CBC" -> 932n
| "cKM_PBE_SHA1_CAST5_CBC" -> 933n
| "cKM_PBE_SHA1_RC4_128" -> 934n
| "cKM_PBE_SHA1_RC4_40" -> 935n
| "cKM_PBE_SHA1_DES3_EDE_CBC" -> 936n
| "cKM_PBE_SHA1_DES2_EDE_CBC" -> 937n
| "cKM_PBE_SHA1_RC2_128_CBC" -> 938n
| "cKM_PBE_SHA1_RC2_40_CBC" -> 939n
| "cKM_PKCS5_PBKD2" -> 944n
| "cKM_PBA_SHA1_WITH_SHA1_HMAC" -> 960n
| "cKM_WTLS_PRE_MASTER_KEY_GEN" -> 976n
| "cKM_WTLS_MASTER_KEY_DERIVE" -> 977n
| "cKM_WTLS_MASTER_KEY_DERIVE_DH_ECC" -> 978n
| "cKM_WTLS_PRF" -> 979n
| "cKM_WTLS_SERVER_KEY_AND_MAC_DERIVE" -> 980n
| "cKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE" -> 981n
| "cKM_KEY_WRAP_LYNKS" -> 1024n
| "cKM_KEY_WRAP_SET_OAEP" -> 1025n
| "cKM_CMS_SIG" -> 1280n
| "cKM_KIP_DERIVE" -> 1296n
| "cKM_KIP_WRAP" -> 1297n
| "cKM_KIP_MAC" -> 1298n
| "cKM_CAMELLIA_KEY_GEN" -> 1360n
| "cKM_CAMELLIA_ECB" -> 1361n
| "cKM_CAMELLIA_CBC" -> 1362n
| "cKM_CAMELLIA_MAC" -> 1363n
| "cKM_CAMELLIA_MAC_GENERAL" -> 1364n
| "cKM_CAMELLIA_CBC_PAD" -> 1365n
| "cKM_CAMELLIA_ECB_ENCRYPT_DATA" -> 1366n
| "cKM_CAMELLIA_CBC_ENCRYPT_DATA" -> 1367n
| "cKM_CAMELLIA_CTR" -> 1368n
| "cKM_ARIA_KEY_GEN" -> 1376n
| "cKM_ARIA_ECB" -> 1377n
| "cKM_ARIA_CBC" -> 1378n
| "cKM_ARIA_MAC" -> 1379n
| "cKM_ARIA_MAC_GENERAL" -> 1380n
| "cKM_ARIA_CBC_PAD" -> 1381n
| "cKM_ARIA_ECB_ENCRYPT_DATA" -> 1382n
| "cKM_ARIA_CBC_ENCRYPT_DATA" -> 1383n
| "cKM_SKIPJACK_KEY_GEN" -> 4096n
| "cKM_SKIPJACK_ECB64" -> 4097n
| "cKM_SKIPJACK_CBC64" -> 4098n
| "cKM_SKIPJACK_OFB64" -> 4099n
| "cKM_SKIPJACK_CFB64" -> 4100n
| "cKM_SKIPJACK_CFB32" -> 4101n
| "cKM_SKIPJACK_CFB16" -> 4102n
| "cKM_SKIPJACK_CFB8" -> 4103n
| "cKM_SKIPJACK_WRAP" -> 4104n
| "cKM_SKIPJACK_PRIVATE_WRAP" -> 4105n
| "cKM_SKIPJACK_RELAYX" -> 4106n
| "cKM_KEA_KEY_PAIR_GEN" -> 4112n
| "cKM_KEA_KEY_DERIVE" -> 4113n
| "cKM_FORTEZZA_TIMESTAMP" -> 4128n
| "cKM_BATON_KEY_GEN" -> 4144n
| "cKM_BATON_ECB128" -> 4145n
| "cKM_BATON_ECB96" -> 4146n
| "cKM_BATON_CBC128" -> 4147n
| "cKM_BATON_COUNTER" -> 4148n
| "cKM_BATON_SHUFFLE" -> 4149n
| "cKM_BATON_WRAP" -> 4150n
| "cKM_EC_KEY_PAIR_GEN" -> 4160n
| "cKM_ECDSA" -> 4161n
| "cKM_ECDSA_SHA1" -> 4162n
| "cKM_ECDH1_DERIVE" -> 4176n
| "cKM_ECDH1_COFACTOR_DERIVE" -> 4177n
| "cKM_ECMQV_DERIVE" -> 4178n
| "cKM_JUNIPER_KEY_GEN" -> 4192n
| "cKM_JUNIPER_ECB128" -> 4193n
| "cKM_JUNIPER_CBC128" -> 4194n
| "cKM_JUNIPER_COUNTER" -> 4195n
| "cKM_JUNIPER_SHUFFLE" -> 4196n
| "cKM_JUNIPER_WRAP" -> 4197n
| "cKM_FASTHASH" -> 4208n
| "cKM_AES_KEY_GEN" -> 4224n
| "cKM_AES_ECB" -> 4225n
| "cKM_AES_CBC" -> 4226n
| "cKM_AES_MAC" -> 4227n
| "cKM_AES_MAC_GENERAL" -> 4228n
| "cKM_AES_CBC_PAD" -> 4229n
| "cKM_AES_CTR" -> 4230n
| "cKM_BLOWFISH_KEY_GEN" -> 4240n
| "cKM_BLOWFISH_CBC" -> 4241n
| "cKM_TWOFISH_KEY_GEN" -> 4242n
| "cKM_TWOFISH_CBC" -> 4243n
| "cKM_DES_ECB_ENCRYPT_DATA" -> 4352n
| "cKM_DES_CBC_ENCRYPT_DATA" -> 4353n
| "cKM_DES3_ECB_ENCRYPT_DATA" -> 4354n
| "cKM_DES3_CBC_ENCRYPT_DATA" -> 4355n
| "cKM_AES_ECB_ENCRYPT_DATA" -> 4356n
| "cKM_AES_CBC_ENCRYPT_DATA" -> 4357n
| "cKM_DSA_PARAMETER_GEN" -> 8192n
| "cKM_DH_PKCS_PARAMETER_GEN" -> 8193n
| "cKM_X9_42_DH_PARAMETER_GEN" -> 8194n
| "cKM_VENDOR_DEFINED" -> 2147483648n
| _ -> raise (Mechanism_unknown a)
let match_cKF_value a = match a with
| 1n -> "cKF_TOKEN_PRESENT | ncKF_RNG | ncKF_HW | ncKF_DONT_BLOCK | ncKF_LIBRARY_CANT_CREATE_OS_THREADS"
| 2n -> "cKF_REMOVABLE_DEVICE | ncKF_RW_SESSION | ncKF_WRITE_PROTECTED | ncKF_OS_LOCKING_OK"
| 4n -> "cKF_HW_SLOT | ncKF_LOGIN_REQUIRED | ncKF_SERIAL_SESSION"
| 1073741824n -> "cKF_ARRAY_ATTRIBUTE"
| 8n -> "cKF_USER_PIN_INITIALIZED"
| 32n -> "cKF_RESTORE_KEY_NOT_NEEDED"
| 64n -> "cKF_CLOCK_ON_TOKEN"
| 256n -> "cKF_PROTECTED_AUTHENTICATION_PATH | ncKF_ENCRYPT"
| 512n -> "cKF_DUAL_CRYPTO_OPERATIONS | ncKF_DECRYPT"
| 1024n -> "cKF_TOKEN_INITIALIZED | ncKF_DIGEST"
| 2048n -> "cKF_SECONDARY_AUTHENTICATION | ncKF_SIGN"
| 65536n -> "cKF_USER_PIN_COUNT_LOW | ncKF_GENERATE_KEY_PAIR"
| 131072n -> "cKF_USER_PIN_FINAL_TRY | ncKF_WRAP"
| 262144n -> "cKF_USER_PIN_LOCKED | ncKF_UNWRAP"
| 524288n -> "cKF_USER_PIN_TO_BE_CHANGED | ncKF_DERIVE"
| 1048576n -> "cKF_SO_PIN_COUNT_LOW"
| 2097152n -> "cKF_SO_PIN_FINAL_TRY"
| 4194304n -> "cKF_SO_PIN_LOCKED"
| 8388608n -> "cKF_SO_PIN_TO_BE_CHANGED"
| 4096n -> "cKF_SIGN_RECOVER"
| 8192n -> "cKF_VERIFY"
| 16384n -> "cKF_VERIFY_RECOVER"
| 32768n -> "cKF_GENERATE"
| 2147483648n -> "cKF_EXTENSION"
| _ -> "cKF_UNKNOWN!"
let match_cKO_value a = match a with
| 0n -> "cKO_DATA"
| 1n -> "cKO_CERTIFICATE"
| 2n -> "cKO_PUBLIC_KEY"
| 3n -> "cKO_PRIVATE_KEY"
| 4n -> "cKO_SECRET_KEY"
| 5n -> "cKO_HW_FEATURE"
| 6n -> "cKO_DOMAIN_PARAMETERS"
| 7n -> "cKO_MECHANISM"
| 2147483648n -> "cKO_VENDOR_DEFINED"
| _ -> "cKO_UNKNOWN!"
let match_cKU_value a = match a with
| 0n -> "cKU_SO"
| 1n -> "cKU_USER"
| 2n -> "cKU_CONTEXT_SPECIFIC"
| _ -> "cKU_UNKNOWN!"
let match_cKA_value a = match a with
| 0n -> "cKA_CLASS"
| 1n -> "cKA_TOKEN"
| 2n -> "cKA_PRIVATE"
| 3n -> "cKA_LABEL"
| 16n -> "cKA_APPLICATION"
| 17n -> "cKA_VALUE"
| 18n -> "cKA_OBJECT_ID"
| 128n -> "cKA_CERTIFICATE_TYPE"
| 129n -> "cKA_ISSUER"
| 130n -> "cKA_SERIAL_NUMBER"
| 131n -> "cKA_AC_ISSUER"
| 132n -> "cKA_OWNER"
| 133n -> "cKA_ATTR_TYPES"
| 134n -> "cKA_TRUSTED"
| 135n -> "cKA_CERTIFICATE_CATEGORY"
| 136n -> "cKA_JAVA_MIDP_SECURITY_DOMAIN"
| 137n -> "cKA_URL"
| 138n -> "cKA_HASH_OF_SUBJECT_PUBLIC_KEY"
| 139n -> "cKA_HASH_OF_ISSUER_PUBLIC_KEY"
| 144n -> "cKA_CHECK_VALUE"
| 256n -> "cKA_KEY_TYPE"
| 257n -> "cKA_SUBJECT"
| 258n -> "cKA_ID"
| 259n -> "cKA_SENSITIVE"
| 260n -> "cKA_ENCRYPT"
| 261n -> "cKA_DECRYPT"
| 262n -> "cKA_WRAP"
| 263n -> "cKA_UNWRAP"
| 264n -> "cKA_SIGN"
| 265n -> "cKA_SIGN_RECOVER"
| 266n -> "cKA_VERIFY"
| 267n -> "cKA_VERIFY_RECOVER"
| 268n -> "cKA_DERIVE"
| 272n -> "cKA_START_DATE"
| 273n -> "cKA_END_DATE"
| 288n -> "cKA_MODULUS"
| 289n -> "cKA_MODULUS_BITS"
| 290n -> "cKA_PUBLIC_EXPONENT"
| 291n -> "cKA_PRIVATE_EXPONENT"
| 292n -> "cKA_PRIME_1"
| 293n -> "cKA_PRIME_2"
| 294n -> "cKA_EXPONENT_1"
| 295n -> "cKA_EXPONENT_2"
| 296n -> "cKA_COEFFICIENT"
| 304n -> "cKA_PRIME"
| 305n -> "cKA_SUBPRIME"
| 306n -> "cKA_BASE"
| 307n -> "cKA_PRIME_BITS"
| 308n -> "cKA_SUB_PRIME_BITS"
| 352n -> "cKA_VALUE_BITS"
| 353n -> "cKA_VALUE_LEN"
| 354n -> "cKA_EXTRACTABLE"
| 355n -> "cKA_LOCAL"
| 356n -> "cKA_NEVER_EXTRACTABLE"
| 357n -> "cKA_ALWAYS_SENSITIVE"
| 358n -> "cKA_KEY_GEN_MECHANISM"
| 368n -> "cKA_MODIFIABLE"
| 384n -> "cKA_EC_PARAMS"
| 385n -> "cKA_EC_POINT"
| 512n -> "cKA_SECONDARY_AUTH"
| 513n -> "cKA_AUTH_PIN_FLAGS"
| 514n -> "cKA_ALWAYS_AUTHENTICATE"
| 528n -> "cKA_WRAP_WITH_TRUSTED"
| 544n -> "cKA_OTP_FORMAT"
| 545n -> "cKA_OTP_LENGTH"
| 546n -> "cKA_OTP_TIME_INTERVAL"
| 547n -> "cKA_OTP_USER_FRIENDLY_MODE"
| 548n -> "cKA_OTP_CHALLENGE_REQUIREMENT"
| 549n -> "cKA_OTP_TIME_REQUIREMENT"
| 550n -> "cKA_OTP_COUNTER_REQUIREMENT"
| 551n -> "cKA_OTP_PIN_REQUIREMENT"
| 552n -> "cKA_OTP_COUNTER"
| 553n -> "cKA_OTP_TIME"
| 554n -> "cKA_OTP_USER_IDENTIFIER"
| 555n -> "cKA_OTP_SERVICE_IDENTIFIER"
| 556n -> "cKA_OTP_SERVICE_LOGO"
| 557n -> "cKA_OTP_SERVICE_LOGO_TYPE"
| 768n -> "cKA_HW_FEATURE_TYPE"
| 769n -> "cKA_RESET_ON_INIT"
| 770n -> "cKA_HAS_RESET"
| 1024n -> "cKA_PIXEL_X"
| 1025n -> "cKA_PIXEL_Y"
| 1026n -> "cKA_RESOLUTION"
| 1027n -> "cKA_CHAR_ROWS"
| 1028n -> "cKA_CHAR_COLUMNS"
| 1029n -> "cKA_COLOR"
| 1030n -> "cKA_BITS_PER_PIXEL"
| 1152n -> "cKA_CHAR_SETS"
| 1153n -> "cKA_ENCODING_METHODS"
| 1154n -> "cKA_MIME_TYPES"
| 1280n -> "cKA_MECHANISM_TYPE"
| 1281n -> "cKA_REQUIRED_CMS_ATTRIBUTES"
| 1282n -> "cKA_DEFAULT_CMS_ATTRIBUTES"
| 1283n -> "cKA_SUPPORTED_CMS_ATTRIBUTES"
| 1073742353n -> "cKA_WRAP_TEMPLATE"
| 1073742354n -> "cKA_UNWRAP_TEMPLATE"
| 1073743360n -> "cKA_ALLOWED_MECHANISMS"
| 2147483648n -> "cKA_VENDOR_DEFINED"
| _ -> "cKA_UNKNOWN!"
let match_cKS_value a = match a with
| 0n -> "cKS_RO_PUBLIC_SESSION"
| 1n -> "cKS_RO_USER_FUNCTIONS"
| 2n -> "cKS_RW_PUBLIC_SESSION"
| 3n -> "cKS_RW_USER_FUNCTIONS"
| 4n -> "cKS_RW_SO_FUNCTIONS"
| _ -> "cKS_UNKNOWN!"
let match_cKH_value a = match a with
| 1n -> "cKH_MONOTONIC_COUNTER"
| 2n -> "cKH_CLOCK"
| 3n -> "cKH_USER_INTERFACE"
| 2147483648n -> "cKH_VENDOR_DEFINED"
| _ -> "cKH_UNKNOWN!"
let match_cKK_value a = match a with
| 0n -> "cKK_RSA"
| 1n -> "cKK_DSA"
| 2n -> "cKK_DH"
| 3n -> "cKK_EC"
| 4n -> "cKK_X9_42_DH"
| 5n -> "cKK_KEA"
| 16n -> "cKK_GENERIC_SECRET"
| 17n -> "cKK_RC2"
| 18n -> "cKK_RC4"
| 19n -> "cKK_DES"
| 20n -> "cKK_DES2"
| 21n -> "cKK_DES3"
| 22n -> "cKK_CAST"
| 23n -> "cKK_CAST3"
| 24n -> "cKK_CAST128"
| 25n -> "cKK_RC5"
| 26n -> "cKK_IDEA"
| 27n -> "cKK_SKIPJACK"
| 28n -> "cKK_BATON"
| 29n -> "cKK_JUNIPER"
| 30n -> "cKK_CDMF"
| 31n -> "cKK_AES"
| 32n -> "cKK_BLOWFISH"
| 33n -> "cKK_TWOFISH"
| 2147483648n -> "cKK_VENDOR_DEFINED"
| _ -> "cKK_UNKNOWN!"
let match_cKC_value a = match a with
| 0n -> "cKC_X_509"
| 1n -> "cKC_X_509_ATTR_CERT"
| 2n -> "cKC_WTLS"
| 2147483648n -> "cKC_VENDOR_DEFINED"
| _ -> "cKC_UNKNOWN!"
let char_array_to_string = fun a -> let s = String.create (Array.length a) in

  Array.iteri (fun i x -> String.set s i x) a; s;;

let string_to_char_array = fun s -> Array.init (String.length s) (fun i -> s.[i]);;

let print_int_array = fun a -> Printf.printf "'"; Array.iter (fun str -> Printf.printf "%s " (Nativeint.to_string str)) a; Printf.printf "'\n";;
let print_char_array = fun a -> Printf.printf "'"; Array.iter (Printf.printf "%c") a; Printf.printf "'\n";;
let print_string_array = fun a -> Printf.printf "'"; Array.iter (Printf.printf "%s | ") a; Printf.printf "'\n";;
let print_hex = fun a -> Printf.printf "%02x" (int_of_char a);;
let print_hex_array = fun a -> Printf.printf "'"; Array.iter print_hex a; Printf.printf "'\n";;
let int_to_hexchar (i : nativeint) : char =
   match i with
     0n -> '0'
   | 1n -> '1'
   | 2n -> '2'
   | 3n -> '3'
   | 4n -> '4'
   | 5n -> '5'
   | 6n -> '6'
   | 7n -> '7'
   | 8n -> '8'
   | 9n -> '9'
   | 10n -> 'a'
   | 11n -> 'b'
   | 12n -> 'c'
   | 13n -> 'd'
   | 14n -> 'e'
   | 15n -> 'f'
   | _ -> failwith "int_to_hexchar";;

let hexchar_to_int (c : char) : nativeint =
   match c with
     '0' -> 0n
   | '1' -> 1n
   | '2' -> 2n
   | '3' -> 3n
   | '4' -> 4n
   | '5' -> 5n
   | '6' -> 6n
   | '7' -> 7n
   | '8' -> 8n
   | '9' -> 9n
   | 'a' -> 10n
   | 'b' -> 11n
   | 'c' -> 12n
   | 'd' -> 13n
   | 'e' -> 14n
   | 'f' -> 15n
   | 'A' -> 10n
   | 'B' -> 11n
   | 'C' -> 12n
   | 'D' -> 13n
   | 'E' -> 14n
   | 'F' -> 15n
   | _ -> failwith "hexchar_to_int";;

let merge_nibbles niba nibb =
    let ciba = hexchar_to_int nibb in
    let cibb = hexchar_to_int niba in
    let res = (Nativeint.shift_left cibb 4) in
    let res = (Nativeint.logxor res ciba) in
    let res = Char.chr (Nativeint.to_int res) in
    (res);;
let pack hexstr =
     let len = String.length hexstr in
     let half_len = len / 2 in
     let res = String.create half_len in
     let j = ref 0 in
     for i = 0 to len - 2 do
        if (i mod 2 == 0) then
          (
          let tmp = merge_nibbles hexstr.[i] hexstr.[i+1] in
          res.[!j] <- tmp;
          j := !j +1;
          )
     done;
     (res);;
let sprint_hex_array myarray =
  let s = Array.fold_left (
    fun a elem -> Printf.sprintf "%s%02x" a (int_of_char elem);
  ) "'" myarray in
  (Printf.sprintf "%s'" s)

let bool_to_char_array boolean_attribute =
  if compare boolean_attribute cK_FALSE = 0 then
    ([| (Char.chr 0) |])
  else
    ([| (Char.chr 1) |])

let char_array_to_bool char_array =
  let check = Array.fold_left (
    fun curr_check elem ->
      if compare elem (Char.chr 0) = 0 then
        (curr_check || false)
      else
        (curr_check || true)
    ) false char_array in
  if compare check false = 0 then
    (cK_FALSE)
  else
    (cK_TRUE)

let sprint_bool_attribute_value attribute_value =
  if compare attribute_value cK_TRUE = 0 then
    ("TRUE")
  else
    if compare attribute_value cK_FALSE = 0 then
      ("FALSE")
    else
      ("UNKNOWN!")

let sprint_template_array template_array =
  let string_ = Array.fold_left
    (fun curr_string templ ->
       let s1 = Printf.sprintf "(%s, " (match_cKA_value templ.type_) in
       let s2 = Printf.sprintf "%s) " (sprint_hex_array templ.value) in
       (String.concat "" [curr_string; s1; s2])
  ) "" template_array in
  (string_)
external mL_CK_C_Daemonize : char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Daemonize"

external mL_CK_C_SetupArch : nativeint -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SetupArch"

external mL_CK_C_LoadModule : char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_LoadModule"

external mL_CK_C_Initialize : unit -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Initialize"

external mL_CK_C_Finalize : unit -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Finalize"

external mL_CK_C_GetSlotList : nativeint -> nativeint -> ck_rv_t * ck_slot_id_t array * nativeint
	= "camlidl_pkcs11_ML_CK_C_GetSlotList"

external mL_CK_C_GetInfo : unit -> ck_rv_t * ck_info
	= "camlidl_pkcs11_ML_CK_C_GetInfo"

external mL_CK_C_WaitForSlotEvent : ck_flags_t -> ck_rv_t * ck_slot_id_t
	= "camlidl_pkcs11_ML_CK_C_WaitForSlotEvent"

external mL_CK_C_GetSlotInfo : ck_slot_id_t -> ck_rv_t * ck_slot_info
	= "camlidl_pkcs11_ML_CK_C_GetSlotInfo"

external mL_CK_C_GetTokenInfo : ck_slot_id_t -> ck_rv_t * ck_token_info
	= "camlidl_pkcs11_ML_CK_C_GetTokenInfo"

external mL_CK_C_InitToken : ck_slot_id_t -> char array -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_InitToken"

external mL_CK_C_OpenSession : ck_slot_id_t -> ck_flags_t -> ck_rv_t * ck_session_handle_t
	= "camlidl_pkcs11_ML_CK_C_OpenSession"

external mL_CK_C_CloseSession : ck_session_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_CloseSession"

external mL_CK_C_CloseAllSessions : ck_slot_id_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_CloseAllSessions"

external mL_CK_C_GetSessionInfo : ck_session_handle_t -> ck_rv_t * ck_session_info
	= "camlidl_pkcs11_ML_CK_C_GetSessionInfo"

external mL_CK_C_Login : ck_session_handle_t -> ck_user_type_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Login"

external mL_CK_C_Logout : ck_session_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Logout"

external mL_CK_C_GetMechanismList : ck_slot_id_t -> nativeint -> ck_rv_t * ck_mechanism_type_t array * nativeint
	= "camlidl_pkcs11_ML_CK_C_GetMechanismList"

external mL_CK_C_GetMechanismInfo : ck_slot_id_t -> ck_mechanism_type_t -> ck_rv_t * ck_mechanism_info
	= "camlidl_pkcs11_ML_CK_C_GetMechanismInfo"

external mL_CK_C_InitPIN : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_InitPIN"

external mL_CK_C_SetPIN : ck_session_handle_t -> char array -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SetPIN"

external mL_CK_C_SeedRandom : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SeedRandom"

external mL_CK_C_GenerateRandom : ck_session_handle_t -> nativeint -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_GenerateRandom"

external mL_CK_C_FindObjectsInit : ck_session_handle_t -> ck_attribute array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_FindObjectsInit"

external mL_CK_C_FindObjects : ck_session_handle_t -> nativeint -> ck_rv_t * ck_object_handle_t array * nativeint
	= "camlidl_pkcs11_ML_CK_C_FindObjects"

external mL_CK_C_FindObjectsFinal : ck_session_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_FindObjectsFinal"

external mL_CK_C_GenerateKey : ck_session_handle_t -> ck_mechanism -> ck_attribute array -> ck_rv_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_GenerateKey"

external mL_CK_C_GenerateKeyPair : ck_session_handle_t -> ck_mechanism -> ck_attribute array -> ck_attribute array -> ck_rv_t * ck_object_handle_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_GenerateKeyPair"

external mL_CK_C_CreateObject : ck_session_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_CreateObject"

external mL_CK_C_CopyObject : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_CopyObject"

external mL_CK_C_DestroyObject : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_DestroyObject"

external mL_CK_C_GetAttributeValue : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_attribute array
	= "camlidl_pkcs11_ML_CK_C_GetAttributeValue"

external mL_CK_C_SetAttributeValue : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SetAttributeValue"

external mL_CK_C_GetObjectSize : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t * nativeint
	= "camlidl_pkcs11_ML_CK_C_GetObjectSize"

external mL_CK_C_WrapKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_object_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_WrapKey"

external mL_CK_C_UnwrapKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> char array -> ck_attribute array -> ck_rv_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_UnwrapKey"

external mL_CK_C_DeriveKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
	= "camlidl_pkcs11_ML_CK_C_DeriveKey"

external mL_CK_C_DigestInit : ck_session_handle_t -> ck_mechanism -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_DigestInit"

external mL_CK_C_Digest : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_Digest"

external mL_CK_C_DigestUpdate : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_DigestUpdate"

external mL_CK_C_DigestKey : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_DigestKey"

external mL_CK_C_DigestFinal : ck_session_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DigestFinal"

external mL_CK_C_SignInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SignInit"

external mL_CK_C_SignRecoverInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SignRecoverInit"

external mL_CK_C_Sign : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_Sign"

external mL_CK_C_SignRecover : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_SignRecover"

external mL_CK_C_SignUpdate : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SignUpdate"

external mL_CK_C_SignFinal : ck_session_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_SignFinal"

external mL_CK_C_VerifyInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_VerifyInit"

external mL_CK_C_VerifyRecoverInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_VerifyRecoverInit"

external mL_CK_C_Verify : ck_session_handle_t -> char array -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_Verify"

external mL_CK_C_VerifyRecover : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_VerifyRecover"

external mL_CK_C_VerifyUpdate : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_VerifyUpdate"

external mL_CK_C_VerifyFinal : ck_session_handle_t -> char array -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_VerifyFinal"

external mL_CK_C_EncryptInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_EncryptInit"

external mL_CK_C_Encrypt : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_Encrypt"

external mL_CK_C_EncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_EncryptUpdate"

external mL_CK_C_EncryptFinal : ck_session_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_EncryptFinal"

external mL_CK_C_DigestEncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DigestEncryptUpdate"

external mL_CK_C_SignEncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_SignEncryptUpdate"

external mL_CK_C_DecryptInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_DecryptInit"

external mL_CK_C_Decrypt : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_Decrypt"

external mL_CK_C_DecryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DecryptUpdate"

external mL_CK_C_DecryptFinal : ck_session_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DecryptFinal"

external mL_CK_C_DecryptDigestUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DecryptDigestUpdate"

external mL_CK_C_DecryptVerifyUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_DecryptVerifyUpdate"

external mL_CK_C_GetOperationState : ck_session_handle_t -> ck_rv_t * char array
	= "camlidl_pkcs11_ML_CK_C_GetOperationState"

external mL_CK_C_SetOperationState : ck_session_handle_t -> char array -> ck_object_handle_t -> ck_object_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_SetOperationState"

external mL_CK_C_GetFunctionStatus : ck_session_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_GetFunctionStatus"

external mL_CK_C_CancelFunction : ck_session_handle_t -> ck_rv_t
	= "camlidl_pkcs11_ML_CK_C_CancelFunction"

external int_to_ulong_char_array : nativeint -> char array
	= "camlidl_pkcs11_int_to_ulong_char_array"

external char_array_to_ulong : char array -> nativeint
	= "camlidl_pkcs11_char_array_to_ulong"

external hton_char_array : char array -> char array
	= "camlidl_pkcs11_hton_char_array"

external ntoh_char_array : char array -> char array
	= "camlidl_pkcs11_ntoh_char_array"

let c_Daemonize = fun param -> mL_CK_C_Daemonize param
let c_SetupArch = fun arch -> mL_CK_C_SetupArch arch
let c_LoadModule = fun path -> mL_CK_C_LoadModule path
let c_Initialize () =  mL_CK_C_Initialize ()
let c_GetInfo () = mL_CK_C_GetInfo ()
let c_GetSlotList = fun token_present count -> mL_CK_C_GetSlotList token_present count
let c_GetSlotInfo = fun ckslotidt_ -> mL_CK_C_GetSlotInfo ckslotidt_
let c_GetTokenInfo = fun ckslotidt_ -> mL_CK_C_GetTokenInfo ckslotidt_
let c_WaitForSlotEvent = fun ckflagst_ -> mL_CK_C_WaitForSlotEvent ckflagst_ 
let c_GetMechanismList = fun ckslotidt_ count -> mL_CK_C_GetMechanismList ckslotidt_ count 
let c_GetMechanismInfo = fun ckslotidt_ ckmechanismtypet_ -> mL_CK_C_GetMechanismInfo ckslotidt_ ckmechanismtypet_ 
let c_InitToken = fun ckslotidt_  so_pin label -> mL_CK_C_InitToken ckslotidt_  so_pin label 
let c_InitPIN = fun cksessionhandlet_ pin -> mL_CK_C_InitPIN cksessionhandlet_ pin 
let c_SetPIN = fun cksessionhandlet_ old_pin  new_pin -> mL_CK_C_SetPIN cksessionhandlet_ old_pin  new_pin 
let c_OpenSession = fun ckslotid_ ckflagst_ -> mL_CK_C_OpenSession ckslotid_ ckflagst_
let c_CloseSession = fun cksessionhandlet_ -> mL_CK_C_CloseSession cksessionhandlet_ 
let c_CloseAllSessions = fun ckslotidt_ -> mL_CK_C_CloseAllSessions ckslotidt_ 
let c_GetSessionInfo = fun cksessionhandlet_ -> mL_CK_C_GetSessionInfo cksessionhandlet_ 
let c_GetOperationState = fun cksessionhandlet_ -> mL_CK_C_GetOperationState cksessionhandlet_ 
let c_SetOperationState = fun cksessionhandlet_ state encryption_handle authentication_handle -> mL_CK_C_SetOperationState cksessionhandlet_ state encryption_handle authentication_handle
let c_Login = fun cksessionhandlet_ ckusertypet_ pin -> mL_CK_C_Login cksessionhandlet_ ckusertypet_ pin 
let c_Logout = fun cksessionhandlet -> mL_CK_C_Logout cksessionhandlet 
let c_Finalize () = mL_CK_C_Finalize ()
let c_CreateObject = fun cksessionhandlet_ ckattributearray_  -> mL_CK_C_CreateObject cksessionhandlet_ ckattributearray_ 
let c_CopyObject = fun cksessionhandlet_ ckobjecthandlet_ ckattributearray_  -> mL_CK_C_CopyObject cksessionhandlet_ ckobjecthandlet_ ckattributearray_
let c_DestroyObject = fun cksessionhandlet_ ckobjecthandlet_ -> mL_CK_C_DestroyObject cksessionhandlet_ ckobjecthandlet_ 
let c_GetObjectSize = fun cksessionhandlet_ ckobjecthandlet_  -> mL_CK_C_GetObjectSize cksessionhandlet_ ckobjecthandlet_  
let c_GetAttributeValue = fun cksessionhandlet_ ckobjecthandlet_ ckattributearray_ -> mL_CK_C_GetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_ 
let c_SetAttributeValue = fun cksessionhandlet_ ckobjecthandlet_ ckattributearray_ -> mL_CK_C_SetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_ 
let c_FindObjectsInit = fun cksessionhandlet_ ckattributearray_ -> mL_CK_C_FindObjectsInit cksessionhandlet_ ckattributearray_ 
let c_FindObjects = fun cksessionhandlet_ count -> mL_CK_C_FindObjects cksessionhandlet_ count 
let c_FindObjectsFinal = fun cksessionhandlet_ -> mL_CK_C_FindObjectsFinal cksessionhandlet_ 
let c_EncryptInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_EncryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 
let c_Encrypt = fun cksessionhandlet_ data  -> mL_CK_C_Encrypt cksessionhandlet_ data  
let c_EncryptUpdate = fun cksessionhandlet_ data  -> mL_CK_C_EncryptUpdate cksessionhandlet_ data  
let c_EncryptFinal = fun cksessionhandlet_  -> mL_CK_C_EncryptFinal cksessionhandlet_ 
let c_DecryptInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_DecryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
let c_Decrypt = fun cksessionhandlet_ data  -> mL_CK_C_Decrypt cksessionhandlet_ data 
let c_DecryptUpdate = fun cksessionhandlet_ data  -> mL_CK_C_DecryptUpdate cksessionhandlet_ data 
let c_DecryptFinal = fun cksessionhandlet_ -> mL_CK_C_DecryptFinal cksessionhandlet_ 
let c_DigestInit = fun cksessionhandlet_ ckmechanism_  -> mL_CK_C_DigestInit cksessionhandlet_ ckmechanism_  
let c_Digest = fun cksessionhandlet_ data   -> mL_CK_C_Digest cksessionhandlet_ data  
let c_DigestUpdate = fun cksessionhandlet_ data   -> mL_CK_C_DigestUpdate cksessionhandlet_ data  
let c_DigestKey = fun cksessionhandlet_ ckobjecthandlet_  -> mL_CK_C_DigestKey cksessionhandlet_ ckobjecthandlet_  
let c_DigestFinal = fun cksessionhandlet -> mL_CK_C_DigestFinal cksessionhandlet 
let c_SignInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_SignInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 
let c_SignRecoverInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_SignRecoverInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 
let c_Sign = fun cksessionhandlet_ data  -> mL_CK_C_Sign cksessionhandlet_ data 
let c_SignRecover = fun cksessionhandlet_ data  -> mL_CK_C_SignRecover cksessionhandlet_ data 
let c_SignUpdate = fun cksessionhandlet_ data  -> mL_CK_C_SignUpdate cksessionhandlet_ data 
let c_SignFinal = fun  cksessionhandlet_ -> mL_CK_C_SignFinal  cksessionhandlet_ 
let c_VerifyInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_VerifyInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 
let c_VerifyRecoverInit = fun cksessionhandlet_ ckmechanism_ ckobjecthandlet_ -> mL_CK_C_VerifyRecoverInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 
let c_Verify = fun cksessionhandlet_ data signed_data -> mL_CK_C_Verify cksessionhandlet_ data signed_data 
let c_VerifyRecover = fun cksessionhandlet_ data  -> mL_CK_C_VerifyRecover cksessionhandlet_ data  
let c_VerifyUpdate = fun cksessionhandlet_ data  -> mL_CK_C_VerifyUpdate cksessionhandlet_ data  
let c_VerifyFinal = fun cksessionhandlet_ data  -> mL_CK_C_VerifyFinal cksessionhandlet_ data  
let c_DigestEncryptUpdate = fun cksessionhandlet_ data  -> mL_CK_C_DigestEncryptUpdate cksessionhandlet_ data
let c_DecryptDigestUpdate = fun cksessionhandlet_ data -> mL_CK_C_DecryptDigestUpdate cksessionhandlet_ data 
let c_SignEncryptUpdate = fun cksessionhandlet_ data  -> mL_CK_C_SignEncryptUpdate cksessionhandlet_ data
let c_DecryptVerifyUpdate = fun cksessionhandlet_ data -> mL_CK_C_DecryptVerifyUpdate cksessionhandlet_ data 
let c_GenerateKey = fun cksessionhandlet_ ckmechanism_ ckattributearray_ -> mL_CK_C_GenerateKey cksessionhandlet_ ckmechanism_ ckattributearray_ 
let c_GenerateKeyPair = fun cksessionhandlet_ ckmechanism_ pub_attributes priv_attributes -> mL_CK_C_GenerateKeyPair cksessionhandlet_ ckmechanism_ pub_attributes priv_attributes
let c_WrapKey = fun cksessionhandlet_ ckmechanism_ wrapping_handle wrapped_handle  -> mL_CK_C_WrapKey cksessionhandlet_ ckmechanism_ wrapping_handle wrapped_handle 
let c_UnwrapKey = fun cksessionhandlet_ ckmechanism_ unwrapping_handle wrapped_key ckattributearray_ -> mL_CK_C_UnwrapKey cksessionhandlet_ ckmechanism_ unwrapping_handle wrapped_key ckattributearray_ 
let c_DeriveKey = fun cksessionhandlet_ ckmechanism_ initial_key_handle ckattributearray_ -> mL_CK_C_DeriveKey cksessionhandlet_ ckmechanism_ initial_key_handle ckattributearray_ 
let c_SeedRandom = fun cksessionhandlet_ seed -> mL_CK_C_SeedRandom cksessionhandlet_ seed 
let c_GenerateRandom = fun cksessionhandlet_ count -> mL_CK_C_GenerateRandom cksessionhandlet_ count
let c_GetFunctionStatus = fun cksessionhandlet_  -> mL_CK_C_GetFunctionStatus cksessionhandlet_  
let c_CancelFunction = fun cksessionhandlet_  -> mL_CK_C_CancelFunction cksessionhandlet_  
