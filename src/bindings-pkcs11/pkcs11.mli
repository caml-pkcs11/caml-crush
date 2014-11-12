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

val lITTLE_ENDIAN_64  : nativeint
val lITTLE_ENDIAN_32  : nativeint
val bIG_ENDIAN_64  : nativeint
val bIG_ENDIAN_32  : nativeint
val uNSUPPORTED_ARCHITECTURE  : nativeint
val nOT_INITIALIZED  : nativeint
val match_arch_value : nativeint -> string

val cRYPTOKI_VERSION_MAJOR  : nativeint
val cRYPTOKI_VERSION_MINOR  : nativeint
val cRYPTOKI_VERSION_REVISION : nativeint
val cKN_SURRENDER : nativeint
val cKN_OTP_CHANGED : nativeint
val cKF_TOKEN_PRESENT : nativeint
val cKF_REMOVABLE_DEVICE : nativeint
val cKF_HW_SLOT  : nativeint
val cKF_ARRAY_ATTRIBUTE : nativeint
val cKF_RNG     : nativeint
val cKF_WRITE_PROTECTED   : nativeint
val cKF_LOGIN_REQUIRED   : nativeint
val cKF_USER_PIN_INITIALIZED  : nativeint
val cKF_RESTORE_KEY_NOT_NEEDED  : nativeint
val cKF_CLOCK_ON_TOKEN   : nativeint
val cKF_PROTECTED_AUTHENTICATION_PATH : nativeint
val cKF_DUAL_CRYPTO_OPERATIONS  : nativeint
val cKF_TOKEN_INITIALIZED   : nativeint
val cKF_SECONDARY_AUTHENTICATION  : nativeint
val cKF_USER_PIN_COUNT_LOW   : nativeint
val cKF_USER_PIN_FINAL_TRY   : nativeint
val cKF_USER_PIN_LOCKED   : nativeint
val cKF_USER_PIN_TO_BE_CHANGED  : nativeint
val cKF_SO_PIN_COUNT_LOW   : nativeint
val cKF_SO_PIN_FINAL_TRY   : nativeint
val cKF_SO_PIN_LOCKED   : nativeint
val cKF_SO_PIN_TO_BE_CHANGED  : nativeint
val cK_UNAVAILABLE_INFORMATION : nativeint
val cK_EFFECTIVELY_INFINITE  : nativeint
val cK_INVALID_HANDLE : nativeint
val cKU_SO   : nativeint
val cKU_USER  : nativeint
val cKU_CONTEXT_SPECIFIC : nativeint
val cKS_RO_PUBLIC_SESSION : nativeint
val cKS_RO_USER_FUNCTIONS : nativeint
val cKS_RW_PUBLIC_SESSION : nativeint
val cKS_RW_USER_FUNCTIONS : nativeint
val cKS_RW_SO_FUNCTIONS : nativeint
val cKF_RW_SESSION  : nativeint
val cKF_SERIAL_SESSION : nativeint
val cKO_DATA  : nativeint
val cKO_CERTIFICATE  : nativeint
val cKO_PUBLIC_KEY  : nativeint
val cKO_PRIVATE_KEY  : nativeint
val cKO_SECRET_KEY  : nativeint
val cKO_HW_FEATURE  : nativeint
val cKO_DOMAIN_PARAMETERS : nativeint
val cKO_MECHANISM  : nativeint
val cKO_OTP_KEY : nativeint
val cKO_VENDOR_DEFINED : nativeint
val cKH_MONOTONIC_COUNTER : nativeint
val cKH_CLOCK  : nativeint
val cKH_USER_INTERFACE : nativeint
val cKH_VENDOR_DEFINED : nativeint
val cKK_RSA   : nativeint
val cKK_DSA   : nativeint
val cKK_DH   : nativeint
val cKK_ECDSA  : nativeint
val cKK_EC   : nativeint
val cKK_X9_42_DH  : nativeint
val cKK_KEA   : nativeint
val cKK_GENERIC_SECRET : nativeint
val cKK_RC2   : nativeint
val cKK_RC4   : nativeint
val cKK_DES   : nativeint
val cKK_DES2  : nativeint
val cKK_DES3  : nativeint
val cKK_CAST  : nativeint
val cKK_CAST3  : nativeint
val cKK_CAST128  : nativeint
val cKK_RC5   : nativeint
val cKK_IDEA  : nativeint
val cKK_SKIPJACK  : nativeint
val cKK_BATON  : nativeint
val cKK_JUNIPER  : nativeint
val cKK_CDMF  : nativeint
val cKK_AES   : nativeint
val cKK_BLOWFISH  : nativeint
val cKK_TWOFISH  : nativeint
val cKK_SECURID  : nativeint
val cKK_HOTP  : nativeint
val cKK_ACTI  : nativeint
val cKK_CAMELLIA  : nativeint
val cKK_ARIA  : nativeint
val cKK_VENDOR_DEFINED : nativeint
val cKC_X_509  : nativeint
val cKC_X_509_ATTR_CERT : nativeint
val cKC_WTLS  : nativeint
val cKC_VENDOR_DEFINED : nativeint
val cK_OTP_FORMAT_DECIMAL   : nativeint
val cK_OTP_FORMAT_HEXADECIMAL   : nativeint
val cK_OTP_FORMAT_ALPHANUMERIC   : nativeint
val cK_OTP_PARAM_IGNORED   : nativeint
val cK_OTP_PARAM_OPTIONAL   : nativeint
val cK_OTP_PARAM_MANDATORY   : nativeint
val cKA_CLASS   : nativeint
val cKA_TOKEN   : nativeint
val cKA_PRIVATE   : nativeint
val cKA_LABEL   : nativeint
val cKA_APPLICATION   : nativeint
val cKA_VALUE   : nativeint
val cKA_OBJECT_ID   : nativeint
val cKA_CERTIFICATE_TYPE  : nativeint
val cKA_ISSUER   : nativeint
val cKA_SERIAL_NUMBER  : nativeint
val cKA_AC_ISSUER   : nativeint
val cKA_OWNER   : nativeint
val cKA_ATTR_TYPES   : nativeint
val cKA_TRUSTED   : nativeint
val cKA_CERTIFICATE_CATEGORY : nativeint
val cKA_JAVA_MIDP_SECURITY_DOMAIN : nativeint
val cKA_URL    : nativeint
val cKA_HASH_OF_SUBJECT_PUBLIC_KEY : nativeint
val cKA_HASH_OF_ISSUER_PUBLIC_KEY : nativeint
val cKA_CHECK_VALUE   : nativeint
val cKA_KEY_TYPE   : nativeint
val cKA_SUBJECT   : nativeint
val cKA_ID    : nativeint
val cKA_SENSITIVE   : nativeint
val cKA_ENCRYPT   : nativeint
val cKA_DECRYPT   : nativeint
val cKA_WRAP   : nativeint
val cKA_UNWRAP   : nativeint
val cKA_SIGN   : nativeint
val cKA_SIGN_RECOVER  : nativeint
val cKA_VERIFY   : nativeint
val cKA_VERIFY_RECOVER  : nativeint
val cKA_DERIVE   : nativeint
val cKA_START_DATE   : nativeint
val cKA_END_DATE   : nativeint
val cKA_MODULUS   : nativeint
val cKA_MODULUS_BITS  : nativeint
val cKA_PUBLIC_EXPONENT  : nativeint
val cKA_PRIVATE_EXPONENT  : nativeint
val cKA_PRIME_1   : nativeint
val cKA_PRIME_2   : nativeint
val cKA_EXPONENT_1   : nativeint
val cKA_EXPONENT_2   : nativeint
val cKA_COEFFICIENT   : nativeint
val cKA_PRIME   : nativeint
val cKA_SUBPRIME   : nativeint
val cKA_BASE   : nativeint
val cKA_PRIME_BITS   : nativeint
val cKA_SUB_PRIME_BITS  : nativeint
val cKA_VALUE_BITS   : nativeint
val cKA_VALUE_LEN   : nativeint
val cKA_EXTRACTABLE   : nativeint
val cKA_LOCAL   : nativeint
val cKA_NEVER_EXTRACTABLE  : nativeint
val cKA_ALWAYS_SENSITIVE  : nativeint
val cKA_KEY_GEN_MECHANISM  : nativeint
val cKA_MODIFIABLE   : nativeint
val cKA_ECDSA_PARAMS  : nativeint
val cKA_EC_PARAMS   : nativeint
val cKA_EC_POINT   : nativeint
val cKA_SECONDARY_AUTH  : nativeint
val cKA_AUTH_PIN_FLAGS  : nativeint
val cKA_ALWAYS_AUTHENTICATE  : nativeint
val cKA_WRAP_WITH_TRUSTED  : nativeint
val cKA_OTP_FORMAT  : nativeint
val cKA_OTP_LENGTH  : nativeint
val cKA_OTP_TIME_INTERVAL  : nativeint
val cKA_OTP_USER_FRIENDLY_MODE  : nativeint
val cKA_OTP_CHALLENGE_REQUIREMENT  : nativeint
val cKA_OTP_TIME_REQUIREMENT  : nativeint
val cKA_OTP_COUNTER_REQUIREMENT  : nativeint
val cKA_OTP_PIN_REQUIREMENT  : nativeint
val cKA_OTP_COUNTER  : nativeint
val cKA_OTP_TIME  : nativeint
val cKA_OTP_USER_IDENTIFIER  : nativeint
val cKA_OTP_SERVICE_IDENTIFIER  : nativeint
val cKA_OTP_SERVICE_LOGO  : nativeint
val cKA_OTP_SERVICE_LOGO_TYPE  : nativeint
val cKA_HW_FEATURE_TYPE  : nativeint
val cKA_RESET_ON_INIT  : nativeint
val cKA_HAS_RESET   : nativeint
val cKA_PIXEL_X   : nativeint
val cKA_PIXEL_Y   : nativeint
val cKA_RESOLUTION   : nativeint
val cKA_CHAR_ROWS   : nativeint
val cKA_CHAR_COLUMNS  : nativeint
val cKA_COLOR   : nativeint
val cKA_BITS_PER_PIXEL  : nativeint
val cKA_CHAR_SETS   : nativeint
val cKA_ENCODING_METHODS  : nativeint
val cKA_MIME_TYPES   : nativeint
val cKA_MECHANISM_TYPE  : nativeint
val cKA_REQUIRED_CMS_ATTRIBUTES : nativeint
val cKA_DEFAULT_CMS_ATTRIBUTES : nativeint
val cKA_SUPPORTED_CMS_ATTRIBUTES : nativeint
val cKA_WRAP_TEMPLATE  : nativeint
val cKA_UNWRAP_TEMPLATE  : nativeint
val cKA_ALLOWED_MECHANISMS  : nativeint
val cKA_VENDOR_DEFINED  : nativeint
val cKM_RSA_PKCS_KEY_PAIR_GEN : nativeint
val cKM_RSA_PKCS   : nativeint
val cKM_RSA_9796   : nativeint
val cKM_RSA_X_509   : nativeint
val cKM_MD2_RSA_PKCS  : nativeint
val cKM_MD5_RSA_PKCS  : nativeint
val cKM_SHA1_RSA_PKCS  : nativeint
val cKM_RIPEMD128_RSA_PKCS  : nativeint
val cKM_RIPEMD160_RSA_PKCS  : nativeint
val cKM_RSA_PKCS_OAEP  : nativeint
val cKM_RSA_X9_31_KEY_PAIR_GEN : nativeint
val cKM_RSA_X9_31   : nativeint
val cKM_SHA1_RSA_X9_31  : nativeint
val cKM_RSA_PKCS_PSS  : nativeint
val cKM_SHA1_RSA_PKCS_PSS  : nativeint
val cKM_DSA_KEY_PAIR_GEN  : nativeint
val cKM_DSA    : nativeint
val cKM_DSA_SHA1   : nativeint
val cKM_DH_PKCS_KEY_PAIR_GEN : nativeint
val cKM_DH_PKCS_DERIVE  : nativeint
val cKM_X9_42_DH_KEY_PAIR_GEN : nativeint
val cKM_X9_42_DH_DERIVE  : nativeint
val cKM_X9_42_DH_HYBRID_DERIVE : nativeint
val cKM_X9_42_MQV_DERIVE  : nativeint
val cKM_SHA256_RSA_PKCS  : nativeint
val cKM_SHA384_RSA_PKCS  : nativeint
val cKM_SHA512_RSA_PKCS  : nativeint
val cKM_SHA224_RSA_PKCS  : nativeint
val cKM_SHA256_RSA_PKCS_PSS  : nativeint
val cKM_SHA384_RSA_PKCS_PSS  : nativeint
val cKM_SHA512_RSA_PKCS_PSS  : nativeint
val cKM_SHA224_RSA_PKCS_PSS  : nativeint
val cKM_RC2_KEY_GEN   : nativeint
val cKM_RC2_ECB   : nativeint
val cKM_RC2_CBC   : nativeint
val cKM_RC2_MAC   : nativeint
val cKM_RC2_MAC_GENERAL  : nativeint
val cKM_RC2_CBC_PAD   : nativeint
val cKM_RC4_KEY_GEN   : nativeint
val cKM_RC4    : nativeint
val cKM_DES_KEY_GEN   : nativeint
val cKM_DES_ECB   : nativeint
val cKM_DES_CBC   : nativeint
val cKM_DES_MAC   : nativeint
val cKM_DES_MAC_GENERAL  : nativeint
val cKM_DES_CBC_PAD   : nativeint
val cKM_DES2_KEY_GEN  : nativeint
val cKM_DES3_KEY_GEN  : nativeint
val cKM_DES3_ECB   : nativeint
val cKM_DES3_CBC   : nativeint
val cKM_DES3_MAC   : nativeint
val cKM_DES3_MAC_GENERAL  : nativeint
val cKM_DES3_CBC_PAD  : nativeint
val cKM_CDMF_KEY_GEN  : nativeint
val cKM_CDMF_ECB   : nativeint
val cKM_CDMF_CBC   : nativeint
val cKM_CDMF_MAC   : nativeint
val cKM_CDMF_MAC_GENERAL  : nativeint
val cKM_CDMF_CBC_PAD  : nativeint
val cKM_MD2    : nativeint
val cKM_MD2_HMAC   : nativeint
val cKM_MD2_HMAC_GENERAL  : nativeint
val cKM_MD5    : nativeint
val cKM_MD5_HMAC   : nativeint
val cKM_MD5_HMAC_GENERAL  : nativeint
val cKM_SHA_1   : nativeint
val cKM_SHA_1_HMAC   : nativeint
val cKM_SHA_1_HMAC_GENERAL  : nativeint
val cKM_RIPEMD128   : nativeint
val cKM_RIPEMD128_HMAC  : nativeint
val cKM_RIPEMD128_HMAC_GENERAL : nativeint
val cKM_RIPEMD160   : nativeint
val cKM_RIPEMD160_HMAC  : nativeint
val cKM_RIPEMD160_HMAC_GENERAL : nativeint
val cKM_SHA256   : nativeint
val cKM_SHA256_HMAC   : nativeint
val cKM_SHA256_HMAC_GENERAL  : nativeint
val cKM_SHA384   : nativeint
val cKM_SHA384_HMAC   : nativeint
val cKM_SHA384_HMAC_GENERAL  : nativeint
val cKM_SHA512   : nativeint
val cKM_SHA512_HMAC   : nativeint
val cKM_SHA512_HMAC_GENERAL  : nativeint
val cKM_SHA224   : nativeint
val cKM_SHA224_HMAC   : nativeint
val cKM_SHA224_HMAC_GENERAL  : nativeint
val cKM_SECURID_KEY_GEN  : nativeint
val cKM_SECURID  : nativeint
val cKM_HOTP_KEY_GEN  : nativeint
val cKM_HOTP  : nativeint
val cKM_ACTI_KEY_GEN  : nativeint
val cKM_ACTI  : nativeint
val cKM_CAST_KEY_GEN  : nativeint
val cKM_CAST_ECB   : nativeint
val cKM_CAST_CBC   : nativeint
val cKM_CAST_MAC   : nativeint
val cKM_CAST_MAC_GENERAL  : nativeint
val cKM_CAST_CBC_PAD  : nativeint
val cKM_CAST3_KEY_GEN  : nativeint
val cKM_CAST3_ECB   : nativeint
val cKM_CAST3_CBC   : nativeint
val cKM_CAST3_MAC   : nativeint
val cKM_CAST3_MAC_GENERAL  : nativeint
val cKM_CAST3_CBC_PAD  : nativeint
val cKM_CAST5_KEY_GEN  : nativeint
val cKM_CAST128_KEY_GEN  : nativeint
val cKM_CAST5_ECB   : nativeint
val cKM_CAST128_ECB   : nativeint
val cKM_CAST5_CBC   : nativeint
val cKM_CAST128_CBC   : nativeint
val cKM_CAST5_MAC   : nativeint
val cKM_CAST128_MAC   : nativeint
val cKM_CAST5_MAC_GENERAL  : nativeint
val cKM_CAST128_MAC_GENERAL  : nativeint
val cKM_CAST5_CBC_PAD  : nativeint
val cKM_CAST128_CBC_PAD  : nativeint
val cKM_RC5_KEY_GEN   : nativeint
val cKM_RC5_ECB   : nativeint
val cKM_RC5_CBC   : nativeint
val cKM_RC5_MAC   : nativeint
val cKM_RC5_MAC_GENERAL  : nativeint
val cKM_RC5_CBC_PAD   : nativeint
val cKM_IDEA_KEY_GEN  : nativeint
val cKM_IDEA_ECB   : nativeint
val cKM_IDEA_CBC   : nativeint
val cKM_IDEA_MAC   : nativeint
val cKM_IDEA_MAC_GENERAL  : nativeint
val cKM_IDEA_CBC_PAD  : nativeint
val cKM_GENERIC_SECRET_KEY_GEN : nativeint
val cKM_CONCATENATE_BASE_AND_KEY : nativeint
val cKM_CONCATENATE_BASE_AND_DATA : nativeint
val cKM_CONCATENATE_DATA_AND_BASE : nativeint
val cKM_XOR_BASE_AND_DATA  : nativeint
val cKM_EXTRACT_KEY_FROM_KEY : nativeint
val cKM_SSL3_PRE_MASTER_KEY_GEN : nativeint
val cKM_SSL3_MASTER_KEY_DERIVE : nativeint
val cKM_SSL3_KEY_AND_MAC_DERIVE : nativeint
val cKM_SSL3_MASTER_KEY_DERIVE_DH : nativeint
val cKM_TLS_PRE_MASTER_KEY_GEN : nativeint
val cKM_TLS_MASTER_KEY_DERIVE : nativeint
val cKM_TLS_KEY_AND_MAC_DERIVE : nativeint
val cKM_TLS_MASTER_KEY_DERIVE_DH : nativeint
val cKM_TLS_PRF  : nativeint
val cKM_SSL3_MD5_MAC  : nativeint
val cKM_SSL3_SHA1_MAC  : nativeint
val cKM_MD5_KEY_DERIVATION  : nativeint
val cKM_MD2_KEY_DERIVATION  : nativeint
val cKM_SHA1_KEY_DERIVATION  : nativeint
val cKM_SHA256_KEY_DERIVATION  : nativeint
val cKM_SHA384_KEY_DERIVATION  : nativeint
val cKM_SHA512_KEY_DERIVATION  : nativeint
val cKM_SHA224_KEY_DERIVATION  : nativeint
val cKM_PBE_MD2_DES_CBC  : nativeint
val cKM_PBE_MD5_DES_CBC  : nativeint
val cKM_PBE_MD5_CAST_CBC  : nativeint
val cKM_PBE_MD5_CAST3_CBC  : nativeint
val cKM_PBE_MD5_CAST5_CBC  : nativeint
val cKM_PBE_MD5_CAST128_CBC  : nativeint
val cKM_PBE_SHA1_CAST5_CBC  : nativeint
val cKM_PBE_SHA1_CAST128_CBC : nativeint
val cKM_PBE_SHA1_RC4_128  : nativeint
val cKM_PBE_SHA1_RC4_40  : nativeint
val cKM_PBE_SHA1_DES3_EDE_CBC : nativeint
val cKM_PBE_SHA1_DES2_EDE_CBC : nativeint
val cKM_PBE_SHA1_RC2_128_CBC : nativeint
val cKM_PBE_SHA1_RC2_40_CBC  : nativeint
val cKM_PKCS5_PBKD2   : nativeint
val cKM_PBA_SHA1_WITH_SHA1_HMAC : nativeint
val cKM_WTLS_PRE_MASTER_KEY_GEN : nativeint
val cKM_WTLS_MASTER_KEY_DERIVE : nativeint
val cKM_WTLS_MASTER_KEY_DERIVE_DH_ECC : nativeint
val cKM_WTLS_PRF : nativeint
val cKM_WTLS_SERVER_KEY_AND_MAC_DERIVE : nativeint
val cKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE : nativeint
val cKM_KEY_WRAP_LYNKS  : nativeint
val cKM_KEY_WRAP_SET_OAEP  : nativeint
val cKM_CMS_SIG : nativeint
val cKM_KIP_DERIVE : nativeint
val cKM_KIP_WRAP : nativeint
val cKM_KIP_MAC : nativeint
val cKM_CAMELLIA_KEY_GEN : nativeint
val cKM_CAMELLIA_ECB : nativeint
val cKM_CAMELLIA_CBC : nativeint
val cKM_CAMELLIA_MAC : nativeint
val cKM_CAMELLIA_MAC_GENERAL : nativeint
val cKM_CAMELLIA_CBC_PAD : nativeint
val cKM_CAMELLIA_ECB_ENCRYPT_DATA : nativeint
val cKM_CAMELLIA_CBC_ENCRYPT_DATA : nativeint
val cKM_CAMELLIA_CTR : nativeint
val cKM_ARIA_KEY_GEN : nativeint
val cKM_ARIA_ECB : nativeint
val cKM_ARIA_CBC : nativeint
val cKM_ARIA_MAC : nativeint
val cKM_ARIA_MAC_GENERAL : nativeint
val cKM_ARIA_CBC_PAD : nativeint
val cKM_ARIA_ECB_ENCRYPT_DATA : nativeint
val cKM_ARIA_CBC_ENCRYPT_DATA : nativeint
val cKM_SKIPJACK_KEY_GEN  : nativeint
val cKM_SKIPJACK_ECB64  : nativeint
val cKM_SKIPJACK_CBC64  : nativeint
val cKM_SKIPJACK_OFB64  : nativeint
val cKM_SKIPJACK_CFB64  : nativeint
val cKM_SKIPJACK_CFB32  : nativeint
val cKM_SKIPJACK_CFB16  : nativeint
val cKM_SKIPJACK_CFB8  : nativeint
val cKM_SKIPJACK_WRAP  : nativeint
val cKM_SKIPJACK_PRIVATE_WRAP : nativeint
val cKM_SKIPJACK_RELAYX  : nativeint
val cKM_KEA_KEY_PAIR_GEN  : nativeint
val cKM_KEA_KEY_DERIVE  : nativeint
val cKM_FORTEZZA_TIMESTAMP  : nativeint
val cKM_BATON_KEY_GEN  : nativeint
val cKM_BATON_ECB128  : nativeint
val cKM_BATON_ECB96   : nativeint
val cKM_BATON_CBC128  : nativeint
val cKM_BATON_COUNTER  : nativeint
val cKM_BATON_SHUFFLE  : nativeint
val cKM_BATON_WRAP   : nativeint
val cKM_ECDSA_KEY_PAIR_GEN  : nativeint
val cKM_EC_KEY_PAIR_GEN  : nativeint
val cKM_ECDSA   : nativeint
val cKM_ECDSA_SHA1   : nativeint
val cKM_ECDH1_DERIVE  : nativeint
val cKM_ECDH1_COFACTOR_DERIVE : nativeint
val cKM_ECMQV_DERIVE  : nativeint
val cKM_JUNIPER_KEY_GEN  : nativeint
val cKM_JUNIPER_ECB128  : nativeint
val cKM_JUNIPER_CBC128  : nativeint
val cKM_JUNIPER_COUNTER  : nativeint
val cKM_JUNIPER_SHUFFLE  : nativeint
val cKM_JUNIPER_WRAP  : nativeint
val cKM_FASTHASH   : nativeint
val cKM_AES_KEY_GEN   : nativeint
val cKM_AES_ECB   : nativeint
val cKM_AES_CBC   : nativeint
val cKM_AES_MAC   : nativeint
val cKM_AES_MAC_GENERAL  : nativeint
val cKM_AES_CBC_PAD   : nativeint
val cKM_AES_CTR   : nativeint
val cKM_BLOWFISH_KEY_GEN : nativeint
val cKM_BLOWFISH_CBC : nativeint
val cKM_TWOFISH_KEY_GEN : nativeint
val cKM_TWOFISH_CBC : nativeint
val cKM_DES_ECB_ENCRYPT_DATA : nativeint
val cKM_DES_CBC_ENCRYPT_DATA : nativeint
val cKM_DES3_ECB_ENCRYPT_DATA : nativeint
val cKM_DES3_CBC_ENCRYPT_DATA : nativeint
val cKM_AES_ECB_ENCRYPT_DATA : nativeint
val cKM_AES_CBC_ENCRYPT_DATA : nativeint
val cKM_DSA_PARAMETER_GEN  : nativeint
val cKM_DH_PKCS_PARAMETER_GEN : nativeint
val cKM_X9_42_DH_PARAMETER_GEN : nativeint
val cKM_VENDOR_DEFINED  : nativeint
val cKF_HW   : nativeint
val cKF_ENCRYPT  : nativeint
val cKF_DECRYPT  : nativeint
val cKF_DIGEST  : nativeint
val cKF_SIGN  : nativeint
val cKF_SIGN_RECOVER : nativeint
val cKF_VERIFY  : nativeint
val cKF_VERIFY_RECOVER : nativeint
val cKF_GENERATE  : nativeint
val cKF_GENERATE_KEY_PAIR : nativeint
val cKF_WRAP  : nativeint
val cKF_UNWRAP  : nativeint
val cKF_DERIVE  : nativeint
val cKF_EC_F_P  : nativeint
val cKF_EC_F_2M  : nativeint
val cKF_EC_ECPARAMETERS  : nativeint
val cKF_EC_NAMEDCURVE  : nativeint
val cKF_EC_UNCOMPRESS  : nativeint
val cKF_EC_COMPRESS  : nativeint
val cKF_EXTENSION  : nativeint
val cKF_DONT_BLOCK    : nativeint
val cKF_LIBRARY_CANT_CREATE_OS_THREADS : nativeint
val cKF_OS_LOCKING_OK   : nativeint
val cKR_OK     : nativeint
val cKR_CANCEL    : nativeint
val cKR_HOST_MEMORY    : nativeint
val cKR_SLOT_ID_INVALID   : nativeint
val cKR_GENERAL_ERROR   : nativeint
val cKR_FUNCTION_FAILED   : nativeint
val cKR_ARGUMENTS_BAD   : nativeint
val cKR_NO_EVENT    : nativeint
val cKR_NEED_TO_CREATE_THREADS  : nativeint
val cKR_CANT_LOCK    : nativeint
val cKR_ATTRIBUTE_READ_ONLY   : nativeint
val cKR_ATTRIBUTE_SENSITIVE   : nativeint
val cKR_ATTRIBUTE_TYPE_INVALID  : nativeint
val cKR_ATTRIBUTE_VALUE_INVALID  : nativeint
val cKR_DATA_INVALID   : nativeint
val cKR_DATA_LEN_RANGE   : nativeint
val cKR_DEVICE_ERROR   : nativeint
val cKR_DEVICE_MEMORY   : nativeint
val cKR_DEVICE_REMOVED   : nativeint
val cKR_ENCRYPTED_DATA_INVALID  : nativeint
val cKR_ENCRYPTED_DATA_LEN_RANGE  : nativeint
val cKR_FUNCTION_CANCELED   : nativeint
val cKR_FUNCTION_NOT_PARALLEL  : nativeint
val cKR_FUNCTION_NOT_SUPPORTED  : nativeint
val cKR_KEY_HANDLE_INVALID   : nativeint
val cKR_KEY_SIZE_RANGE   : nativeint
val cKR_KEY_TYPE_INCONSISTENT  : nativeint
val cKR_KEY_NOT_NEEDED   : nativeint
val cKR_KEY_CHANGED    : nativeint
val cKR_KEY_NEEDED    : nativeint
val cKR_KEY_INDIGESTIBLE   : nativeint
val cKR_KEY_FUNCTION_NOT_PERMITTED  : nativeint
val cKR_KEY_NOT_WRAPPABLE   : nativeint
val cKR_KEY_UNEXTRACTABLE   : nativeint
val cKR_MECHANISM_INVALID   : nativeint
val cKR_MECHANISM_PARAM_INVALID  : nativeint
val cKR_OBJECT_HANDLE_INVALID  : nativeint
val cKR_OPERATION_ACTIVE   : nativeint
val cKR_OPERATION_NOT_INITIALIZED  : nativeint
val cKR_PIN_INCORRECT   : nativeint
val cKR_PIN_INVALID    : nativeint
val cKR_PIN_LEN_RANGE   : nativeint
val cKR_PIN_EXPIRED    : nativeint
val cKR_PIN_LOCKED    : nativeint
val cKR_SESSION_CLOSED   : nativeint
val cKR_SESSION_COUNT   : nativeint
val cKR_SESSION_HANDLE_INVALID  : nativeint
val cKR_SESSION_PARALLEL_NOT_SUPPORTED : nativeint
val cKR_SESSION_READ_ONLY   : nativeint
val cKR_SESSION_EXISTS   : nativeint
val cKR_SESSION_READ_ONLY_EXISTS  : nativeint
val cKR_SESSION_READ_WRITE_SO_EXISTS : nativeint
val cKR_SIGNATURE_INVALID   : nativeint
val cKR_SIGNATURE_LEN_RANGE   : nativeint
val cKR_TEMPLATE_INCOMPLETE   : nativeint
val cKR_TEMPLATE_INCONSISTENT  : nativeint
val cKR_TOKEN_NOT_PRESENT   : nativeint
val cKR_TOKEN_NOT_RECOGNIZED  : nativeint
val cKR_TOKEN_WRITE_PROTECTED  : nativeint
val cKR_UNWRAPPING_KEY_HANDLE_INVALID : nativeint
val cKR_UNWRAPPING_KEY_SIZE_RANGE  : nativeint
val cKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : nativeint
val cKR_USER_ALREADY_LOGGED_IN  : nativeint
val cKR_USER_NOT_LOGGED_IN   : nativeint
val cKR_USER_PIN_NOT_INITIALIZED  : nativeint
val cKR_USER_TYPE_INVALID   : nativeint
val cKR_USER_ANOTHER_ALREADY_LOGGED_IN : nativeint
val cKR_USER_TOO_MANY_TYPES   : nativeint
val cKR_WRAPPED_KEY_INVALID   : nativeint
val cKR_WRAPPED_KEY_LEN_RANGE  : nativeint
val cKR_WRAPPING_KEY_HANDLE_INVALID  : nativeint
val cKR_WRAPPING_KEY_SIZE_RANGE  : nativeint
val cKR_WRAPPING_KEY_TYPE_INCONSISTENT : nativeint
val cKR_RANDOM_SEED_NOT_SUPPORTED  : nativeint
val cKR_RANDOM_NO_RNG   : nativeint
val cKR_DOMAIN_PARAMS_INVALID  : nativeint
val cKR_BUFFER_TOO_SMALL   : nativeint
val cKR_SAVED_STATE_INVALID   : nativeint
val cKR_INFORMATION_SENSITIVE  : nativeint
val cKR_STATE_UNSAVEABLE   : nativeint
val cKR_CRYPTOKI_NOT_INITIALIZED  : nativeint
val cKR_CRYPTOKI_ALREADY_INITIALIZED : nativeint
val cKR_MUTEX_BAD    : nativeint
val cKR_MUTEX_NOT_LOCKED   : nativeint
val cKR_NEW_PIN_MODE   : nativeint
val cKR_NEXT_OTP   : nativeint
val cKR_FUNCTION_REJECTED   : nativeint
val cKR_VENDOR_DEFINED   : nativeint
val cK_FALSE : nativeint
val cK_TRUE : nativeint
val fALSE : nativeint
val tRUE : nativeint
val nULL_PTR : nativeint
val false_ : char array
val true_ : char array
exception Mechanism_unknown of string
(* Helpers for information printing *)

val match_cKM_value : nativeint -> string

val match_cKR_value : nativeint -> string

val match_cKA_value : nativeint -> string

val match_cKF_value : nativeint -> string

val match_cKC_value : nativeint -> string

val match_cKK_value : nativeint -> string

val match_cKS_value : nativeint -> string

val match_cKU_value : nativeint -> string

val match_cKO_value : nativeint -> string

val string_to_cKM_value : string -> nativeint

(* Helpers for strings and char arrays *)

val string_to_char_array : string -> char array

val char_array_to_string : char array -> string

val print_int_array : nativeint array -> unit

val print_char_array : char array -> unit

val print_string_array : string array -> unit

val print_hex : char -> unit

val print_hex_array : char array -> unit

val int_to_hexchar : nativeint -> char

val hexchar_to_int : char -> nativeint

val merge_nibbles : char -> char -> char

val pack : string -> string

val sprint_hex_array : char array -> string

val bool_to_char_array : nativeint -> char array

val char_array_to_bool : char array -> nativeint

val sprint_bool_attribute_value : nativeint -> string

val sprint_template_array : ck_attribute array -> string

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

val c_Daemonize : char array -> ck_rv_t
val c_SetupArch : nativeint -> ck_rv_t
val c_LoadModule : char array -> ck_rv_t
val c_Initialize : unit -> ck_rv_t
val c_GetInfo : unit -> ck_rv_t * ck_info
val c_GetSlotList : nativeint -> nativeint -> ck_rv_t * ck_slot_id_t array * nativeint
val c_GetSlotInfo : ck_slot_id_t -> ck_rv_t * ck_slot_info
val c_GetTokenInfo : ck_slot_id_t -> ck_rv_t * ck_token_info
val c_WaitForSlotEvent : ck_flags_t -> ck_rv_t * ck_slot_id_t
val c_GetMechanismList : ck_slot_id_t -> nativeint -> ck_rv_t * ck_mechanism_type_t array * nativeint
val c_GetMechanismInfo : ck_slot_id_t -> ck_mechanism_type_t -> ck_rv_t * ck_mechanism_info
val c_InitToken : ck_slot_id_t -> char array -> char array -> ck_rv_t
val c_InitPIN : ck_session_handle_t -> char array -> ck_rv_t
val c_SetPIN : ck_session_handle_t -> char array -> char array -> ck_rv_t
val c_OpenSession : ck_slot_id_t -> ck_flags_t -> ck_rv_t * ck_session_handle_t
val c_CloseSession : ck_session_handle_t -> ck_rv_t
val c_CloseAllSessions : ck_slot_id_t -> ck_rv_t
val c_GetSessionInfo : ck_session_handle_t -> ck_rv_t * ck_session_info
val c_GetOperationState : ck_session_handle_t -> ck_rv_t * char array
val c_SetOperationState : ck_session_handle_t -> char array -> ck_object_handle_t -> ck_object_handle_t -> ck_rv_t
val c_Login : ck_session_handle_t -> ck_user_type_t -> char array -> ck_rv_t
val c_Logout : ck_session_handle_t -> ck_rv_t
val c_Finalize : unit -> ck_rv_t
val c_CreateObject : ck_session_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
val c_CopyObject : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
val c_DestroyObject : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t
val c_GetObjectSize : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t * nativeint
val c_GetAttributeValue : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_attribute array
val c_SetAttributeValue : ck_session_handle_t -> ck_object_handle_t -> ck_attribute array -> ck_rv_t
val c_FindObjectsInit : ck_session_handle_t -> ck_attribute array -> ck_rv_t
val c_FindObjects : ck_session_handle_t -> nativeint -> ck_rv_t * ck_object_handle_t array * nativeint
val c_FindObjectsFinal : ck_session_handle_t -> ck_rv_t
val c_EncryptInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_Encrypt : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_EncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_EncryptFinal : ck_session_handle_t -> ck_rv_t * char array
val c_DecryptInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_Decrypt : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_DecryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_DecryptFinal : ck_session_handle_t -> ck_rv_t * char array
val c_DigestInit : ck_session_handle_t -> ck_mechanism -> ck_rv_t
val c_Digest : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_DigestUpdate : ck_session_handle_t -> char array -> ck_rv_t
val c_DigestKey : ck_session_handle_t -> ck_object_handle_t -> ck_rv_t
val c_DigestFinal : ck_session_handle_t -> ck_rv_t * char array
val c_SignInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_SignRecoverInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_Sign : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_SignRecover : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_SignUpdate : ck_session_handle_t -> char array -> ck_rv_t
val c_SignFinal : ck_session_handle_t -> ck_rv_t * char array
val c_VerifyInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_VerifyRecoverInit : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_rv_t
val c_Verify : ck_session_handle_t -> char array -> char array -> ck_rv_t
val c_VerifyRecover : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_VerifyUpdate : ck_session_handle_t -> char array -> ck_rv_t
val c_VerifyFinal : ck_session_handle_t -> char array -> ck_rv_t
val c_DigestEncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_DecryptDigestUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_SignEncryptUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_DecryptVerifyUpdate : ck_session_handle_t -> char array -> ck_rv_t * char array
val c_GenerateKey : ck_session_handle_t -> ck_mechanism -> ck_attribute array -> ck_rv_t * ck_object_handle_t
val c_GenerateKeyPair : ck_session_handle_t -> ck_mechanism -> ck_attribute array -> ck_attribute array -> ck_rv_t * ck_object_handle_t * ck_object_handle_t
val c_WrapKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_object_handle_t -> ck_rv_t * char array
val c_UnwrapKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> char array -> ck_attribute array -> ck_rv_t * ck_object_handle_t
val c_DeriveKey : ck_session_handle_t -> ck_mechanism -> ck_object_handle_t -> ck_attribute array -> ck_rv_t * ck_object_handle_t
val c_SeedRandom : ck_session_handle_t -> char array -> ck_rv_t
val c_GenerateRandom : ck_session_handle_t -> nativeint -> ck_rv_t * char array
val c_GetFunctionStatus : ck_session_handle_t -> ck_rv_t
val c_CancelFunction : ck_session_handle_t -> ck_rv_t
