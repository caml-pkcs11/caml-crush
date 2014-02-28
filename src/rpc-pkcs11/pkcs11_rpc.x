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

    The current source code is part of the RPC 2] source tree:
                          --------  socket (TCP or Unix)  --------------------
                         |2] RPC  |<+++++++++++++++++++> |                    |
                         |  Layer | [SSL/TLS optional]   |  --------          |
                          --------                       | |2] RPC  |         |
                                                         | |  Layer |         |
                                                         |  --------          |
                                                          --------------------

    Project: PKCS#11 Filtering Proxy
    File:    src/rpc-pkcs11/pkcs11_rpc.x

-------------------------- CeCILL-B HEADER ----------------------------------*/
#ifdef RPC_HDR
%#ifdef WIN32
%#include <stdint.h>
%#define quad_t int64_t
%#endif
%extern CLIENT *cl;
#endif
typedef hyper pkcs11_int;

typedef pkcs11_int rpc_ck_rv_t;
typedef pkcs11_int rpc_ck_slot_id_t;
typedef pkcs11_int rpc_ck_mechanism_type_t;
typedef pkcs11_int rpc_ck_session_handle_t;
typedef pkcs11_int rpc_ck_user_type_t;
typedef pkcs11_int rpc_ck_state_t;

typedef pkcs11_int rpc_ck_object_handle_t;
typedef pkcs11_int rpc_ck_object_class_t;
typedef pkcs11_int rpc_ck_hw_feature_type_t;
typedef pkcs11_int rpc_ck_key_type_t;
typedef pkcs11_int rpc_ck_certificate_type_t;
typedef pkcs11_int rpc_ck_attribute_type_t;
typedef pkcs11_int rpc_ck_flags_t;
typedef pkcs11_int rpc_ck_notification_t;
typedef opaque opaque_data <>;

struct rpc_ck_version {
  opaque major < 1 >;
  opaque minor < 1 >;
};
struct rpc_ck_info {
  rpc_ck_version rpc_ck_info_cryptoki_version;
  opaque rpc_ck_info_manufacturer_id < 32 >;
  rpc_ck_flags_t rpc_ck_info_flags;
  opaque rpc_ck_info_library_description < 32 >;
  rpc_ck_version rpc_ck_info_library_version;
};
struct rpc_ck_slot_info {
  opaque rpc_ck_slot_info_slot_description <>;
  opaque rpc_ck_slot_info_manufacturer_id <>;
  rpc_ck_flags_t rpc_ck_slot_info_flags;
  rpc_ck_version rpc_ck_slot_info_hardware_version;
  rpc_ck_version rpc_ck_slot_info_firmware_version;
};

struct rpc_ck_token_info {
  opaque rpc_ck_token_info_label < 32 >;
  opaque rpc_ck_token_info_manufacturer_id < 32 >;
  opaque rpc_ck_token_info_model < 16 >;
  opaque rpc_ck_token_info_serial_number < 16 >;
  rpc_ck_flags_t rpc_ck_token_info_flags;
  pkcs11_int rpc_ck_token_info_max_session_count;
  pkcs11_int rpc_ck_token_info_session_count;
  pkcs11_int rpc_ck_token_info_max_rw_session_count;
  pkcs11_int rpc_ck_token_info_rw_session_count;
  pkcs11_int rpc_ck_token_info_max_pin_len;
  pkcs11_int rpc_ck_token_info_min_pin_len;
  pkcs11_int rpc_ck_token_info_total_public_memory;
  pkcs11_int rpc_ck_token_info_free_public_memory;
  pkcs11_int rpc_ck_token_info_total_private_memory;
  pkcs11_int rpc_ck_token_info_free_private_memory;
  rpc_ck_version rpc_ck_token_info_hardware_version;
  rpc_ck_version rpc_ck_token_info_firmware_version;
  opaque rpc_ck_token_info_utc_time < 16 >;
};

struct rpc_ck_mechanism {
  rpc_ck_mechanism_type_t rpc_ck_mechanism_mechanism;
  opaque rpc_ck_mechanism_parameter <>;
};

struct rpc_ck_session_info {
  rpc_ck_slot_id_t rpc_ck_session_info_slot_id;
  rpc_ck_state_t rpc_ck_session_info_state;
  rpc_ck_flags_t rpc_ck_session_info_flags;
  pkcs11_int rpc_ck_session_info_device_error;
};

struct rpc_ck_mechanism_info {
  pkcs11_int rpc_ck_mechanism_info_min_key_size;
  pkcs11_int rpc_ck_mechanism_info_max_key_size;
  rpc_ck_flags_t rpc_ck_mechanism_info_flags;
};

struct rpc_ck_attribute {
  rpc_ck_attribute_type_t rpc_ck_attribute_type;
  opaque rpc_ck_attribute_value <>;
  pkcs11_int rpc_ck_attribute_value_len;
};
typedef rpc_ck_attribute rpc_ck_attribute_array <>;

struct rpc_ck_date {
  opaque rpc_ck_date_year < 4 >;
  opaque rpc_ck_date_month < 2 >;
  opaque rpc_ck_date_day < 2 >;
};

struct ck_rv_c_GetSlotList {
  rpc_ck_rv_t c_GetSlotList_rv;
  rpc_ck_slot_id_t c_GetSlotList_slot_list <>;
  pkcs11_int c_GetSlotList_count;
};

struct ck_rv_c_GetSlotInfo {
  rpc_ck_rv_t c_GetSlotInfo_rv;
  rpc_ck_slot_info c_GetSlotInfo_slot_info;
};

struct ck_rv_c_GetTokenInfo {
  rpc_ck_rv_t c_GetTokenInfo_rv;
  rpc_ck_token_info c_GetTokenInfo_token_info;
};

struct ck_rv_c_GetInfo {
  rpc_ck_rv_t c_GetInfo_rv;
  rpc_ck_info c_GetInfo_info;
};

struct ck_rv_c_WaitForSlotEvent {
  rpc_ck_rv_t c_WaitForSlotEvent_rv;
  rpc_ck_slot_id_t c_WaitForSlotEvent_count;
};

struct ck_rv_c_OpenSession {
  rpc_ck_rv_t c_OpenSession_rv;
  rpc_ck_session_handle_t c_OpenSession_handle;
};

struct ck_rv_c_GetMechanismList {
  rpc_ck_rv_t c_GetMechanismList_rv;
  rpc_ck_mechanism_type_t c_GetMechanismList_list <>;
  pkcs11_int c_GetMechanismList_count;
};

struct ck_rv_c_GetSessionInfo {
  rpc_ck_rv_t c_GetSessionInfo_rv;
  rpc_ck_session_info c_GetSessionInfo_info;
};

struct ck_rv_c_GetMechanismInfo {
  rpc_ck_rv_t c_GetMechanismInfo_rv;
  rpc_ck_mechanism_info c_GetMechanismInfo_info;
};

struct ck_rv_c_GenerateRandom {
  rpc_ck_rv_t c_GenerateRandom_rv;
  opaque c_GenerateRandom_data <>;
};

struct ck_rv_c_FindObjects {
  rpc_ck_rv_t c_FindObjects_rv;
  rpc_ck_object_handle_t c_FindObjects_objects <>;
  pkcs11_int c_FindObjects_count;
};

struct ck_rv_c_GenerateKey {
  rpc_ck_rv_t c_GenerateKey_rv;
  rpc_ck_object_handle_t c_GenerateKey_handle;
};

struct ck_rv_c_GenerateKeyPair {
  rpc_ck_rv_t c_GenerateKeyPair_rv;
  rpc_ck_object_handle_t c_GenerateKeyPair_pubhandle;
  rpc_ck_object_handle_t c_GenerateKeyPair_privhandle;
};

struct ck_rv_c_CreateObject {
  rpc_ck_rv_t c_CreateObject_rv;
  rpc_ck_object_handle_t c_CreateObject_handle;
};

struct ck_rv_c_CopyObject {
  rpc_ck_rv_t c_CopyObject_rv;
  rpc_ck_object_handle_t c_CopyObject_handle;
};

struct ck_rv_c_GetAttributeValue {
  rpc_ck_rv_t c_GetAttributeValue_rv;
  rpc_ck_attribute_array c_GetAttributeValue_value;
};

struct ck_rv_c_GetObjectSize {
  rpc_ck_rv_t c_GetObjectSize_rv;
  pkcs11_int c_GetObjectSize_size;
};

struct ck_rv_c_WrapKey {
  rpc_ck_rv_t c_WrapKey_rv;
  opaque c_WrapKey_value <>;
};

struct ck_rv_c_UnwrapKey {
  rpc_ck_rv_t c_UnwrapKey_rv;
  rpc_ck_object_handle_t c_UnwrapKey_handle;
};

struct ck_rv_c_DeriveKey {
  rpc_ck_rv_t c_DeriveKey_rv;
  rpc_ck_object_handle_t c_DeriveKey_handle;
};

struct ck_rv_c_Digest {
  rpc_ck_rv_t c_Digest_rv;
  opaque c_Digest_value <>;
};

struct ck_rv_c_DigestFinal {
  rpc_ck_rv_t c_DigestFinal_rv;
  opaque c_DigestFinal_value <>;
};

struct ck_rv_c_Sign {
  rpc_ck_rv_t c_Sign_rv;
  opaque c_Sign_value <>;
};

struct ck_rv_c_SignFinal {
  rpc_ck_rv_t c_SignFinal_rv;
  opaque c_SignFinal_value <>;
};

struct ck_rv_c_Encrypt {
  rpc_ck_rv_t c_Encrypt_rv;
  opaque c_Encrypt_value <>;
};

struct ck_rv_c_EncryptUpdate {
  rpc_ck_rv_t c_EncryptUpdate_rv;
  opaque c_EncryptUpdate_value <>;
};

struct ck_rv_c_EncryptFinal {
  rpc_ck_rv_t c_EncryptFinal_rv;
  opaque c_EncryptFinal_value <>;
};

struct ck_rv_c_Decrypt {
  rpc_ck_rv_t c_Decrypt_rv;
  opaque c_Decrypt_value <>;
};

struct ck_rv_c_DecryptUpdate {
  rpc_ck_rv_t c_DecryptUpdate_rv;
  opaque c_DecryptUpdate_value <>;
};

struct ck_rv_c_DecryptFinal {
  rpc_ck_rv_t c_DecryptFinal_rv;
  opaque c_DecryptFinal_value <>;
};

struct ck_rv_c_SignRecover {
  rpc_ck_rv_t c_SignRecover_rv;
  opaque c_SignRecover_value <>;
};

struct ck_rv_c_VerifyRecover {
  rpc_ck_rv_t c_VerifyRecover_rv;
  opaque c_VerifyRecover_value <>;
};

struct ck_rv_c_DigestEncryptUpdate {
  rpc_ck_rv_t c_DigestEncryptUpdate_rv;
  opaque c_DigestEncryptUpdate_value <>;
};

struct ck_rv_c_DecryptDigestUpdate {
  rpc_ck_rv_t c_DecryptDigestUpdate_rv;
  opaque c_DecryptDigestUpdate_value <>;
};

struct ck_rv_c_SignEncryptUpdate {
  rpc_ck_rv_t c_SignEncryptUpdate_rv;
  opaque c_SignEncryptUpdate_value <>;
};

struct ck_rv_c_DecryptVerifyUpdate {
  rpc_ck_rv_t c_DecryptVerifyUpdate_rv;
  opaque c_DecryptVerifyUpdate_value <>;
};

struct ck_rv_c_GetOperationState {
  rpc_ck_rv_t c_GetOperationState_rv;
  opaque c_GetOperationState_value <>;
};

program P {
  version V {
    rpc_ck_rv_t c_SetupArch(pkcs11_int) = 2;
    rpc_ck_rv_t c_Initialize(void) = 3;
    ck_rv_c_GetSlotList c_GetSlotList(pkcs11_int, pkcs11_int) = 4;
    ck_rv_c_GetInfo c_GetInfo(void) = 5;
    ck_rv_c_WaitForSlotEvent c_WaitForSlotEvent(rpc_ck_flags_t) = 6;
    ck_rv_c_GetSlotInfo c_GetSlotInfo(rpc_ck_slot_id_t) = 7;
    ck_rv_c_GetTokenInfo c_GetTokenInfo(rpc_ck_slot_id_t) = 8;
    rpc_ck_rv_t c_Login(rpc_ck_session_handle_t, rpc_ck_user_type_t,
			opaque_data) = 9;
    rpc_ck_rv_t c_Logout(rpc_ck_session_handle_t) = 10;
    ck_rv_c_OpenSession c_OpenSession(rpc_ck_slot_id_t, rpc_ck_flags_t) = 11;
    rpc_ck_rv_t c_CloseSession(rpc_ck_session_handle_t) = 12;
    rpc_ck_rv_t c_Finalize(void) = 13;
    ck_rv_c_GetMechanismList c_GetMechanismList(rpc_ck_slot_id_t, pkcs11_int) =
	14;
    rpc_ck_rv_t c_CloseAllSessions(rpc_ck_slot_id_t) = 15;
    ck_rv_c_GetSessionInfo c_GetSessionInfo(rpc_ck_session_handle_t) = 16;
    ck_rv_c_GetMechanismInfo c_GetMechanismInfo(rpc_ck_slot_id_t,
						rpc_ck_mechanism_type_t) = 17;
    rpc_ck_rv_t c_InitPIN(rpc_ck_session_handle_t, opaque_data) = 18;
    rpc_ck_rv_t c_SetPIN(rpc_ck_session_handle_t, opaque_data, opaque_data) =
	19;
    rpc_ck_rv_t c_SeedRandom(rpc_ck_session_handle_t, opaque_data) = 20;
    rpc_ck_rv_t c_InitToken(rpc_ck_slot_id_t, opaque_data, opaque_data) = 21;
    ck_rv_c_GenerateRandom c_GenerateRandom(rpc_ck_session_handle_t,
					    pkcs11_int) = 22;
    rpc_ck_rv_t c_FindObjectsInit(rpc_ck_session_handle_t,
				  rpc_ck_attribute_array) = 23;
    ck_rv_c_FindObjects c_FindObjects(rpc_ck_session_handle_t, pkcs11_int) = 24;
    rpc_ck_rv_t c_FindObjectsFinal(rpc_ck_session_handle_t) = 25;

    ck_rv_c_GenerateKey c_GenerateKey(rpc_ck_session_handle_t, rpc_ck_mechanism,
				      rpc_ck_attribute_array) = 26;
    ck_rv_c_GenerateKeyPair c_GenerateKeyPair(rpc_ck_session_handle_t,
					      rpc_ck_mechanism,
					      rpc_ck_attribute_array,
					      rpc_ck_attribute_array) = 27;
    ck_rv_c_CreateObject c_CreateObject(rpc_ck_session_handle_t,
					rpc_ck_attribute_array) = 28;
    ck_rv_c_CopyObject c_CopyObject(rpc_ck_session_handle_t,
				    rpc_ck_object_handle_t,
				    rpc_ck_attribute_array) = 29;
    rpc_ck_rv_t c_DestroyObject(rpc_ck_session_handle_t,
				rpc_ck_object_handle_t) = 30;

    ck_rv_c_GetAttributeValue c_GetAttributeValue(rpc_ck_session_handle_t,
						  rpc_ck_object_handle_t,
						  rpc_ck_attribute_array) = 31;
    rpc_ck_rv_t c_SetAttributeValue(rpc_ck_session_handle_t,
				    rpc_ck_object_handle_t,
				    rpc_ck_attribute_array) = 32;
    ck_rv_c_GetObjectSize c_GetObjectSize(rpc_ck_session_handle_t,
					  rpc_ck_object_handle_t) = 33;

    ck_rv_c_WrapKey c_WrapKey(rpc_ck_session_handle_t, rpc_ck_mechanism,
			      rpc_ck_object_handle_t, rpc_ck_object_handle_t) =
	34;
    ck_rv_c_UnwrapKey c_UnwrapKey(rpc_ck_session_handle_t, rpc_ck_mechanism,
				  rpc_ck_object_handle_t, opaque_data,
				  rpc_ck_attribute_array) = 35;
    ck_rv_c_DeriveKey c_DeriveKey(rpc_ck_session_handle_t, rpc_ck_mechanism,
				  rpc_ck_object_handle_t,
				  rpc_ck_attribute_array) = 36;

    rpc_ck_rv_t c_DigestInit(rpc_ck_session_handle_t, rpc_ck_mechanism) = 37;
    ck_rv_c_Digest c_Digest(rpc_ck_session_handle_t, opaque_data) = 38;
    rpc_ck_rv_t c_DigestUpdate(rpc_ck_session_handle_t, opaque_data) = 39;
    ck_rv_c_DigestFinal c_DigestFinal(rpc_ck_session_handle_t) = 40;
    rpc_ck_rv_t c_DigestKey(rpc_ck_session_handle_t, rpc_ck_object_handle_t) =
	41;

    rpc_ck_rv_t c_SignInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
			   rpc_ck_object_handle_t) = 42;
    ck_rv_c_Sign c_Sign(rpc_ck_session_handle_t, opaque_data) = 43;
    rpc_ck_rv_t c_SignUpdate(rpc_ck_session_handle_t, opaque_data) = 44;
    ck_rv_c_SignFinal c_SignFinal(rpc_ck_session_handle_t) = 45;

    rpc_ck_rv_t c_VerifyInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
			     rpc_ck_object_handle_t) = 46;
    rpc_ck_rv_t c_Verify(rpc_ck_session_handle_t, opaque_data, opaque_data) =
	47;
    rpc_ck_rv_t c_VerifyUpdate(rpc_ck_session_handle_t, opaque_data) = 48;
    rpc_ck_rv_t c_VerifyFinal(rpc_ck_session_handle_t, opaque_data) = 49;

    rpc_ck_rv_t c_EncryptInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
			      rpc_ck_object_handle_t) = 50;
    ck_rv_c_Encrypt c_Encrypt(rpc_ck_session_handle_t, opaque_data) = 51;
    ck_rv_c_EncryptUpdate c_EncryptUpdate(rpc_ck_session_handle_t,
					  opaque_data) = 52;
    ck_rv_c_EncryptFinal c_EncryptFinal(rpc_ck_session_handle_t) = 53;

    rpc_ck_rv_t c_DecryptInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
			      rpc_ck_object_handle_t) = 54;
    ck_rv_c_Decrypt c_Decrypt(rpc_ck_session_handle_t, opaque_data) = 55;
    ck_rv_c_DecryptUpdate c_DecryptUpdate(rpc_ck_session_handle_t,
					  opaque_data) = 56;
    ck_rv_c_DecryptFinal c_DecryptFinal(rpc_ck_session_handle_t) = 57;

    rpc_ck_rv_t c_SignRecoverInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
				  rpc_ck_object_handle_t) = 58;
    ck_rv_c_SignRecover c_SignRecover(rpc_ck_session_handle_t, opaque_data) =
	59;

    rpc_ck_rv_t c_VerifyRecoverInit(rpc_ck_session_handle_t, rpc_ck_mechanism,
				    rpc_ck_object_handle_t) = 60;
    ck_rv_c_VerifyRecover c_VerifyRecover(rpc_ck_session_handle_t,
					  opaque_data) = 61;

    ck_rv_c_DigestEncryptUpdate c_DigestEncryptUpdate(rpc_ck_session_handle_t,
						      opaque_data) = 62;
    ck_rv_c_SignEncryptUpdate c_SignEncryptUpdate(rpc_ck_session_handle_t,
						  opaque_data) = 63;
    ck_rv_c_DecryptDigestUpdate c_DecryptDigestUpdate(rpc_ck_session_handle_t,
						      opaque_data) = 64;
    ck_rv_c_DecryptVerifyUpdate c_DecryptVerifyUpdate(rpc_ck_session_handle_t,
						      opaque_data) = 65;

    ck_rv_c_GetOperationState c_GetOperationState(rpc_ck_session_handle_t) = 66;
    rpc_ck_rv_t c_SetOperationState(rpc_ck_session_handle_t, opaque_data,
				    rpc_ck_object_handle_t,
				    rpc_ck_object_handle_t) = 67;
    rpc_ck_rv_t c_GetFunctionStatus(rpc_ck_session_handle_t) = 68;
    rpc_ck_rv_t c_CancelFunction(rpc_ck_session_handle_t) = 69;

    rpc_ck_rv_t c_LoadModule(opaque_data) = 70;

  } = 3;
} = 4;
