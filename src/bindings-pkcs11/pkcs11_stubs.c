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
    File:    src/bindings-pkcs11/pkcs11_stubs.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
/* File generated from pkcs11.idl */

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

#define CUSTOM_ALLOC
#include "pkcs11.h"

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_flags_t(value _v1, ck_flags_t * _c2,
				    __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_flags_t(value _v1, ck_flags_t * _c2,
				    camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_flags_t(ck_flags_t * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_flags_t(ck_flags_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_version(value _v1, struct ck_version *_c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_version(value _v1, struct ck_version *_c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  _v3 = Field(_v1, 0);
  (*_c2).major = Int_val(_v3);
  _v4 = Field(_v1, 1);
  (*_c2).minor = Int_val(_v4);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_version(struct ck_version *_c1,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_version(struct ck_version *_c1,
					    camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[2];
  _v3[0] = _v3[1] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = Val_int((*_c1).major);
  _v3[1] = Val_int((*_c1).minor);
  _v2 = camlidl_alloc_small(2, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_info(value _v1, struct ck_info *_c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_info(value _v1, struct ck_info *_c2,
					camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  mlsize_t _c5;
  mlsize_t _c6;
  value _v7;
  value _v8;
  value _v9;
  mlsize_t _c10;
  mlsize_t _c11;
  value _v12;
  value _v13;
  _v3 = Field(_v1, 0);
  camlidl_ml2c_pkcs11_struct_ck_version(_v3, &(*_c2).cryptoki_version, _ctx);
  _v4 = Field(_v1, 1);
  _c5 = Wosize_val(_v4);
  if (_c5 != 32)
    invalid_argument("struct ck_info");
  for (_c6 = 0; _c6 < 32; _c6++) {
    _v7 = Field(_v4, _c6);
    (*_c2).manufacturer_id[_c6] = Int_val(_v7);
  }
  _v8 = Field(_v1, 2);
  camlidl_ml2c_pkcs11_ck_flags_t(_v8, &(*_c2).flags, _ctx);
  _v9 = Field(_v1, 3);
  _c10 = Wosize_val(_v9);
  if (_c10 != 32)
    invalid_argument("struct ck_info");
  for (_c11 = 0; _c11 < 32; _c11++) {
    _v12 = Field(_v9, _c11);
    (*_c2).library_description[_c11] = Int_val(_v12);
  }
  _v13 = Field(_v1, 4);
  camlidl_ml2c_pkcs11_struct_ck_version(_v13, &(*_c2).library_version, _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_info(struct ck_info *_c1,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_info(struct ck_info *_c1, camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[5];
  mlsize_t _c4;
  mlsize_t _c5;
  memset(_v3, 0, 5 * sizeof(value));
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 5);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] =
      camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).cryptoki_version, _ctx);
  _v3[1] = camlidl_alloc_small(32, 0);
  for (_c4 = 0; _c4 < 32; _c4++) {
    Field(_v3[1], _c4) = Val_int((*_c1).manufacturer_id[_c4]);
  }
  _v3[2] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v3[3] = camlidl_alloc_small(32, 0);
  for (_c5 = 0; _c5 < 32; _c5++) {
    Field(_v3[3], _c5) = Val_int((*_c1).library_description[_c5]);
  }
  _v3[4] = camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).library_version, _ctx);
  _v2 = camlidl_alloc_small(5, 0);
  {
    mlsize_t _c6;
    for (_c6 = 0; _c6 < 5; _c6++)
      Field(_v2, _c6) = _v3[_c6];
  }
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_notification_t(value _v1, ck_notification_t * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_ck_notification_t(value _v1, ck_notification_t * _c2,
					   camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_notification_t(ck_notification_t * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_ck_notification_t(ck_notification_t * _c2,
					    camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_slot_id_t(value _v1, ck_slot_id_t * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_slot_id_t(value _v1, ck_slot_id_t * _c2,
				      camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_slot_id_t(ck_slot_id_t * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
value camlidl_c2ml_pkcs11_ck_slot_id_t(ck_slot_id_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_slot_info(value _v1,
					     struct ck_slot_info *_c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_slot_info(value _v1,
					     struct ck_slot_info *_c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _v7;
  mlsize_t _c8;
  mlsize_t _c9;
  value _v10;
  value _v11;
  value _v12;
  value _v13;
  _v3 = Field(_v1, 0);
  _c4 = Wosize_val(_v3);
  if (_c4 != 64)
    invalid_argument("struct ck_slot_info");
  for (_c5 = 0; _c5 < 64; _c5++) {
    _v6 = Field(_v3, _c5);
    (*_c2).slot_description[_c5] = Int_val(_v6);
  }
  _v7 = Field(_v1, 1);
  _c8 = Wosize_val(_v7);
  if (_c8 != 32)
    invalid_argument("struct ck_slot_info");
  for (_c9 = 0; _c9 < 32; _c9++) {
    _v10 = Field(_v7, _c9);
    (*_c2).manufacturer_id[_c9] = Int_val(_v10);
  }
  _v11 = Field(_v1, 2);
  camlidl_ml2c_pkcs11_ck_flags_t(_v11, &(*_c2).flags, _ctx);
  _v12 = Field(_v1, 3);
  camlidl_ml2c_pkcs11_struct_ck_version(_v12, &(*_c2).hardware_version, _ctx);
  _v13 = Field(_v1, 4);
  camlidl_ml2c_pkcs11_struct_ck_version(_v13, &(*_c2).firmware_version, _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_slot_info(struct ck_slot_info *_c1,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_slot_info(struct ck_slot_info *_c1,
					      camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[5];
  mlsize_t _c4;
  value _v5;
  mlsize_t _c6;
  memset(_v3, 0, 5 * sizeof(value));
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 5);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_alloc(64, 0);
  for (_c4 = 0; _c4 < 64; _c4++) {
    _v5 = Val_int((*_c1).slot_description[_c4]);
    modify(&Field(_v3[0], _c4), _v5);
  }
  _v3[1] = camlidl_alloc_small(32, 0);
  for (_c6 = 0; _c6 < 32; _c6++) {
    Field(_v3[1], _c6) = Val_int((*_c1).manufacturer_id[_c6]);
  }
  _v3[2] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v3[3] =
      camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).hardware_version, _ctx);
  _v3[4] =
      camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).firmware_version, _ctx);
  _v2 = camlidl_alloc_small(5, 0);
  {
    mlsize_t _c7;
    for (_c7 = 0; _c7 < 5; _c7++)
      Field(_v2, _c7) = _v3[_c7];
  }
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_token_info(value _v1,
					      struct ck_token_info *_c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_token_info(value _v1,
					      struct ck_token_info *_c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _v7;
  mlsize_t _c8;
  mlsize_t _c9;
  value _v10;
  value _v11;
  mlsize_t _c12;
  mlsize_t _c13;
  value _v14;
  value _v15;
  mlsize_t _c16;
  mlsize_t _c17;
  value _v18;
  value _v19;
  value _v20;
  value _v21;
  value _v22;
  value _v23;
  value _v24;
  value _v25;
  value _v26;
  value _v27;
  value _v28;
  value _v29;
  value _v30;
  value _v31;
  value _v32;
  mlsize_t _c33;
  mlsize_t _c34;
  value _v35;
  _v3 = Field(_v1, 0);
  _c4 = Wosize_val(_v3);
  if (_c4 != 32)
    invalid_argument("struct ck_token_info");
  for (_c5 = 0; _c5 < 32; _c5++) {
    _v6 = Field(_v3, _c5);
    (*_c2).label[_c5] = Int_val(_v6);
  }
  _v7 = Field(_v1, 1);
  _c8 = Wosize_val(_v7);
  if (_c8 != 32)
    invalid_argument("struct ck_token_info");
  for (_c9 = 0; _c9 < 32; _c9++) {
    _v10 = Field(_v7, _c9);
    (*_c2).manufacturer_id[_c9] = Int_val(_v10);
  }
  _v11 = Field(_v1, 2);
  _c12 = Wosize_val(_v11);
  if (_c12 != 16)
    invalid_argument("struct ck_token_info");
  for (_c13 = 0; _c13 < 16; _c13++) {
    _v14 = Field(_v11, _c13);
    (*_c2).model[_c13] = Int_val(_v14);
  }
  _v15 = Field(_v1, 3);
  _c16 = Wosize_val(_v15);
  if (_c16 != 16)
    invalid_argument("struct ck_token_info");
  for (_c17 = 0; _c17 < 16; _c17++) {
    _v18 = Field(_v15, _c17);
    (*_c2).serial_number[_c17] = Int_val(_v18);
  }
  _v19 = Field(_v1, 4);
  camlidl_ml2c_pkcs11_ck_flags_t(_v19, &(*_c2).flags, _ctx);
  _v20 = Field(_v1, 5);
  (*_c2).max_session_count = custom_int_val(_v20);
  _v21 = Field(_v1, 6);
  (*_c2).session_count = custom_int_val(_v21);
  _v22 = Field(_v1, 7);
  (*_c2).max_rw_session_count = custom_int_val(_v22);
  _v23 = Field(_v1, 8);
  (*_c2).rw_session_count = custom_int_val(_v23);
  _v24 = Field(_v1, 9);
  (*_c2).max_pin_len = custom_int_val(_v24);
  _v25 = Field(_v1, 10);
  (*_c2).min_pin_len = custom_int_val(_v25);
  _v26 = Field(_v1, 11);
  (*_c2).total_public_memory = custom_int_val(_v26);
  _v27 = Field(_v1, 12);
  (*_c2).free_public_memory = custom_int_val(_v27);
  _v28 = Field(_v1, 13);
  (*_c2).total_private_memory = custom_int_val(_v28);
  _v29 = Field(_v1, 14);
  (*_c2).free_private_memory = custom_int_val(_v29);
  _v30 = Field(_v1, 15);
  camlidl_ml2c_pkcs11_struct_ck_version(_v30, &(*_c2).hardware_version, _ctx);
  _v31 = Field(_v1, 16);
  camlidl_ml2c_pkcs11_struct_ck_version(_v31, &(*_c2).firmware_version, _ctx);
  _v32 = Field(_v1, 17);
  _c33 = Wosize_val(_v32);
  if (_c33 != 16)
    invalid_argument("struct ck_token_info");
  for (_c34 = 0; _c34 < 16; _c34++) {
    _v35 = Field(_v32, _c34);
    (*_c2).utc_time[_c34] = Int_val(_v35);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_token_info(struct ck_token_info *_c1,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_token_info(struct ck_token_info *_c1,
					       camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[18];
  mlsize_t _c4;
  mlsize_t _c5;
  mlsize_t _c6;
  mlsize_t _c7;
  mlsize_t _c8;
  memset(_v3, 0, 18 * sizeof(value));
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 18);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_alloc_small(32, 0);
  for (_c4 = 0; _c4 < 32; _c4++) {
    Field(_v3[0], _c4) = Val_int((*_c1).label[_c4]);
  }
  _v3[1] = camlidl_alloc_small(32, 0);
  for (_c5 = 0; _c5 < 32; _c5++) {
    Field(_v3[1], _c5) = Val_int((*_c1).manufacturer_id[_c5]);
  }
  _v3[2] = camlidl_alloc_small(16, 0);
  for (_c6 = 0; _c6 < 16; _c6++) {
    Field(_v3[2], _c6) = Val_int((*_c1).model[_c6]);
  }
  _v3[3] = camlidl_alloc_small(16, 0);
  for (_c7 = 0; _c7 < 16; _c7++) {
    Field(_v3[3], _c7) = Val_int((*_c1).serial_number[_c7]);
  }
  _v3[4] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v3[5] = custom_copy_int((*_c1).max_session_count);
  _v3[6] = custom_copy_int((*_c1).session_count);
  _v3[7] = custom_copy_int((*_c1).max_rw_session_count);
  _v3[8] = custom_copy_int((*_c1).rw_session_count);
  _v3[9] = custom_copy_int((*_c1).max_pin_len);
  _v3[10] = custom_copy_int((*_c1).min_pin_len);
  _v3[11] = custom_copy_int((*_c1).total_public_memory);
  _v3[12] = custom_copy_int((*_c1).free_public_memory);
  _v3[13] = custom_copy_int((*_c1).total_private_memory);
  _v3[14] = custom_copy_int((*_c1).free_private_memory);
  _v3[15] =
      camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).hardware_version, _ctx);
  _v3[16] =
      camlidl_c2ml_pkcs11_struct_ck_version(&(*_c1).firmware_version, _ctx);
  _v3[17] = camlidl_alloc_small(16, 0);
  for (_c8 = 0; _c8 < 16; _c8++) {
    Field(_v3[17], _c8) = Val_int((*_c1).utc_time[_c8]);
  }
  _v2 = camlidl_alloc_small(18, 0);
  {
    mlsize_t _c9;
    for (_c9 = 0; _c9 < 18; _c9++)
      Field(_v2, _c9) = _v3[_c9];
  }
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_session_handle_t(value _v1,
					     ck_session_handle_t * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_session_handle_t(value _v1,
					     ck_session_handle_t * _c2,
					     camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_session_handle_t(ck_session_handle_t * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_session_handle_t(ck_session_handle_t * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_user_type_t(value _v1, ck_user_type_t * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_ck_user_type_t(value _v1, ck_user_type_t * _c2,
					camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_user_type_t(ck_user_type_t * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_ck_user_type_t(ck_user_type_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_state_t(value _v1, ck_state_t * _c2,
				    __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_state_t(value _v1, ck_state_t * _c2,
				    camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_state_t(ck_state_t * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_state_t(ck_state_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_session_info(value _v1,
						struct ck_session_info *_c2,
						__attribute__ ((unused))
						camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_session_info(value _v1,
						struct ck_session_info *_c2,
						camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  value _v5;
  value _v6;
  _v3 = Field(_v1, 0);
  camlidl_ml2c_pkcs11_ck_slot_id_t(_v3, &(*_c2).slot_id, _ctx);
  _v4 = Field(_v1, 1);
  camlidl_ml2c_pkcs11_ck_state_t(_v4, &(*_c2).state, _ctx);
  _v5 = Field(_v1, 2);
  camlidl_ml2c_pkcs11_ck_flags_t(_v5, &(*_c2).flags, _ctx);
  _v6 = Field(_v1, 3);
  (*_c2).device_error = custom_int_val(_v6);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_session_info(struct ck_session_info *_c1,
						 __attribute__ ((unused))
						 camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_session_info(struct ck_session_info *_c1,
						 camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[4];
  _v3[0] = _v3[1] = _v3[2] = _v3[3] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 4);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&(*_c1).slot_id, _ctx);
  _v3[1] = camlidl_c2ml_pkcs11_ck_state_t(&(*_c1).state, _ctx);
  _v3[2] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v3[3] = custom_copy_int((*_c1).device_error);
  _v2 = camlidl_alloc_small(4, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  Field(_v2, 2) = _v3[2];
  Field(_v2, 3) = _v3[3];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_object_handle_t(value _v1, ck_object_handle_t * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
void camlidl_ml2c_pkcs11_ck_object_handle_t(value _v1, ck_object_handle_t * _c2,
					    camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_object_handle_t(ck_object_handle_t * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_object_handle_t(ck_object_handle_t * _c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_object_class_t(value _v1, ck_object_class_t * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_ck_object_class_t(value _v1, ck_object_class_t * _c2,
					   camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_object_class_t(ck_object_class_t * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_ck_object_class_t(ck_object_class_t * _c2,
					    camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_hw_feature_type_t(value _v1,
					      ck_hw_feature_type_t * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_hw_feature_type_t(value _v1,
					      ck_hw_feature_type_t * _c2,
					      camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_hw_feature_type_t(ck_hw_feature_type_t * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_hw_feature_type_t(ck_hw_feature_type_t * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_key_type_t(value _v1, ck_key_type_t * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
void camlidl_ml2c_pkcs11_ck_key_type_t(value _v1, ck_key_type_t * _c2,
				       camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_key_type_t(ck_key_type_t * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
value camlidl_c2ml_pkcs11_ck_key_type_t(ck_key_type_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_certificate_type_t(value _v1,
					       ck_certificate_type_t * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_certificate_type_t(value _v1,
					       ck_certificate_type_t * _c2,
					       camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_certificate_type_t(ck_certificate_type_t * _c2,
						__attribute__ ((unused))
						camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_certificate_type_t(ck_certificate_type_t * _c2,
						camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_attribute_type_t(value _v1,
					     ck_attribute_type_t * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_attribute_type_t(value _v1,
					     ck_attribute_type_t * _c2,
					     camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_attribute_type_t(ck_attribute_type_t * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_attribute_type_t(ck_attribute_type_t * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_attribute(value _v1,
					     struct ck_attribute *_c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_attribute(value _v1,
					     struct ck_attribute *_c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  mlsize_t _c5;
  mlsize_t _c6;
  value _v7;
  _v3 = Field(_v1, 0);
  camlidl_ml2c_pkcs11_ck_attribute_type_t(_v3, &(*_c2).type_, _ctx);
  _v4 = Field(_v1, 1);
  _c5 = Wosize_val(_v4);
  /* Endianness transformations for 
     CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_KEY_TYPE, 
     CKA_KEY_GEN_MECHANISM, CKA_AUTH_PIN_FLAGS, 
     CKA_MECHANISM_TYPE */
  switch ((*_c2).type_) {
  case 0x0:
  case 0x80:
  case 0x88:
  case 0x100:
  case 0x121:
  case 0x166:
  case 0x201:
  case 0x400:
  case 0x401:
  case 0x402:
  case 0x403:
  case 0x404:
  case 0x405:
  case 0x406:
  case 0x500:{
#ifdef SERVER_ROLE
      int decode_ret = 1;
      if ((long)_c5 > 0) {
	decode_ret = decode_ck_attribute_arch(_v4, _c2, _ctx);
      }
      /* We come from OCaml cannot be negative, allocate a zero pointer */
      else {
	(*_c2).value = camlidl_malloc(_c5 * sizeof(char), _ctx);
	(*_c2).value_len = _c5;
      }
      /* Break ONLY if decode_ck_attribute_arch succeeded
       * otherwise, we want to go to the default case */
      if (decode_ret != -1) {
	break;
      }
#endif
    }
  default:{
      if ((long)_c5 >= 0) {
	(*_c2).value = camlidl_malloc(_c5 * sizeof(char), _ctx);
	for (_c6 = 0; _c6 < _c5; _c6++) {
	  _v7 = Field(_v4, _c6);
	  (*_c2).value[_c6] = Int_val(_v7);
	}
      }
      (*_c2).value_len = _c5;
      break;
    }

  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_attribute(struct ck_attribute *_c1,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_attribute(struct ck_attribute *_c1,
					      camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[2];
  mlsize_t _c4;
  value _v5;
  unsigned char buff[sizeof(uint64_t)];
  struct ck_attribute temp_;
  struct ck_attribute *temp;
  _v3[0] = _v3[1] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_c2ml_pkcs11_ck_attribute_type_t(&(*_c1).type_, _ctx);
  memset(buff, 0, sizeof(uint64_t));
  temp_.type_ = 0;
  temp_.value = (void *)buff;
  temp_.value_len = sizeof(uint64_t);
  temp = &temp_;

  *temp = *_c1;

  if ((long)(*temp).value_len >= 0) {
    /* Endianness transformations for 
       CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_KEY_TYPE,
       CKA_KEY_GEN_MECHANISM, CKA_AUTH_PIN_FLAGS,
       CKA_MECHANISM_TYPE */

#ifdef SERVER_ROLE
    switch ((*temp).type_) {
    case 0x0:
    case 0x80:
    case 0x88:
    case 0x100:
    case 0x121:
    case 0x166:
    case 0x201:
    case 0x400:
    case 0x401:
    case 0x402:
    case 0x403:
    case 0x404:
    case 0x405:
    case 0x406:
    case 0x500:{
	int encode_ret = 1;
	/* We override the pointer to temp->value */
	temp->value = (void *)buff;
	encode_ret = encode_ck_attribute_arch(_c1, temp);
	if (encode_ret == -1) {
	  /* FIXME: Something went wrong with encode_ck_attribute_arch
	   * we exit (thus terminating the child process), is there a
	   * better way to handle it.
	   */
	  exit(-1);
	}
      }

    }
#endif
    if ((*temp).value != NULL) {

      _v3[1] = camlidl_alloc((*temp).value_len, 0);

      for (_c4 = 0; _c4 < (*temp).value_len; _c4++) {
	_v5 = Val_int((unsigned char)((*temp).value[_c4]));
	modify(&Field(_v3[1], _c4), _v5);
      }
    } else {
      _v3[1] = camlidl_alloc((*temp).value_len, 0);
      for (_c4 = 0; _c4 < (*temp).value_len; _c4++) {
	_v5 = Val_int(0);
	modify(&Field(_v3[1], _c4), _v5);
      }
      /*
         int i = 0;
         char output_size[sizeof(unsigned long)];
         *((unsigned long*)output_size) = (*temp).value_len;
         _v3[1] = camlidl_alloc(sizeof(unsigned long), 0);
         for (i = 0 ; i< sizeof(unsigned long); i++){
         modify(&Field(_v3[1], i), output_size[i]);
         }
       */
    }
  } else {
    (*temp).value_len = -1;
    _v3[1] = camlidl_alloc(0, 0);
  }
  _v2 = camlidl_alloc_small(2, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_date(value _v1, struct ck_date *_c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_date(value _v1, struct ck_date *_c2,
					camlidl_ctx _ctx)
#endif
{
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _v7;
  mlsize_t _c8;
  mlsize_t _c9;
  value _v10;
  value _v11;
  mlsize_t _c12;
  mlsize_t _c13;
  value _v14;
  _v3 = Field(_v1, 0);
  _c4 = Wosize_val(_v3);
  if (_c4 != 4)
    invalid_argument("struct ck_date");
  for (_c5 = 0; _c5 < 4; _c5++) {
    _v6 = Field(_v3, _c5);
    (*_c2).year[_c5] = Int_val(_v6);
  }
  _v7 = Field(_v1, 1);
  _c8 = Wosize_val(_v7);
  if (_c8 != 2)
    invalid_argument("struct ck_date");
  for (_c9 = 0; _c9 < 2; _c9++) {
    _v10 = Field(_v7, _c9);
    (*_c2).month[_c9] = Int_val(_v10);
  }
  _v11 = Field(_v1, 2);
  _c12 = Wosize_val(_v11);
  if (_c12 != 2)
    invalid_argument("struct ck_date");
  for (_c13 = 0; _c13 < 2; _c13++) {
    _v14 = Field(_v11, _c13);
    (*_c2).day[_c13] = Int_val(_v14);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_date(struct ck_date *_c1,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_date(struct ck_date *_c1, camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[3];
  mlsize_t _c4;
  mlsize_t _c5;
  mlsize_t _c6;
  _v3[0] = _v3[1] = _v3[2] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_alloc_small(4, 0);
  for (_c4 = 0; _c4 < 4; _c4++) {
    Field(_v3[0], _c4) = Val_int((*_c1).year[_c4]);
  }
  _v3[1] = camlidl_alloc_small(2, 0);
  for (_c5 = 0; _c5 < 2; _c5++) {
    Field(_v3[1], _c5) = Val_int((*_c1).month[_c5]);
  }
  _v3[2] = camlidl_alloc_small(2, 0);
  for (_c6 = 0; _c6 < 2; _c6++) {
    Field(_v3[2], _c6) = Val_int((*_c1).day[_c6]);
  }
  _v2 = camlidl_alloc_small(3, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  Field(_v2, 2) = _v3[2];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_mechanism_type_t(value _v1,
					     ck_mechanism_type_t * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_mechanism_type_t(value _v1,
					     ck_mechanism_type_t * _c2,
					     camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_mechanism_type_t(ck_mechanism_type_t * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_mechanism_type_t(ck_mechanism_type_t * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_mechanism(value _v1,
					     struct ck_mechanism *_c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_mechanism(value _v1,
					     struct ck_mechanism *_c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  mlsize_t _c5;
  mlsize_t _c6;
  value _v7;
  _v3 = Field(_v1, 0);
  camlidl_ml2c_pkcs11_ck_mechanism_type_t(_v3, &(*_c2).mechanism, _ctx);
  _v4 = Field(_v1, 1);
  _c5 = Wosize_val(_v4);
  (*_c2).parameter = camlidl_malloc(_c5 * sizeof(char), _ctx);
  for (_c6 = 0; _c6 < _c5; _c6++) {
    _v7 = Field(_v4, _c6);
    (*_c2).parameter[_c6] = Int_val(_v7);
  }
  (*_c2).parameter_len = _c5;
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
					      camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[2];
  mlsize_t _c4;
  value _v5;
  _v3[0] = _v3[1] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&(*_c1).mechanism, _ctx);
  _v3[1] = camlidl_alloc((*_c1).parameter_len, 0);
  for (_c4 = 0; _c4 < (*_c1).parameter_len; _c4++) {
    _v5 = Val_int((unsigned char)((*_c1).parameter[_c4]));
    modify(&Field(_v3[1], _c4), _v5);
  }
  _v2 = camlidl_alloc_small(2, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_mechanism_info(value _v1,
						  struct ck_mechanism_info *_c2,
						  __attribute__ ((unused))
						  camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_mechanism_info(value _v1,
						  struct ck_mechanism_info *_c2,
						  camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  value _v5;
  _v3 = Field(_v1, 0);
  (*_c2).min_key_size = custom_int_val(_v3);
  _v4 = Field(_v1, 1);
  (*_c2).max_key_size = custom_int_val(_v4);
  _v5 = Field(_v1, 2);
  camlidl_ml2c_pkcs11_ck_flags_t(_v5, &(*_c2).flags, _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_mechanism_info(struct ck_mechanism_info
						   *_c1,
						   __attribute__ ((unused))
						   camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_mechanism_info(struct ck_mechanism_info
						   *_c1, camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[3];
  _v3[0] = _v3[1] = _v3[2] = 0;
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = custom_copy_int((*_c1).min_key_size);
  _v3[1] = custom_copy_int((*_c1).max_key_size);
  _v3[2] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v2 = camlidl_alloc_small(3, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  Field(_v2, 2) = _v3[2];
  End_roots();
  return _v2;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_BYTE(value _v1, CK_BYTE * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_BYTE(value _v1, CK_BYTE * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = Int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_BYTE(CK_BYTE * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_BYTE(CK_BYTE * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = Val_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_CHAR(value _v1, CK_CHAR * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_CHAR(value _v1, CK_CHAR * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = Int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_CHAR(CK_CHAR * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_CHAR(CK_CHAR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = Val_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_UTF8CHAR(value _v1, CK_UTF8CHAR * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_UTF8CHAR(value _v1, CK_UTF8CHAR * _c2,
				     camlidl_ctx _ctx)
#endif
{
  (*_c2) = Int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_UTF8CHAR(CK_UTF8CHAR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_UTF8CHAR(CK_UTF8CHAR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = Val_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_BBOOL(value _v1, CK_BBOOL * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_BBOOL(value _v1, CK_BBOOL * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = Int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_BBOOL(CK_BBOOL * _c2,
				   __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_BBOOL(CK_BBOOL * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = Val_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_ULONG(value _v1, CK_ULONG * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_ULONG(value _v1, CK_ULONG * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_ULONG(CK_ULONG * _c2,
				   __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_ULONG(CK_ULONG * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_LONG(value _v1, CK_LONG * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_LONG(value _v1, CK_LONG * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_LONG(CK_LONG * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_LONG(CK_LONG * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_BYTE_PTR(value _v1, CK_BYTE_PTR * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_BYTE_PTR(value _v1, CK_BYTE_PTR * _c2,
				     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (CK_BYTE *) camlidl_malloc(sizeof(CK_BYTE), _ctx);
    camlidl_ml2c_pkcs11_CK_BYTE(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_BYTE_PTR(CK_BYTE_PTR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_BYTE_PTR(CK_BYTE_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_CK_BYTE(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_CHAR_PTR(value _v1, CK_CHAR_PTR * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_CHAR_PTR(value _v1, CK_CHAR_PTR * _c2,
				     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (CK_CHAR *) camlidl_malloc(sizeof(CK_CHAR), _ctx);
    camlidl_ml2c_pkcs11_CK_CHAR(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_CHAR_PTR(CK_CHAR_PTR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_CHAR_PTR(CK_CHAR_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_CK_CHAR(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_UTF8CHAR_PTR(value _v1, CK_UTF8CHAR_PTR * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
void camlidl_ml2c_pkcs11_CK_UTF8CHAR_PTR(value _v1, CK_UTF8CHAR_PTR * _c2,
					 camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (CK_UTF8CHAR *) camlidl_malloc(sizeof(CK_UTF8CHAR), _ctx);
    camlidl_ml2c_pkcs11_CK_UTF8CHAR(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_UTF8CHAR_PTR(CK_UTF8CHAR_PTR * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
value camlidl_c2ml_pkcs11_CK_UTF8CHAR_PTR(CK_UTF8CHAR_PTR * _c2,
					  camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_CK_UTF8CHAR(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_ULONG_PTR(value _v1, CK_ULONG_PTR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_ULONG_PTR(value _v1, CK_ULONG_PTR * _c2,
				      camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (CK_ULONG *) camlidl_malloc(sizeof(CK_ULONG), _ctx);
    camlidl_ml2c_pkcs11_CK_ULONG(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_ULONG_PTR(CK_ULONG_PTR * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
value camlidl_c2ml_pkcs11_CK_ULONG_PTR(CK_ULONG_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_CK_ULONG(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_VERSION(value _v1, CK_VERSION * _c2,
				    __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_VERSION(value _v1, CK_VERSION * _c2,
				    camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_version(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_VERSION(CK_VERSION * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_VERSION(CK_VERSION * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_version(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_VERSION_PTR(value _v1, CK_VERSION_PTR * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_CK_VERSION_PTR(value _v1, CK_VERSION_PTR * _c2,
					camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_version *)camlidl_malloc(sizeof(struct ck_version), _ctx);
    camlidl_ml2c_pkcs11_struct_ck_version(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_VERSION_PTR(CK_VERSION_PTR * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_CK_VERSION_PTR(CK_VERSION_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_version(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_INFO(value _v1, CK_INFO * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_INFO(value _v1, CK_INFO * _c2, camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_info(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_INFO(CK_INFO * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_INFO(CK_INFO * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_info(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_INFO_PTR(value _v1, CK_INFO_PTR * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_INFO_PTR(value _v1, CK_INFO_PTR * _c2,
				     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (struct ck_info *)camlidl_malloc(sizeof(struct ck_info), _ctx);
    camlidl_ml2c_pkcs11_struct_ck_info(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_INFO_PTR(CK_INFO_PTR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_INFO_PTR(CK_INFO_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_info(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SLOT_ID_PTR(value _v1, CK_SLOT_ID_PTR * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_CK_SLOT_ID_PTR(value _v1, CK_SLOT_ID_PTR * _c2,
					camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (ck_slot_id_t *) camlidl_malloc(sizeof(ck_slot_id_t), _ctx);
    camlidl_ml2c_pkcs11_ck_slot_id_t(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SLOT_ID_PTR(CK_SLOT_ID_PTR * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SLOT_ID_PTR(CK_SLOT_ID_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_ck_slot_id_t(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SLOT_INFO(value _v1, CK_SLOT_INFO * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_SLOT_INFO(value _v1, CK_SLOT_INFO * _c2,
				      camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_slot_info(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SLOT_INFO(CK_SLOT_INFO * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SLOT_INFO(CK_SLOT_INFO * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_slot_info(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SLOT_INFO_PTR(value _v1, CK_SLOT_INFO_PTR * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
void camlidl_ml2c_pkcs11_CK_SLOT_INFO_PTR(value _v1, CK_SLOT_INFO_PTR * _c2,
					  camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_slot_info *)camlidl_malloc(sizeof(struct ck_slot_info),
					      _ctx);
    camlidl_ml2c_pkcs11_struct_ck_slot_info(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SLOT_INFO_PTR(CK_SLOT_INFO_PTR * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SLOT_INFO_PTR(CK_SLOT_INFO_PTR * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_slot_info(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO(value _v1, CK_TOKEN_INFO * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO(value _v1, CK_TOKEN_INFO * _c2,
				       camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_token_info(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO(CK_TOKEN_INFO * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO(CK_TOKEN_INFO * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_token_info(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO_PTR(value _v1, CK_TOKEN_INFO_PTR * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_CK_TOKEN_INFO_PTR(value _v1, CK_TOKEN_INFO_PTR * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_token_info *)camlidl_malloc(sizeof(struct ck_token_info),
					       _ctx);
    camlidl_ml2c_pkcs11_struct_ck_token_info(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO_PTR(CK_TOKEN_INFO_PTR * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_CK_TOKEN_INFO_PTR(CK_TOKEN_INFO_PTR * _c2,
					    camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_token_info(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SESSION_HANDLE_PTR(value _v1,
					       CK_SESSION_HANDLE_PTR * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_SESSION_HANDLE_PTR(value _v1,
					       CK_SESSION_HANDLE_PTR * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(ck_session_handle_t *) camlidl_malloc(sizeof(ck_session_handle_t),
					       _ctx);
    camlidl_ml2c_pkcs11_ck_session_handle_t(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SESSION_HANDLE_PTR(CK_SESSION_HANDLE_PTR * _c2,
						__attribute__ ((unused))
						camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SESSION_HANDLE_PTR(CK_SESSION_HANDLE_PTR * _c2,
						camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_ck_session_handle_t(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SESSION_INFO(value _v1, CK_SESSION_INFO * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
void camlidl_ml2c_pkcs11_CK_SESSION_INFO(value _v1, CK_SESSION_INFO * _c2,
					 camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_session_info(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SESSION_INFO(CK_SESSION_INFO * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SESSION_INFO(CK_SESSION_INFO * _c2,
					  camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_session_info(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_SESSION_INFO_PTR(value _v1,
					     CK_SESSION_INFO_PTR * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_SESSION_INFO_PTR(value _v1,
					     CK_SESSION_INFO_PTR * _c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_session_info *)camlidl_malloc(sizeof(struct ck_session_info),
						 _ctx);
    camlidl_ml2c_pkcs11_struct_ck_session_info(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_SESSION_INFO_PTR(CK_SESSION_INFO_PTR * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_SESSION_INFO_PTR(CK_SESSION_INFO_PTR * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_session_info(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_OBJECT_HANDLE_PTR(value _v1,
					      CK_OBJECT_HANDLE_PTR * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_OBJECT_HANDLE_PTR(value _v1,
					      CK_OBJECT_HANDLE_PTR * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(ck_object_handle_t *) camlidl_malloc(sizeof(ck_object_handle_t), _ctx);
    camlidl_ml2c_pkcs11_ck_object_handle_t(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_OBJECT_HANDLE_PTR(CK_OBJECT_HANDLE_PTR * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_OBJECT_HANDLE_PTR(CK_OBJECT_HANDLE_PTR * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_OBJECT_CLASS_PTR(value _v1,
					     CK_OBJECT_CLASS_PTR * _c2,
					     __attribute__ ((unused))
					     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_OBJECT_CLASS_PTR(value _v1,
					     CK_OBJECT_CLASS_PTR * _c2,
					     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(ck_object_class_t *) camlidl_malloc(sizeof(ck_object_class_t), _ctx);
    camlidl_ml2c_pkcs11_ck_object_class_t(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_OBJECT_CLASS_PTR(CK_OBJECT_CLASS_PTR * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_OBJECT_CLASS_PTR(CK_OBJECT_CLASS_PTR * _c2,
					      camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_ck_object_class_t(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE(value _v1, CK_ATTRIBUTE * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE(value _v1, CK_ATTRIBUTE * _c2,
				      camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_attribute(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE(CK_ATTRIBUTE * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE(CK_ATTRIBUTE * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_attribute(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE_PTR(value _v1, CK_ATTRIBUTE_PTR * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
void camlidl_ml2c_pkcs11_CK_ATTRIBUTE_PTR(value _v1, CK_ATTRIBUTE_PTR * _c2,
					  camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_attribute *)camlidl_malloc(sizeof(struct ck_attribute),
					      _ctx);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE_PTR(CK_ATTRIBUTE_PTR * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
value camlidl_c2ml_pkcs11_CK_ATTRIBUTE_PTR(CK_ATTRIBUTE_PTR * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_attribute(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_DATE(value _v1, CK_DATE * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_DATE(value _v1, CK_DATE * _c2, camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_date(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_DATE(CK_DATE * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_DATE(CK_DATE * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_date(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_DATE_PTR(value _v1, CK_DATE_PTR * _c2,
				     __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_DATE_PTR(value _v1, CK_DATE_PTR * _c2,
				     camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (struct ck_date *)camlidl_malloc(sizeof(struct ck_date), _ctx);
    camlidl_ml2c_pkcs11_struct_ck_date(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_DATE_PTR(CK_DATE_PTR * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_DATE_PTR(CK_DATE_PTR * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_date(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_MECHANISM_TYPE_PTR(value _v1,
					       CK_MECHANISM_TYPE_PTR * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_MECHANISM_TYPE_PTR(value _v1,
					       CK_MECHANISM_TYPE_PTR * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(ck_mechanism_type_t *) camlidl_malloc(sizeof(ck_mechanism_type_t),
					       _ctx);
    camlidl_ml2c_pkcs11_ck_mechanism_type_t(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_MECHANISM_TYPE_PTR(CK_MECHANISM_TYPE_PTR * _c2,
						__attribute__ ((unused))
						camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_MECHANISM_TYPE_PTR(CK_MECHANISM_TYPE_PTR * _c2,
						camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_MECHANISM(value _v1, CK_MECHANISM * _c2,
				      __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_MECHANISM(value _v1, CK_MECHANISM * _c2,
				      camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_MECHANISM(CK_MECHANISM * _c2,
				       __attribute__ ((unused)) camlidl_ctx
				       _ctx)
#else
value camlidl_c2ml_pkcs11_CK_MECHANISM(CK_MECHANISM * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_mechanism(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_MECHANISM_PTR(value _v1, CK_MECHANISM_PTR * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
void camlidl_ml2c_pkcs11_CK_MECHANISM_PTR(value _v1, CK_MECHANISM_PTR * _c2,
					  camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) =
	(struct ck_mechanism *)camlidl_malloc(sizeof(struct ck_mechanism),
					      _ctx);
    camlidl_ml2c_pkcs11_struct_ck_mechanism(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_MECHANISM_PTR(CK_MECHANISM_PTR * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
value camlidl_c2ml_pkcs11_CK_MECHANISM_PTR(CK_MECHANISM_PTR * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_mechanism(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO(value _v1, CK_MECHANISM_INFO * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO(value _v1, CK_MECHANISM_INFO * _c2,
					   camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_mechanism_info(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO(CK_MECHANISM_INFO * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO(CK_MECHANISM_INFO * _c2,
					    camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_mechanism_info(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO_PTR(value _v1,
					       CK_MECHANISM_INFO_PTR * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_MECHANISM_INFO_PTR(value _v1,
					       CK_MECHANISM_INFO_PTR * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (struct ck_mechanism_info *)
	camlidl_malloc(sizeof(struct ck_mechanism_info), _ctx);
    camlidl_ml2c_pkcs11_struct_ck_mechanism_info(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO_PTR(CK_MECHANISM_INFO_PTR * _c2,
						__attribute__ ((unused))
						camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_MECHANISM_INFO_PTR(CK_MECHANISM_INFO_PTR * _c2,
						camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_mechanism_info(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

extern void camlidl_ml2c_pkcs11_struct_ck_c_initialize_args(value, struct
							    ck_c_initialize_args
							    *,
							    camlidl_ctx _ctx);
extern value camlidl_c2ml_pkcs11_struct_ck_c_initialize_args(struct
							     ck_c_initialize_args
							     *,
							     camlidl_ctx _ctx);

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS(value _v1,
					      CK_C_INITIALIZE_ARGS * _c2,
					      __attribute__ ((unused))
					      camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS(value _v1,
					      CK_C_INITIALIZE_ARGS * _c2,
					      camlidl_ctx _ctx)
#endif
{
  camlidl_ml2c_pkcs11_struct_ck_c_initialize_args(_v1, &(*_c2), _ctx);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS(CK_C_INITIALIZE_ARGS * _c2,
					       __attribute__ ((unused))
					       camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS(CK_C_INITIALIZE_ARGS * _c2,
					       camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = camlidl_c2ml_pkcs11_struct_ck_c_initialize_args(&(*_c2), _ctx);
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS_PTR(value _v1,
						  CK_C_INITIALIZE_ARGS_PTR *
						  _c2, __attribute__ ((unused))
						  camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_CK_C_INITIALIZE_ARGS_PTR(value _v1,
						  CK_C_INITIALIZE_ARGS_PTR *
						  _c2, camlidl_ctx _ctx)
#endif
{
  value _v3;
  if (_v1 == Val_int(0)) {
    (*_c2) = NULL;
  } else {
    _v3 = Field(_v1, 0);
    (*_c2) = (struct ck_c_initialize_args *)
	camlidl_malloc(sizeof(struct ck_c_initialize_args), _ctx);
    camlidl_ml2c_pkcs11_struct_ck_c_initialize_args(_v3, &*(*_c2), _ctx);
  }
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS_PTR(CK_C_INITIALIZE_ARGS_PTR *
						   _c2, __attribute__ ((unused))
						   camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_CK_C_INITIALIZE_ARGS_PTR(CK_C_INITIALIZE_ARGS_PTR *
						   _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  value _v3;
  if ((*_c2) == NULL) {
    _v1 = Val_int(0);
  } else {
    _v3 = camlidl_c2ml_pkcs11_struct_ck_c_initialize_args(&*(*_c2), _ctx);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_v3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    _v1 = camlidl_alloc_small(1, 0);
    Field(_v1, 0) = _v3;
    End_roots();
  }
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_rv_t(value _v1, ck_rv_t * _c2,
				 __attribute__ ((unused)) camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_ck_rv_t(value _v1, ck_rv_t * _c2, camlidl_ctx _ctx)
#endif
{
  (*_c2) = custom_int_val(_v1);
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_rv_t(ck_rv_t * _c2,
				  __attribute__ ((unused)) camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_ck_rv_t(ck_rv_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 = custom_copy_int((*_c2));
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_createmutex_t(value _v1, ck_createmutex_t * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
void camlidl_ml2c_pkcs11_ck_createmutex_t(value _v1, ck_createmutex_t * _c2,
					  camlidl_ctx _ctx)
#endif
{
  *_c2 = *((ck_createmutex_t *) Bp_val(_v1));
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_createmutex_t(ck_createmutex_t * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
value camlidl_c2ml_pkcs11_ck_createmutex_t(ck_createmutex_t * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 =
      camlidl_alloc((sizeof(ck_createmutex_t) + sizeof(value) -
		     1) / sizeof(value), Abstract_tag);
  *((ck_createmutex_t *) Bp_val(_v1)) = *_c2;
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_destroymutex_t(value _v1, ck_destroymutex_t * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
void camlidl_ml2c_pkcs11_ck_destroymutex_t(value _v1, ck_destroymutex_t * _c2,
					   camlidl_ctx _ctx)
#endif
{
  *_c2 = *((ck_destroymutex_t *) Bp_val(_v1));
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_destroymutex_t(ck_destroymutex_t * _c2,
					    __attribute__ ((unused)) camlidl_ctx
					    _ctx)
#else
value camlidl_c2ml_pkcs11_ck_destroymutex_t(ck_destroymutex_t * _c2,
					    camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 =
      camlidl_alloc((sizeof(ck_destroymutex_t) + sizeof(value) -
		     1) / sizeof(value), Abstract_tag);
  *((ck_destroymutex_t *) Bp_val(_v1)) = *_c2;
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_lockmutex_t(value _v1, ck_lockmutex_t * _c2,
					__attribute__ ((unused)) camlidl_ctx
					_ctx)
#else
void camlidl_ml2c_pkcs11_ck_lockmutex_t(value _v1, ck_lockmutex_t * _c2,
					camlidl_ctx _ctx)
#endif
{
  *_c2 = *((ck_lockmutex_t *) Bp_val(_v1));
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_lockmutex_t(ck_lockmutex_t * _c2,
					 __attribute__ ((unused)) camlidl_ctx
					 _ctx)
#else
value camlidl_c2ml_pkcs11_ck_lockmutex_t(ck_lockmutex_t * _c2, camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 =
      camlidl_alloc((sizeof(ck_lockmutex_t) + sizeof(value) -
		     1) / sizeof(value), Abstract_tag);
  *((ck_lockmutex_t *) Bp_val(_v1)) = *_c2;
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_ck_unlockmutex_t(value _v1, ck_unlockmutex_t * _c2,
					  __attribute__ ((unused)) camlidl_ctx
					  _ctx)
#else
void camlidl_ml2c_pkcs11_ck_unlockmutex_t(value _v1, ck_unlockmutex_t * _c2,
					  camlidl_ctx _ctx)
#endif
{
  *_c2 = *((ck_unlockmutex_t *) Bp_val(_v1));
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_ck_unlockmutex_t(ck_unlockmutex_t * _c2,
					   __attribute__ ((unused)) camlidl_ctx
					   _ctx)
#else
value camlidl_c2ml_pkcs11_ck_unlockmutex_t(ck_unlockmutex_t * _c2,
					   camlidl_ctx _ctx)
#endif
{
  value _v1;
  _v1 =
      camlidl_alloc((sizeof(ck_unlockmutex_t) + sizeof(value) -
		     1) / sizeof(value), Abstract_tag);
  *((ck_unlockmutex_t *) Bp_val(_v1)) = *_c2;
  return _v1;
}

#ifdef __GNUC__
void camlidl_ml2c_pkcs11_struct_ck_c_initialize_args(value _v1, struct ck_c_initialize_args
						     *_c2,
						     __attribute__ ((unused))
						     camlidl_ctx _ctx)
#else
void camlidl_ml2c_pkcs11_struct_ck_c_initialize_args(value _v1, struct ck_c_initialize_args
						     *_c2, camlidl_ctx _ctx)
#endif
{
  value _v3;
  value _v4;
  value _v5;
  value _v6;
  value _v7;
  _v3 = Field(_v1, 0);
  camlidl_ml2c_pkcs11_ck_createmutex_t(_v3, &(*_c2).create_mutex, _ctx);
  _v4 = Field(_v1, 1);
  camlidl_ml2c_pkcs11_ck_destroymutex_t(_v4, &(*_c2).destroy_mutex, _ctx);
  _v5 = Field(_v1, 2);
  camlidl_ml2c_pkcs11_ck_lockmutex_t(_v5, &(*_c2).lock_mutex, _ctx);
  _v6 = Field(_v1, 3);
  camlidl_ml2c_pkcs11_ck_unlockmutex_t(_v6, &(*_c2).unlock_mutex, _ctx);
  _v7 = Field(_v1, 4);
  camlidl_ml2c_pkcs11_ck_flags_t(_v7, &(*_c2).flags, _ctx);
  (*_c2).reserved = NULL;
}

#ifdef __GNUC__
value camlidl_c2ml_pkcs11_struct_ck_c_initialize_args(struct
						      ck_c_initialize_args *_c1,
						      __attribute__ ((unused))
						      camlidl_ctx _ctx)
#else
value camlidl_c2ml_pkcs11_struct_ck_c_initialize_args(struct
						      ck_c_initialize_args *_c1,
						      camlidl_ctx _ctx)
#endif
{
  value _v2;
  value _v3[5];
  memset(_v3, 0, 5 * sizeof(value));
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_v3, 5);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _v3[0] = camlidl_c2ml_pkcs11_ck_createmutex_t(&(*_c1).create_mutex, _ctx);
  _v3[1] = camlidl_c2ml_pkcs11_ck_destroymutex_t(&(*_c1).destroy_mutex, _ctx);
  _v3[2] = camlidl_c2ml_pkcs11_ck_lockmutex_t(&(*_c1).lock_mutex, _ctx);
  _v3[3] = camlidl_c2ml_pkcs11_ck_unlockmutex_t(&(*_c1).unlock_mutex, _ctx);
  _v3[4] = camlidl_c2ml_pkcs11_ck_flags_t(&(*_c1).flags, _ctx);
  _v2 = camlidl_alloc_small(5, 0);
  {
    mlsize_t _c4;
    for (_c4 = 0; _c4 < 5; _c4++)
      Field(_v2, _c4) = _v3[_c4];
  }
  End_roots();
  return _v2;
}

#define MAX_BUFF_LEN 16384

#define CKR_OK					(0UL)

value camlidl_pkcs11_ML_CK_C_Daemonize(value _v_param)
{
  unsigned char *param;		/*in */
  unsigned long param_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  _c1 = Wosize_val(_v_param);
  param = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_param, _c2);
    param[_c2] = Int_val(_v3);
  }
  param_len = _c1;
  _res = ML_CK_C_Daemonize(param, param_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_SetupArch(value _v_arch)
{
  unsigned int arch;		/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  arch = custom_int_val(_v_arch);
  /* Check if SetupArch was previously called, if so, return -1 */
  if (peer_arch != NOT_INITIALIZED) {
#ifdef DEBUG
    fprintf(stderr, "Multiple C_SetupArch calls is invalid, ignoring\n");
#endif
    _res = -1;
    _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
    camlidl_free(_ctx);
    return _vres;
  }
  _res = ML_CK_C_SetupArch(arch);
  /* Initialize local architecture */
  if (_res != UNSUPPORTED_ARCHITECTURE) {
    peer_arch = arch;
    my_arch = _res;
  }
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_LoadModule(value _v_libname)
{
  unsigned char *libname;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  _c1 = Wosize_val(_v_libname);
  libname = camlidl_malloc((_c1 + 1) * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_libname, _c2);
    libname[_c2] = Int_val(_v3);
  }
  libname[_c1] = 0;
#ifdef SERVER_ROLE
  /* Check if LoadModule was previously called, if so, return -1 */
  if (module_loaded != NOT_INITIALIZED) {
#ifdef DEBUG
    fprintf(stderr, "Multiple C_LoadModule calls is invalid, ignoring\n");
#endif
    _res = -1;
    _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
    camlidl_free(_ctx);
    return _vres;
  }
#endif
  _res = ML_CK_C_LoadModule(libname);
#ifdef SERVER_ROLE
  if (_res == CKR_OK) {
    module_loaded = CKR_OK;
  }
#endif
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

#ifdef __GNUC__
value camlidl_pkcs11_ML_CK_C_Initialize( __attribute__ ((unused)) value _unit)
#else
value camlidl_pkcs11_ML_CK_C_Initialize(value _unit)
#endif
{
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  _res = ML_CK_C_Initialize();
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

#ifdef __GNUC__
value camlidl_pkcs11_ML_CK_C_Finalize( __attribute__ ((unused)) value _unit)
#else
value camlidl_pkcs11_ML_CK_C_Finalize(value _unit)
#endif
{
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  _res = ML_CK_C_Finalize();
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetSlotList(value _v_token_present, value _v_count)
{
  unsigned int token_present;	/*in */
  ck_slot_id_t *slot_list;	/*out */
  unsigned long count;		/*in */
  unsigned long *real_count;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  mlsize_t _c2;
  value _v3;
  value _vresult;
  value _vres[3] = { 0, 0, 0, };

  token_present = custom_int_val(_v_token_present);
  count = custom_int_val(_v_count);
  slot_list = camlidl_malloc(count * sizeof(ck_slot_id_t), _ctx);
  real_count = &_c1;
  _res = ML_CK_C_GetSlotList(token_present, slot_list, count, real_count);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  /* If we have got an error from PKCS#11 functions */
  /* we return an empty array to the caml side      */
  if (_res != CKR_OK) {
    count = 0;
  }
  if (count > *real_count) {
    _vres[1] = camlidl_alloc(*real_count, 0);
  } else {
    _vres[1] = camlidl_alloc(count, 0);
  }
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_root(_vres[1]);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  for (_c2 = 0; _c2 < count; _c2++) {
    _v3 = camlidl_c2ml_pkcs11_ck_slot_id_t(&slot_list[_c2], _ctx);
    modify(&Field(_vres[1], _c2), _v3);
  }
  End_roots();
  _vres[2] = custom_copy_int(*real_count);
  _vresult = camlidl_alloc_small(3, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  Field(_vresult, 2) = _vres[2];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

#ifdef __GNUC__
value camlidl_pkcs11_ML_CK_C_GetInfo( __attribute__ ((unused)) value _unit)
#else
value camlidl_pkcs11_ML_CK_C_GetInfo(value _unit)
#endif
{
  struct ck_info *info;		/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  struct ck_info _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  info = &_c1;
  _res = ML_CK_C_GetInfo(info);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_struct_ck_info(&*info, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_WaitForSlotEvent(value _v_flags)
{
  ck_flags_t flags;		/*in */
  ck_slot_id_t *slot_id;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  ck_slot_id_t _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_flags_t(_v_flags, &flags, _ctx);
  slot_id = &_c1;
  _res = ML_CK_C_WaitForSlotEvent(flags, slot_id);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_slot_id_t(&*slot_id, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_GetSlotInfo(value _v_slot_id)
{
  ck_slot_id_t slot_id;		/*in */
  struct ck_slot_info *info;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  struct ck_slot_info _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  info = &_c1;
  _res = ML_CK_C_GetSlotInfo(slot_id, info);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_struct_ck_slot_info(&*info, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_GetTokenInfo(value _v_slot_id)
{
  ck_slot_id_t slot_id;		/*in */
  struct ck_token_info *info;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  struct ck_token_info _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  info = &_c1;
  _res = ML_CK_C_GetTokenInfo(slot_id, info);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_struct_ck_token_info(&*info, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_InitToken(value _v_slot_id,
				       value _v_pin, value _v_label)
{
  ck_slot_id_t slot_id;		/*in */
  unsigned char *pin;		/*in */
  unsigned long pin_len;	/*in */
  unsigned char *label;		/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  _c1 = Wosize_val(_v_pin);
  pin = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_pin, _c2);
    pin[_c2] = Int_val(_v3);
  }
  pin_len = _c1;
  _c4 = Wosize_val(_v_label);
  label = camlidl_malloc((_c4 + 1) * sizeof(unsigned char), _ctx);
  for (_c5 = 0; _c5 < _c4; _c5++) {
    _v6 = Field(_v_label, _c5);
    label[_c5] = Int_val(_v6);
  }
  label[_c4] = 0;
  _res = ML_CK_C_InitToken(slot_id, pin, pin_len, label);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_OpenSession(value _v_slot_id, value _v_flags)
{
  ck_slot_id_t slot_id;		/*in */
  ck_flags_t flags;		/*in */
  ck_session_handle_t *session;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  ck_session_handle_t _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  camlidl_ml2c_pkcs11_ck_flags_t(_v_flags, &flags, _ctx);
  session = &_c1;
  _res = ML_CK_C_OpenSession(slot_id, flags, session);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_session_handle_t(&*session, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_CloseSession(value _v_session)
{
  ck_session_handle_t session;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_CloseSession(session);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_CloseAllSessions(value _v_slot_id)
{
  ck_slot_id_t slot_id;		/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  _res = ML_CK_C_CloseAllSessions(slot_id);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetSessionInfo(value _v_session)
{
  ck_session_handle_t session;	/*in */
  struct ck_session_info *info;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  struct ck_session_info _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  info = &_c1;
  _res = ML_CK_C_GetSessionInfo(session, info);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_struct_ck_session_info(&*info, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_Login(value _v_session,
				   value _v_user_type, value _v_pin)
{
  ck_session_handle_t session;	/*in */
  ck_user_type_t user_type;	/*in */
  unsigned char *pin;		/*in */
  unsigned long pin_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_user_type_t(_v_user_type, &user_type, _ctx);
  _c1 = Wosize_val(_v_pin);
  pin = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_pin, _c2);
    pin[_c2] = Int_val(_v3);
  }
  pin_len = _c1;
  _res = ML_CK_C_Login(session, user_type, pin, pin_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Logout(value _v_session)
{
  ck_session_handle_t session;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_Logout(session);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetMechanismList(value _v_slot_id, value _v_count)
{
  ck_slot_id_t slot_id;		/*in */
  ck_mechanism_type_t *mechanism_list;	/*out */
  unsigned long count;		/*in */
  unsigned long *real_count;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  mlsize_t _c2;
  value _v3;
  value _vresult;
  value _vres[3] = { 0, 0, 0, };

  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  count = custom_int_val(_v_count);
  mechanism_list = camlidl_malloc(count * sizeof(ck_mechanism_type_t), _ctx);
  real_count = &_c1;
  _res = ML_CK_C_GetMechanismList(slot_id, mechanism_list, count, real_count);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  /* If we have got an error from PKCS#11 functions */
  /* we return an empty array to the caml side      */
  if (_res != CKR_OK) {
    count = 0;
  }
  if (count > *real_count) {
    _vres[1] = camlidl_alloc(*real_count, 0);
  } else {
    _vres[1] = camlidl_alloc(count, 0);
  }
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_root(_vres[1]);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  for (_c2 = 0; _c2 < count; _c2++) {
    _v3 = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&mechanism_list[_c2], _ctx);
    modify(&Field(_vres[1], _c2), _v3);
  }
  End_roots();
  _vres[2] = custom_copy_int(*real_count);
  _vresult = camlidl_alloc_small(3, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  Field(_vresult, 2) = _vres[2];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_GetMechanismInfo(value _v_slot_id,
					      value _v_mechanism)
{
  ck_slot_id_t slot_id;		/*in */
  ck_mechanism_type_t mechanism;	/*in */
  struct ck_mechanism_info *info;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  struct ck_mechanism_info _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_slot_id_t(_v_slot_id, &slot_id, _ctx);
  camlidl_ml2c_pkcs11_ck_mechanism_type_t(_v_mechanism, &mechanism, _ctx);
  info = &_c1;
  _res = ML_CK_C_GetMechanismInfo(slot_id, mechanism, info);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_struct_ck_mechanism_info(&*info, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_InitPIN(value _v_session, value _v_pin)
{
  ck_session_handle_t session;	/*in */
  unsigned char *pin;		/*in */
  unsigned long pin_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_pin);
  pin = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_pin, _c2);
    pin[_c2] = Int_val(_v3);
  }
  pin_len = _c1;
  _res = ML_CK_C_InitPIN(session, pin, pin_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_SetPIN(value _v_session,
				    value _v_old_pin, value _v_new_pin)
{
  ck_session_handle_t session;	/*in */
  unsigned char *old_pin;	/*in */
  unsigned long old_pin_len;	/*in */
  unsigned char *new_pin;	/*in */
  unsigned long new_pin_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_old_pin);
  old_pin = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_old_pin, _c2);
    old_pin[_c2] = Int_val(_v3);
  }
  old_pin_len = _c1;
  _c4 = Wosize_val(_v_new_pin);
  new_pin = camlidl_malloc(_c4 * sizeof(unsigned char), _ctx);
  for (_c5 = 0; _c5 < _c4; _c5++) {
    _v6 = Field(_v_new_pin, _c5);
    new_pin[_c5] = Int_val(_v6);
  }
  new_pin_len = _c4;
  _res = ML_CK_C_SetPIN(session, old_pin, old_pin_len, new_pin, new_pin_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_SeedRandom(value _v_session, value _v_seed)
{
  ck_session_handle_t session;	/*in */
  unsigned char *seed;		/*in */
  unsigned long seed_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_seed);
  seed = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_seed, _c2);
    seed[_c2] = Int_val(_v3);
  }
  seed_len = _c1;
  _res = ML_CK_C_SeedRandom(session, seed, seed_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GenerateRandom(value _v_session, value _v_rand_len)
{
  ck_session_handle_t session;	/*in */
  unsigned char *rand_value;	/*out */
  unsigned long rand_len;	/*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  rand_len = custom_int_val(_v_rand_len);
  rand_value = camlidl_malloc(rand_len * sizeof(unsigned char), _ctx);
  _res = ML_CK_C_GenerateRandom(session, rand_value, rand_len);
  /* If for some reason the function fails, return an empty array */
  if (_res != CKR_OK) {
    rand_len = 0;
  }
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(rand_len, 0);
  for (_c1 = 0; _c1 < rand_len; _c1++) {
    _v2 = Val_int(rand_value[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_FindObjectsInit(value _v_session, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  _res = ML_CK_C_FindObjectsInit(session, templ, count);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_FindObjects(value _v_session,
					 value _v_max_object_count)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t *object;	/*out */
  unsigned long max_object_count;	/*in */
  unsigned long *object_count;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  mlsize_t _c2;
  value _v3;
  value _vresult;
  value _vres[3] = { 0, 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  max_object_count = custom_int_val(_v_max_object_count);
  object = camlidl_malloc(max_object_count * sizeof(ck_object_handle_t), _ctx);
  object_count = &_c1;
  _res = ML_CK_C_FindObjects(session, object, max_object_count, object_count);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  if (max_object_count > *object_count) {
    _vres[1] = camlidl_alloc(*object_count, 0);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_vres[1]);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    for (_c2 = 0; _c2 < *object_count; _c2++) {
      _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&object[_c2], _ctx);
      modify(&Field(_vres[1], _c2), _v3);
    }
    End_roots();
  } else {
    _vres[1] = camlidl_alloc(max_object_count, 0);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    Begin_root(_vres[1]);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
    for (_c2 = 0; _c2 < max_object_count; _c2++) {
      _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&object[_c2], _ctx);
      modify(&Field(_vres[1], _c2), _v3);
    }
    End_roots();
  }
  _vres[2] = custom_copy_int(*object_count);
  _vresult = camlidl_alloc_small(3, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  Field(_vresult, 2) = _vres[2];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_FindObjectsFinal(value _v_session)
{
  ck_session_handle_t session;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_FindObjectsFinal(session);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GenerateKey(value _v_session,
					 value _v_mechanism, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_object_handle_t *phkey;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  ck_object_handle_t _c4;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  phkey = &_c4;
  _res = ML_CK_C_GenerateKey(session, mechanism, templ, count, phkey);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phkey, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_GenerateKeyPair(value _v_session,
					     value _v_mechanism,
					     value _v_pub_templ,
					     value _v_priv_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  struct ck_attribute *pub_templ;	/*in */
  unsigned long pub_count;	/*in */
  struct ck_attribute *priv_templ;	/*in */
  unsigned long priv_count;	/*in */
  ck_object_handle_t *phpubkey;	/*out */
  ck_object_handle_t *phprivkey;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  ck_object_handle_t _c7;
  ck_object_handle_t _c8;
  value _vresult;
  value _vres[3] = { 0, 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  _c1 = Wosize_val(_v_pub_templ);
  pub_templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_pub_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &pub_templ[_c2], _ctx);
  }
  pub_count = _c1;
  _c4 = Wosize_val(_v_priv_templ);
  priv_templ = camlidl_malloc(_c4 * sizeof(struct ck_attribute), _ctx);
  for (_c5 = 0; _c5 < _c4; _c5++) {
    _v6 = Field(_v_priv_templ, _c5);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v6, &priv_templ[_c5], _ctx);
  }
  priv_count = _c4;
  phpubkey = &_c7;
  phprivkey = &_c8;
  _res =
      ML_CK_C_GenerateKeyPair(session, mechanism, pub_templ, pub_count,
			      priv_templ, priv_count, phpubkey, phprivkey);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 3);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phpubkey, _ctx);
  _vres[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phprivkey, _ctx);
  _vresult = camlidl_alloc_small(3, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  Field(_vresult, 2) = _vres[2];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_CreateObject(value _v_session, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_object_handle_t *phobject;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  ck_object_handle_t _c4;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  phobject = &_c4;
  _res = ML_CK_C_CreateObject(session, templ, count, phobject);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phobject, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_CopyObject(value _v_session,
					value _v_hobject, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hobject;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_object_handle_t *phnewobject;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  ck_object_handle_t _c4;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hobject, &hobject, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  phnewobject = &_c4;
  _res = ML_CK_C_CopyObject(session, hobject, templ, count, phnewobject);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phnewobject, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DestroyObject(value _v_session, value _v_hobject)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hobject;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hobject, &hobject, _ctx);
  _res = ML_CK_C_DestroyObject(session, hobject);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetAttributeValue(value _v_session,
					       value _v_hobject, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hobject;	/*in */
  struct ck_attribute *templ;	/*in,out */
  unsigned long count;		/*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hobject, &hobject, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  _res = ML_CK_C_GetAttributeValue(session, hobject, templ, count);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(count, 0);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_root(_vres[1]);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  for (_c4 = 0; _c4 < count; _c4++) {
    _v5 = camlidl_c2ml_pkcs11_struct_ck_attribute(&templ[_c4], _ctx);
    modify(&Field(_vres[1], _c4), _v5);
  }
  End_roots();
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SetAttributeValue(value _v_session,
					       value _v_hobject, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hobject;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hobject, &hobject, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  _res = ML_CK_C_SetAttributeValue(session, hobject, templ, count);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetObjectSize(value _v_session, value _v_hobject)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hobject;	/*in */
  unsigned long *object_size;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hobject, &hobject, _ctx);
  object_size = &_c1;
  _res = ML_CK_C_GetObjectSize(session, hobject, object_size);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = custom_copy_int(*object_size);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_WrapKey(value _v_session,
				     value _v_mechanism,
				     value _v_hwrappingkey, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hwrappingkey;	/*in */
  ck_object_handle_t hkey;	/*in */
  unsigned char *wrapped_key;
  unsigned long tmp_wrapped_key_len = MAX_BUFF_LEN;
  unsigned long *wrapped_key_len = &tmp_wrapped_key_len;	/*in */
  unsigned char tmp_buff[MAX_BUFF_LEN];
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
  wrapped_key = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hwrappingkey, &hwrappingkey, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res =
      ML_CK_C_WrapKey(session, mechanism, hwrappingkey, hkey, wrapped_key,
		      wrapped_key_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*wrapped_key_len, 0);
  for (_c1 = 0; _c1 < *wrapped_key_len; _c1++) {
    _v2 = Val_int(wrapped_key[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_UnwrapKey(value _v_session,
				       value _v_mechanism,
				       value _v_hunwrappingkey,
				       value _v_wrapped_key, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hunwrappingkey;	/*in */
  unsigned char *wrapped_key;	/*in */
  unsigned long wrapped_key_len;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_object_handle_t *phobject;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  ck_object_handle_t _c7;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hunwrappingkey, &hunwrappingkey,
					 _ctx);
  _c1 = Wosize_val(_v_wrapped_key);
  wrapped_key = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_wrapped_key, _c2);
    wrapped_key[_c2] = Int_val(_v3);
  }
  wrapped_key_len = _c1;
  _c4 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c4 * sizeof(struct ck_attribute), _ctx);
  for (_c5 = 0; _c5 < _c4; _c5++) {
    _v6 = Field(_v_templ, _c5);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v6, &templ[_c5], _ctx);
  }
  count = _c4;
  phobject = &_c7;
  _res =
      ML_CK_C_UnwrapKey(session, mechanism, hunwrappingkey, wrapped_key,
			wrapped_key_len, templ, count, phobject);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phobject, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DeriveKey(value _v_session,
				       value _v_mechanism,
				       value _v_hbasekey, value _v_templ)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hbasekey;	/*in */
  struct ck_attribute *templ;	/*in */
  unsigned long count;		/*in */
  ck_object_handle_t *phkey;	/*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  ck_object_handle_t _c4;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hbasekey, &hbasekey, _ctx);
  _c1 = Wosize_val(_v_templ);
  templ = camlidl_malloc(_c1 * sizeof(struct ck_attribute), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_templ, _c2);
    camlidl_ml2c_pkcs11_struct_ck_attribute(_v3, &templ[_c2], _ctx);
  }
  count = _c1;
  phkey = &_c4;
  _res = ML_CK_C_DeriveKey(session, mechanism, hbasekey, templ, count, phkey);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&*phkey, _ctx);
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DigestInit(value _v_session, value _v_mechanism)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  _res = ML_CK_C_DigestInit(session, mechanism);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Digest(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *digest;
  unsigned char tmp_buff[MAX_BUFF_LEN];
  unsigned long tmp_digest_len = MAX_BUFF_LEN;
  unsigned long *digest_len = &tmp_digest_len;	/*in */
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
  digest = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_Digest(session, data, data_len, digest, digest_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*digest_len, 0);
  for (_c4 = 0; _c4 < *digest_len; _c4++) {
    _v5 = Val_int(digest[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DigestUpdate(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_DigestUpdate(session, data, data_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_DigestKey(value _v_session, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_DigestKey(session, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_DigestFinal(value _v_session)
{
  ck_session_handle_t session;	/*in */
  unsigned char *digest;
  unsigned long tmp_digest_len = MAX_BUFF_LEN;
  unsigned long *digest_len = &tmp_digest_len;	/*in */
  unsigned char tmp_buff[MAX_BUFF_LEN];
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
  digest = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_DigestFinal(session, digest, digest_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*digest_len, 0);
  for (_c1 = 0; _c1 < *digest_len; _c1++) {
    _v2 = Val_int(digest[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SignInit(value _v_session,
				      value _v_mechanism, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_SignInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_SignRecoverInit(value _v_session,
					     value _v_mechanism, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_SignRecoverInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Sign(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *signature;
  unsigned long tmp_signed_len = MAX_BUFF_LEN;
  unsigned long *signed_len = &tmp_signed_len;	/*in */
  unsigned char tmp_buff[MAX_BUFF_LEN];
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
  signature = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_Sign(session, data, data_len, signature, signed_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*signed_len, 0);
  for (_c4 = 0; _c4 < *signed_len; _c4++) {
    _v5 = Val_int(signature[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SignRecover(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *signature;
  unsigned long tmp_signed_len = MAX_BUFF_LEN;
  unsigned long *signed_len = &tmp_signed_len;	/*in */
  unsigned char tmp_buff[MAX_BUFF_LEN];
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
  signature = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_SignRecover(session, data, data_len, signature, signed_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*signed_len, 0);
  for (_c4 = 0; _c4 < *signed_len; _c4++) {
    _v5 = Val_int(signature[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SignUpdate(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_SignUpdate(session, data, data_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_SignFinal(value _v_session)
{
  ck_session_handle_t session;	/*in */
  unsigned char *signature;
  unsigned long tmp_signed_len = MAX_BUFF_LEN;
  unsigned long *signed_len = &tmp_signed_len;	/*in */
  unsigned char tmp_buff[MAX_BUFF_LEN];
  /*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
  signature = tmp_buff;

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_SignFinal(session, signature, signed_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*signed_len, 0);
  for (_c1 = 0; _c1 < *signed_len; _c1++) {
    _v2 = Val_int(signature[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_VerifyInit(value _v_session,
					value _v_mechanism, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_VerifyInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_VerifyRecoverInit(value _v_session,
					       value _v_mechanism,
					       value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_VerifyRecoverInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Verify(value _v_session,
				    value _v_data, value _v_signature)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *signature;	/*in */
  unsigned long signed_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  mlsize_t _c5;
  value _v6;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _c4 = Wosize_val(_v_signature);
  signature = camlidl_malloc(_c4 * sizeof(unsigned char), _ctx);
  for (_c5 = 0; _c5 < _c4; _c5++) {
    _v6 = Field(_v_signature, _c5);
    signature[_c5] = Int_val(_v6);
  }
  signed_len = _c4;
  _res = ML_CK_C_Verify(session, data, data_len, signature, signed_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_VerifyRecover(value _v_session, value _v_signature)
{
  ck_session_handle_t session;	/*in */
  unsigned char *signature;	/*in */
  unsigned long signature_len;	/*in */
  unsigned char *data;		/*out */
  unsigned long tmp_data_len;
  unsigned long *data_len = &tmp_data_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_signature);
  signature = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_signature, _c2);
    signature[_c2] = Int_val(_v3);
  }
  signature_len = _c1;
  _res = ML_CK_C_VerifyRecover(session, signature, signature_len, &data,
			       data_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*data_len, 0);
  for (_c4 = 0; _c4 < *data_len; _c4++) {
    _v5 = Val_int(data[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&data);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_VerifyUpdate(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_VerifyUpdate(session, data, data_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_VerifyFinal(value _v_session, value _v_signature)
{
  ck_session_handle_t session;	/*in */
  unsigned char *signature;	/*in */
  unsigned long signed_len;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_signature);
  signature = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_signature, _c2);
    signature[_c2] = Int_val(_v3);
  }
  signed_len = _c1;
  _res = ML_CK_C_VerifyFinal(session, signature, signed_len);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_EncryptInit(value _v_session,
					 value _v_mechanism, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_EncryptInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Encrypt(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *encrypted;	/*out */
  unsigned long tmp_encrypted_len;
  unsigned long *encrypted_len = &tmp_encrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_Encrypt(session, data, data_len, &encrypted, encrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*encrypted_len, 0);
  for (_c4 = 0; _c4 < *encrypted_len; _c4++) {
    _v5 = Val_int(encrypted[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&encrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_EncryptUpdate(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *encrypted;	/*out */
  unsigned long tmp_encrypted_len;
  unsigned long *encrypted_len = &tmp_encrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_EncryptUpdate(session, data, data_len, &encrypted,
			       encrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*encrypted_len, 0);
  for (_c4 = 0; _c4 < *encrypted_len; _c4++) {
    _v5 = Val_int(encrypted[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&encrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_EncryptFinal(value _v_session)
{
  ck_session_handle_t session;	/*in */
  unsigned char *encrypted;	/*out */
  unsigned long tmp_encrypted_len;
  unsigned long *encrypted_len = &tmp_encrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_EncryptFinal(session, &encrypted, encrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*encrypted_len, 0);
  for (_c1 = 0; _c1 < *encrypted_len; _c1++) {
    _v2 = Val_int(encrypted[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&encrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DigestEncryptUpdate(value _v_session,
						 value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *encrypted;	/*out */
  unsigned long tmp_encrypted_len;
  unsigned long *encrypted_len = &tmp_encrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_DigestEncryptUpdate(session, data, data_len, &encrypted,
				     encrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*encrypted_len, 0);
  for (_c4 = 0; _c4 < *encrypted_len; _c4++) {
    _v5 = Val_int(encrypted[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&encrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SignEncryptUpdate(value _v_session, value _v_data)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  unsigned char *encrypted;	/*out */
  unsigned long tmp_encrypted_len;
  unsigned long *encrypted_len = &tmp_encrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  _res = ML_CK_C_SignEncryptUpdate(session, data, data_len, &encrypted,
				   encrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*encrypted_len, 0);
  for (_c4 = 0; _c4 < *encrypted_len; _c4++) {
    _v5 = Val_int(encrypted[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&encrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DecryptInit(value _v_session,
					 value _v_mechanism, value _v_hkey)
{
  ck_session_handle_t session;	/*in */
  struct ck_mechanism mechanism;	/*in */
  ck_object_handle_t hkey;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  camlidl_ml2c_pkcs11_struct_ck_mechanism(_v_mechanism, &mechanism, _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hkey, &hkey, _ctx);
  _res = ML_CK_C_DecryptInit(session, mechanism, hkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_Decrypt(value _v_session, value _v_encrypted)
{
  ck_session_handle_t session;	/*in */
  unsigned char *encrypted;	/*in */
  unsigned long encrypted_len;	/*in */
  unsigned char *decrypted;	/*out */
  unsigned long tmp_decrypted_len;
  unsigned long *decrypted_len = &tmp_decrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_encrypted);
  encrypted = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_encrypted, _c2);
    encrypted[_c2] = Int_val(_v3);
  }
  encrypted_len = _c1;
  _res = ML_CK_C_Decrypt(session, encrypted, encrypted_len, &decrypted,
			 decrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*decrypted_len, 0);
  for (_c4 = 0; _c4 < *decrypted_len; _c4++) {
    _v5 = Val_int(decrypted[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&decrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DecryptUpdate(value _v_session, value _v_encrypted)
{
  ck_session_handle_t session;	/*in */
  unsigned char *encrypted;	/*in */
  unsigned long encrypted_len;	/*in */
  unsigned char *data;		/*out */
  unsigned long tmp_data_len;
  unsigned long *data_len = &tmp_data_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_encrypted);
  encrypted = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_encrypted, _c2);
    encrypted[_c2] = Int_val(_v3);
  }
  encrypted_len = _c1;
  _res = ML_CK_C_DecryptUpdate(session, encrypted, encrypted_len, &data,
			       data_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*data_len, 0);
  for (_c4 = 0; _c4 < *data_len; _c4++) {
    _v5 = Val_int(data[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&data);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DecryptFinal(value _v_session)
{
  ck_session_handle_t session;	/*in */
  unsigned char *decrypted;	/*out */
  unsigned long tmp_decrypted_len;
  unsigned long *decrypted_len = &tmp_decrypted_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_DecryptFinal(session, &decrypted, decrypted_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*decrypted_len, 0);
  for (_c1 = 0; _c1 < *decrypted_len; _c1++) {
    _v2 = Val_int(decrypted[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&decrypted);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DecryptDigestUpdate(value _v_session,
						 value _v_encrypted)
{
  ck_session_handle_t session;	/*in */
  unsigned char *encrypted;	/*in */
  unsigned long encrypted_len;	/*in */
  unsigned char *data;		/*out */
  unsigned long tmp_data_len;
  unsigned long *data_len = &tmp_data_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_encrypted);
  encrypted = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_encrypted, _c2);
    encrypted[_c2] = Int_val(_v3);
  }
  encrypted_len = _c1;
  _res = ML_CK_C_DecryptDigestUpdate(session, encrypted, encrypted_len,
				     &data, data_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*data_len, 0);
  for (_c4 = 0; _c4 < *data_len; _c4++) {
    _v5 = Val_int(data[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&data);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_DecryptVerifyUpdate(value _v_session,
						 value _v_encrypted)
{
  ck_session_handle_t session;	/*in */
  unsigned char *encrypted;	/*in */
  unsigned long encrypted_len;	/*in */
  unsigned char *data;		/*out */
  unsigned long tmp_data_len;
  unsigned long *data_len = &tmp_data_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_encrypted);
  encrypted = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_encrypted, _c2);
    encrypted[_c2] = Int_val(_v3);
  }
  encrypted_len = _c1;
  _res = ML_CK_C_DecryptVerifyUpdate(session, encrypted, encrypted_len,
				     &data, data_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*data_len, 0);
  for (_c4 = 0; _c4 < *data_len; _c4++) {
    _v5 = Val_int(data[_c4]);
    modify(&Field(_vres[1], _c4), _v5);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&data);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_GetOperationState(value _v_session)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*out */
  unsigned long tmp_data_len;
  unsigned long *data_len = &tmp_data_len;	/*in *//*in */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_GetOperationState(session, &data, data_len);
/* We add this because of possible shadow warning  */
/* (this is not our code: these are camlidl macros)*/
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
  Begin_roots_block(_vres, 2);
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
  _vres[0] = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  _vres[1] = camlidl_alloc(*data_len, 0);
  for (_c1 = 0; _c1 < *data_len; _c1++) {
    _v2 = Val_int(data[_c1]);
    modify(&Field(_vres[1], _c1), _v2);
  }
  _vresult = camlidl_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  End_roots();
  camlidl_free(_ctx);
  if (_res == CKR_OK) {
    custom_free((void **)&data);
  }
  return _vresult;
}

value camlidl_pkcs11_ML_CK_C_SetOperationState(value _v_session,
					       value _v_data,
					       value _v_hencryptionkey,
					       value _v_hauthenticationkey)
{
  ck_session_handle_t session;	/*in */
  unsigned char *data;		/*in */
  unsigned long data_len;	/*in */
  ck_object_handle_t hencryptionkey;	/*in */
  ck_object_handle_t hauthenticationkey;	/*in */
  ck_rv_t _res;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  data_len = _c1;
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hencryptionkey, &hencryptionkey,
					 _ctx);
  camlidl_ml2c_pkcs11_ck_object_handle_t(_v_hauthenticationkey,
					 &hauthenticationkey, _ctx);
  _res =
      ML_CK_C_SetOperationState(session, data, data_len, hencryptionkey,
				hauthenticationkey);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_GetFunctionStatus(value _v_session)
{
  ck_session_handle_t session;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_GetFunctionStatus(session);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_ML_CK_C_CancelFunction(value _v_session)
{
  ck_session_handle_t session;	/*in */
  ck_rv_t _res;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
  _res = ML_CK_C_CancelFunction(session);
  _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_int_to_ulong_char_array(value _v_input)
{
  unsigned long input;		/*in */
  unsigned char *data;		/*out */
  mlsize_t _c1;
  value _v2;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  input = custom_int_val(_v_input);
  data = camlidl_malloc(sizeof(unsigned long) * sizeof(unsigned char), _ctx);
  int_to_ulong_char_array(input, data);
  _vres = camlidl_alloc(sizeof(unsigned long), 0);
  for (_c1 = 0; _c1 < sizeof(unsigned long); _c1++) {
    _v2 = Val_int(data[_c1]);
    modify(&Field(_vres, _c1), _v2);
  }
  camlidl_free(_ctx);
  return _vres;
}

value camlidl_pkcs11_char_array_to_ulong(value _v_data)
{
  unsigned char *data;		/*in */
  unsigned long output;		/*out */
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  value _vres;

  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  _c1 = Wosize_val(_v_data);
  data = camlidl_malloc(_c1 * sizeof(unsigned char), _ctx);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    data[_c2] = Int_val(_v3);
  }
  char_array_to_ulong(data, _c1, &output);
  _vres = custom_copy_int(output);
  camlidl_free(_ctx);
  return _vres;
}

#ifdef SERVER_ROLE
int encode_ck_attribute_arch(struct ck_attribute *in, struct ck_attribute *out)
{
  uint32_t to_send32;
  uint64_t to_send64;
  out->type_ = in->type_;
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint32_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == BIG_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == BIG_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      memcpy(out->value, in->value, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == BIG_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      to_send32 = htobe32(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send32, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      to_send32 = htole32(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send32, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == BIG_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      to_send64 = htobe64(*((uint64_t *) (in->value)));
      memcpy(out->value, &to_send64, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      to_send64 = htole64(*((uint64_t *) (in->value)));
      memcpy(out->value, &to_send64, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == BIG_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send32 = htobe32(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send32, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send64 = htole64(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send64, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == BIG_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send64 = htobe64(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send64, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send32 = htole32(*((uint32_t *) (in->value + 4)));
      memcpy(out->value, &to_send32, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == BIG_ENDIAN_64) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint32_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send64 = htobe64(*((uint32_t *) (in->value)));
      memcpy(out->value, &to_send64, sizeof(uint64_t));
      out->value_len = sizeof(uint64_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint64_t);
    }
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == BIG_ENDIAN_32) {
    if (in->value != NULL) {
      if (in->value_len != sizeof(uint64_t)) {
	return -1;
      }
      /* Endianness is different */
      to_send32 = htobe32(*((uint32_t *) (in->value + 4)));
      memcpy(out->value, &to_send32, sizeof(uint32_t));
      out->value_len = sizeof(uint32_t);
    } else {
      out->value = NULL;
      out->value_len = sizeof(uint32_t);
    }
  }
  return 0;
}
#endif
#ifdef SERVER_ROLE
int decode_ck_attribute_arch(value in, struct ck_attribute *out,
			     camlidl_ctx _ctx)
{
  value vtmp;
  unsigned long counter;

  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }

  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }

  if (my_arch == BIG_ENDIAN_32 && peer_arch == BIG_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter + sizeof(uint32_t));
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == BIG_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter + sizeof(uint32_t)] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }

  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }

  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint64_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == BIG_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == BIG_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint64_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);

  }
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == BIG_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint32_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);

  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint32_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == BIG_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint64_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint64_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint64_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint64_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }
  if (my_arch == LITTLE_ENDIAN_64 && peer_arch == BIG_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint32_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);

  }
  if (my_arch == BIG_ENDIAN_32 && peer_arch == LITTLE_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint32_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);
  }
  if (my_arch == LITTLE_ENDIAN_32 && peer_arch == BIG_ENDIAN_64) {
    if (Wosize_val(in) != sizeof(uint64_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint64_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint32_t), _ctx);
    memset((*out).value, 0, sizeof(uint32_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter + sizeof(uint32_t));
      (*out).value[(sizeof(uint32_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint32_t);

  }
  if (my_arch == BIG_ENDIAN_64 && peer_arch == LITTLE_ENDIAN_32) {
    if (Wosize_val(in) != sizeof(uint32_t)) {
#ifdef DEBUG
      fprintf(stderr,
	      "Something went wrong with the endianness transformation : got %lu instead of %lu\n",
	      Wosize_val(in), sizeof(uint32_t));
#endif
      return -1;
    }
    (*out).value = camlidl_malloc(sizeof(uint64_t), _ctx);
    memset((*out).value, 0, sizeof(uint64_t));
    for (counter = 0; counter < sizeof(uint32_t); counter++) {
      vtmp = Field(in, counter);
      (*out).value[(sizeof(uint64_t) - 1) - counter] = Int_val(vtmp);
    }
    (*out).value_len = sizeof(uint64_t);
  }
  return 0;
}
#endif
