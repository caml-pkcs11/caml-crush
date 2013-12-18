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
    File:    src/client-lib/modwrap_camlrpc.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include "modwrap.h"

/* -------------------------------- */
/* RPC CAML serialization functions */
/*
WARNING:
        This function is not mechanism type agnostic
        parameter and parameter_len can be uninitialized
        The implemented fix is the above custom_sanitize_ck_mechanism()
        that has to be called in C_<CryptoOp>Init() functions before parsing 
        with custom_c2ml_pkcs11_struct_ck_mechanism().
*/
value
custom_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
				       camlidl_ctx _ctx)
{
  value _v2;
  value _v3[2];
  mlsize_t _c4;
  value _v5;
  _v3[0] = _v3[1] = 0;
  Begin_roots_block(_v3, 2);;;
  _v3[0] = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&(*_c1).mechanism, _ctx);
  _v3[1] = camlidl_alloc((*_c1).parameter_len, 0);
  for (_c4 = 0; _c4 < (*_c1).parameter_len; _c4++) {
    /* FIXME: parameter is void and can be any type, we assume it is a unsigned
       char array and we have to call our sanitize function on input
       before trying to parse
     */
    _v5 = Val_int((unsigned char)((*_c1).parameter[_c4]));
    modify(&Field(_v3[1], _c4), _v5);
  }
  _v2 = camlidl_alloc_small(2, 0);
  Field(_v2, 0) = _v3[0];
  Field(_v2, 1) = _v3[1];
  End_roots();;
  return _v2;
}

value
custom_pkcs11_c2ml_buffer_to_ck_attribute_array(struct ck_attribute * array,
						unsigned long array_len,
						camlidl_ctx _ctx)
{
  CAMLparam0();
  CAMLlocal2(_v5, v);
  mlsize_t _c4;
  v = caml_alloc(array_len, 0);
  for (_c4 = 0; _c4 < array_len; _c4++) {
    _v5 = camlidl_c2ml_pkcs11_struct_ck_attribute(&array[_c4], _ctx);
    Store_field(v, _c4, _v5);
  }
  CAMLreturn(v);
}

void
custom_ml2c_pkcs11_struct_ck_attribute(value _v1, struct ck_attribute *_c2,
				       camlidl_ctx _ctx, unsigned long ret)
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

  (*_c2).value_len = _c5;
#ifdef DEBUG
  fprintf(stderr,
	  "custom_ml2c_pkcs11_struct_ck_attribute : type %x, len %d ARRAY\n",
	  (*_c2).type_, (*_c2).value_len);
#endif

  if ((*_c2).value_len != 0) {
    /* We must first check that the value is not NULL while 
       the length is */
    if ((*_c2).value == NULL) {
      /* Return an error if this is the case ... */
      return;
    }
    for (_c6 = 0; _c6 < _c5; _c6++) {
      _v7 = Field(_v4, _c6);
      (*_c2).value[_c6] = Int_val(_v7);
    }
  }
  /* Carry the ret value to update UlValueLen to be passed -1 on errors */
  else {
    if (ret != CKR_OK) {
      (*_c2).value_len = -1;
    }
  }

  return;
}

int
custom_pkcs11_ml2c_ck_attribute_array_to_buffer(value _v_data,
						struct ck_attribute *array,
						unsigned long *array_len,
						camlidl_ctx _ctx,
						unsigned long ret)
{
  CAMLparam0();
  CAMLlocal1(_v3);
  mlsize_t _c1;
  mlsize_t _c2;

  _c1 = Wosize_val(_v_data);
  for (_c2 = 0; _c2 < _c1; _c2++) {
    _v3 = Field(_v_data, _c2);
    /* Call our custom function */
    custom_ml2c_pkcs11_struct_ck_attribute(_v3, &array[_c2], _ctx, ret);
  }
  *array_len = _c1;

  CAMLreturn(0);
}

value
custom_pkcs11_c2ml_buffer_to_char_array(unsigned char *array,
					unsigned long array_len)
{
  CAMLparam0();
  CAMLlocal1(v);
  mlsize_t i;
  v = caml_alloc(array_len, 0);
  for (i = 0; i < (mlsize_t) array_len; i++) {
    Store_field(v, i, Val_int(array[i]));
  }
  CAMLreturn(v);
}

int
custom_pkcs11_ml2c_char_array_to_buffer(value _v_data, unsigned char *array,
					unsigned long *array_len)
{
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;

  _c1 = Wosize_val(_v_data);
  if (array != NULL) {

    for (_c2 = 0; _c2 < _c1; _c2++) {
      _v3 = Field(_v_data, _c2);
      array[_c2] = Int_val(_v3);
    }
  }
  *array_len = _c1;
  return 0;
}

/* -----------------------------  */
/*  RPC OCAML PKCS#11 functions   */

ck_rv_t init_ml(const char *module)
{
  ck_rv_t ret;
  char *dummy_init_args[2] = { (char *)"client-pkcs11", (char *)0 };
  /* Initialize OCaml runtime */
  caml_startup(dummy_init_args);
  ret = myRPC_connect();
  if (ret != 0) {
    fprintf(stderr, "Could not connect to RPC server\n");
    fprintf(stderr, "Check you parameters\n");
    return ret;
  }
  /* Initialize Architecture */
  ret = myC_SetupArch();
  switch (ret) {
  case LITTLE_ENDIAN_64:
  case LITTLE_ENDIAN_32:
  case BIG_ENDIAN_64:
  case BIG_ENDIAN_32:
    peer_arch = ret;
    break;
  default:
    fprintf(stderr, "Unsupported architecture error\n");
    return UNSUPPORTED_ARCHITECTURE;
  }
  /* Call LoadModule */
  ret = myC_LoadModule(module);
  return ret;
}

void destroy_ml()
{
  CAMLparam0();
  static value *shut_down_client_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "Shut_Down_Client calling\n");
#endif

  if (shut_down_client_closure == NULL) {
    shut_down_client_closure = caml_named_value("Shut_Down_Client");
  }
  if (shut_down_client_closure == NULL) {
    fprintf(stderr, "\nError binding with caml Shut_Down_Client\n");
    CAMLreturn0;
  }
  caml_callback(*shut_down_client_closure, copy_int64(0));

  CAMLreturn0;
}

ck_rv_t myRPC_connect(void)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  static value *RPC_connect_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "RPC_connect calling\n");
#endif

  if (RPC_connect_closure == NULL) {
    RPC_connect_closure = caml_named_value("RPC_connect");
  }
  if (RPC_connect_closure == NULL) {
    fprintf(stderr, "\nError binding with caml RPC_connect\n");
    exit(-1);
  }
  tuple = caml_callback_exn(*RPC_connect_closure, copy_int64(0));
  if (Is_exception_result(tuple)) {
    tuple = Extract_exception(tuple);
    CAMLreturn(-1);
  }
  CAMLreturn(0);
}

ck_rv_t myC_SetupArch(void)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;
  static value *C_SetupArch_closure = NULL;

  unsigned int test = 0xAABBCCDD;

#ifdef DEBUG
  fprintf(stderr, "C_SetupArch calling\n");
#endif

  if (((unsigned char *)&test)[0] == 0xDD) {
    /* LittleEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      args[0] = copy_int64(LITTLE_ENDIAN_64);
      my_arch = LITTLE_ENDIAN_64;
    } else {
      args[0] = copy_int64(LITTLE_ENDIAN_32);
      my_arch = LITTLE_ENDIAN_32;
    }
  } else {
    /* BigEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      args[0] = copy_int64(BIG_ENDIAN_64);
      my_arch = BIG_ENDIAN_64;
    } else {
      args[0] = copy_int64(BIG_ENDIAN_32);
      my_arch = BIG_ENDIAN_32;
    }
  }

  if (C_SetupArch_closure == NULL) {
    C_SetupArch_closure = caml_named_value("C_SetupArch");
  }
  if (C_SetupArch_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SetupArch\n");
    exit(-1);
  }
  tuple = caml_callbackN(*C_SetupArch_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_Initialize(void *init_args)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;
  static value *C_Initialize_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Initialize calling\n");
#endif
  if (C_Initialize_closure == NULL) {
    C_Initialize_closure = caml_named_value("C_Initialize");
  }
  if (C_Initialize_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Initialize\n");
    exit(-1);
  }

  /* Check for pInitArgs PTR presence */
  if (init_args != NULL) {
#ifdef DEBUG
    fprintf(stderr, "C_Initialize *pInitArgs not NULL, we won't use them\n");
#endif
  }

  tuple = caml_callback(*C_Initialize_closure, copy_int64(0));
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);
  CAMLreturn(ret);
}

ck_rv_t myC_Finalize(void *init_args)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  ck_rv_t ret;
  static value *C_Finalize_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Finalize calling\n");
#endif
  if (C_Finalize_closure == NULL) {
    C_Finalize_closure = caml_named_value("C_Finalize");
  }
  if (C_Finalize_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Finalize\n");
    exit(-1);
  }
  /* P11 Compliance */
  if (init_args != NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
  tuple = caml_callback(*C_Finalize_closure, copy_int64(0));
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);
  CAMLreturn(ret);
}

ck_rv_t
myC_GetSlotList(CK_BBOOL input0, ck_slot_id_t * output2, unsigned long *output3)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;
  unsigned long i;
  static value *C_GetSlotList_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetSlotList calling\n");
#endif
  if (C_GetSlotList_closure == NULL) {
    C_GetSlotList_closure = caml_named_value("C_GetSlotList");
  }
  if (C_GetSlotList_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetSlotList\n");
    exit(-1);
  }
  /* P11 compliant */
  if (output3 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
  if (input0 == 1) {
    /* CK_TRUE */
    args[0] = copy_int64(1);
  } else {
    args[0] = copy_int64(0);
  }
  if (output2 == NULL) {
    args[1] = copy_int64(0);
  } else if (*output3 > 0) {
    args[1] = copy_int64(*output3);
  }
  /* P11 compliant */
  else {
    CAMLreturn(CKR_BUFFER_TOO_SMALL);
  }
  tuple = caml_callbackN(*C_GetSlotList_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  *output3 = Int64_val(Field(tuple, 2));
  /* Copy back only if *output2 is not NULL */
  if (output2 != NULL) {
    for (i = 0; i < *output3; i++) {
      camlidl_ml2c_pkcs11_ck_slot_id_t(Field(Field(tuple, 1), i),
				       &output2[i], NULL);
    }
  }
  CAMLreturn(ret);
}

ck_rv_t myC_GetInfo(struct ck_info *output0)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;
  static value *C_GetInfo_closure = NULL;
#ifdef DEBUG
  fprintf(stderr, "C_GetInfo calling\n");
#endif
  if (C_GetInfo_closure == NULL) {
    C_GetInfo_closure = caml_named_value("C_GetInfo");
  }
  if (C_GetInfo_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetInfo\n");
    exit(-1);
  }
  if (output0 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
  tuple = caml_callback(*C_GetInfo_closure, copy_int64(0));
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_struct_ck_info(Field(tuple, 1), output0, NULL);
  CAMLreturn(ret);
}

ck_rv_t
myC_WaitForSlotEvent(ck_flags_t input0, ck_slot_id_t * output1, void *reserved)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;
  static value *C_WaitForSlotEvent_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_WaitForSlotEvent calling\n");
#endif
  if (C_WaitForSlotEvent_closure == NULL) {
    C_WaitForSlotEvent_closure = caml_named_value("C_WaitForSlotEvent");
  }
  if (C_WaitForSlotEvent_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_WaitForSlotEvent\n");
    exit(-1);
  }

  /* P11 compliant */
  if (reserved != NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  args[0] = camlidl_c2ml_pkcs11_ck_flags_t(&input0, NULL);
  tuple = caml_callbackN(*C_WaitForSlotEvent_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_slot_id_t(Field(tuple, 1), output1, NULL);
  CAMLreturn(ret);
}

ck_rv_t myC_GetSlotInfo(ck_slot_id_t input0, struct ck_slot_info * output1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_GetSlotInfo_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetSlotInfo calling\n");
#endif
  if (C_GetSlotInfo_closure == NULL) {
    C_GetSlotInfo_closure = caml_named_value("C_GetSlotInfo");
  }
  if (C_GetSlotInfo_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetSlotInfo\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetSlotInfo_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_struct_ck_slot_info(Field(tuple, 1), output1, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_GetTokenInfo(ck_slot_id_t input0, struct ck_token_info *output1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_GetTokenInfo_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetTokenInfo calling\n");
#endif
  if (C_GetTokenInfo_closure == NULL) {
    C_GetTokenInfo_closure = caml_named_value("C_GetTokenInfo");
  }
  if (C_GetTokenInfo_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetTokenInfo\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetTokenInfo_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_CK_TOKEN_INFO(Field(tuple, 1), output1, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_InitToken(ck_slot_id_t input0, unsigned char *input1,
	      unsigned long input1_len, unsigned char *input2)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;
  /* Label is 32 bytes long */
  unsigned long input2_len = 32;

  static value *C_InitToken_closure = NULL;

  /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
  if (input1 == NULL) {
    input1_len = 0;
  }
#ifdef DEBUG
  fprintf(stderr, "C_InitToken calling\n");
#endif
  if (C_InitToken_closure == NULL) {
    C_InitToken_closure = caml_named_value("C_InitToken");
  }
  if (C_InitToken_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_InitToken\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  args[2] = custom_pkcs11_c2ml_buffer_to_char_array(input2, input2_len);
  tuple = caml_callbackN(*C_InitToken_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_OpenSession(ck_slot_id_t input0, ck_flags_t input1, void *application,
		ck_notify_t notify, ck_session_handle_t * output2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_OpenSession_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_OpenSession calling\n");
#endif
  if (C_OpenSession_closure == NULL) {
    C_OpenSession_closure = caml_named_value("C_OpenSession");
  }
  if (C_OpenSession_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_OpenSession\n");
    exit(-1);
  }
  /* P11 compliant */
  if (output2 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Check for application/notify PTR presence */
  if ((application != NULL) || (notify != NULL)) {
#ifdef DEBUG
    fprintf(stderr,
	    "C_OpenSession *application/*notify not NULL, we won't pass them\n");
#endif
  }

  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_flags_t(&input1, NULL);
  tuple = caml_callbackN(*C_OpenSession_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_session_handle_t(Field(tuple, 1), output2, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_CloseSession(ck_session_handle_t input0)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_CloseSession_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_CloseSession calling\n");
#endif
  if (C_CloseSession_closure == NULL) {
    C_CloseSession_closure = caml_named_value("C_CloseSession");
  }
  if (C_CloseSession_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_CloseSession\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_CloseSession_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_CloseAllSessions(ck_slot_id_t input0)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_CloseAllSessions_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_CloseAllSessions calling\n");
#endif
  if (C_CloseAllSessions_closure == NULL) {
    C_CloseAllSessions_closure = caml_named_value("C_CloseAllSessions");
  }
  if (C_CloseAllSessions_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_CloseAllSessions\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  tuple = caml_callbackN(*C_CloseAllSessions_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GetSessionInfo(ck_session_handle_t input0, struct ck_session_info *output1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_GetSessionInfo_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetSessionInfo calling\n");
#endif
  if (C_GetSessionInfo_closure == NULL) {
    C_GetSessionInfo_closure = caml_named_value("C_GetSessionInfo");
  }
  if (C_GetSessionInfo_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetSessionInfo\n");
    exit(-1);
  }
  /* P11 compliant */
  if (output1 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetSessionInfo_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_CK_SESSION_INFO(Field(tuple, 1), output1, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Login(ck_session_handle_t input0, ck_user_type_t input1,
	  unsigned char *input2, unsigned long input2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_Login_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Login calling\n");
#endif
  if (C_Login_closure == NULL) {
    C_Login_closure = caml_named_value("C_Login");
  }
  if (C_Login_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Login\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_user_type_t(&input1, NULL);
  args[2] = custom_pkcs11_c2ml_buffer_to_char_array(input2, input2_len);
  tuple = caml_callbackN(*C_Login_closure, 3, args);

  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_Logout(ck_session_handle_t input0)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_Logout_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Logout calling\n");
#endif
  if (C_Logout_closure == NULL) {
    C_Logout_closure = caml_named_value("C_Logout");
  }
  if (C_Logout_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Logout\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_Logout_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GetMechanismList(ck_slot_id_t input0, ck_mechanism_type_t * output2,
		     unsigned long *output3)
{

  CAMLparam0();
  CAMLlocal2(tuple, _v3);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_GetMechanismList_closure = NULL;
  int i, len;

#ifdef DEBUG
  fprintf(stderr, "C_GetMechanismList calling\n");
#endif
  if (C_GetMechanismList_closure == NULL) {
    C_GetMechanismList_closure = caml_named_value("C_GetMechanismList");
  }
  if (C_GetMechanismList_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetMechanismList\n");
    exit(-1);
  }
  /* P11 compliant */
  if (output3 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  if (output2 == NULL) {
    args[1] = copy_int64(0);
  } else {
    args[1] = copy_int64(*output3);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetMechanismList_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  /* TODO: explain P11 compliance algorithm */
  if (ret == CKR_BUFFER_TOO_SMALL) {
    *output3 = Int64_val(Field(tuple, 2));
    CAMLreturn(ret);
  } else if (ret != CKR_OK) {
    CAMLreturn(ret);
  }

  /* P11 compliant */
  /* FIXME: For now cast to (unsigned long) because we should not recieve a huge mech_count */
  if ((output2 != NULL && *output3 == 0)
      || (*output3 < (unsigned long)Int64_val(Field(tuple, 2)))) {
    *output3 = Int64_val(Field(tuple, 2));
    if (output2 == NULL) {
      CAMLreturn(ret);
    }
    CAMLreturn(CKR_BUFFER_TOO_SMALL);
  }

  len = Int64_val(Field(tuple, 2));
  i = 0;
  if (output2 != NULL) {
    for (i = 0; i < len; i++) {
      _v3 = Field(Field(tuple, 1), i);
      camlidl_ml2c_pkcs11_ck_mechanism_type_t(_v3, &output2[i], NULL);
    }
  }

  *output3 = Int64_val(Field(tuple, 2));

  CAMLreturn(ret);
}

ck_rv_t
myC_GetMechanismInfo(ck_slot_id_t input0, ck_mechanism_type_t input1,
		     struct ck_mechanism_info *output2)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_GetMechanismInfo_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetMechanismInfo calling\n");
#endif
  if (C_GetMechanismInfo_closure == NULL) {
    C_GetMechanismInfo_closure = caml_named_value("C_GetMechanismInfo");
  }
  if (C_GetMechanismInfo_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetMechanismInfo\n");
    exit(-1);
  }
  /* P11 compliant */
  if (output2 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_slot_id_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&input1, NULL);
  tuple = caml_callbackN(*C_GetMechanismInfo_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_CK_MECHANISM_INFO(Field(tuple, 1), output2, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_InitPIN(ck_session_handle_t input0, unsigned char *input1,
	    unsigned long input1_len)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_InitPIN_closure = NULL;

  /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
  if (input1 == NULL) {
    input1_len = 0;
  }
#ifdef DEBUG
  fprintf(stderr, "C_InitPIN calling\n");
#endif
  if (C_InitPIN_closure == NULL) {
    C_InitPIN_closure = caml_named_value("C_InitPIN");
  }
  if (C_InitPIN_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_InitPIN\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_InitPIN_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_SetPIN(ck_session_handle_t input0, unsigned char *input1,
	   unsigned long input1_len, unsigned char *input2,
	   unsigned long input2_len)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_SetPIN_closure = NULL;

  /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
  if (input1 == NULL) {
    input1_len = 0;
  }
  if (input2 == NULL) {
    input2_len = 0;
  }
#ifdef DEBUG
  fprintf(stderr, "C_SetPIN calling\n");
#endif
  if (C_SetPIN_closure == NULL) {
    C_SetPIN_closure = caml_named_value("C_SetPIN");
  }
  if (C_SetPIN_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SetPIN\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  args[2] = custom_pkcs11_c2ml_buffer_to_char_array(input2, input2_len);
  tuple = caml_callbackN(*C_SetPIN_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_SeedRandom(ck_session_handle_t input0, unsigned char *input1,
	       unsigned long input1_len)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_SeedRandom_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_SeedRandom calling\n");
#endif
  if (C_SeedRandom_closure == NULL) {
    C_SeedRandom_closure = caml_named_value("C_SeedRandom");
  }
  if (C_SeedRandom_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SeedRandom\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_SeedRandom_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GenerateRandom(ck_session_handle_t input0, unsigned char *output2,
		   unsigned long output2_len)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_GenerateRandom_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GenerateRandom calling\n");
#endif
  if (C_GenerateRandom_closure == NULL) {
    C_GenerateRandom_closure = caml_named_value("C_GenerateRandom");
  }
  if (C_GenerateRandom_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GenerateRandom\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = copy_int64(output2_len);
  tuple = caml_callbackN(*C_GenerateRandom_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  custom_pkcs11_ml2c_char_array_to_buffer(Field(tuple, 1), output2,
					  &output2_len);

  CAMLreturn(ret);
}

ck_rv_t
myC_GetOperationState(ck_session_handle_t input0, unsigned char *output1,
		      unsigned long *output1_len)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_GetOperationState_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_GetOperationState calling\n");
#endif
  if (C_GetOperationState_closure == NULL) {
    C_GetOperationState_closure = caml_named_value("C_GetOperationState");
  }
  if (C_GetOperationState_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetOperationState\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("GetOperationState", GETOPERATION_STATE_OP, input0, NULL, 0,
		    output1, output1_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetOperationState_closure, 1, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(GetOperationState, GETOPERATION_STATE_OP, input0, NULL, 0,
		     output1, output1_len);
}

ck_rv_t
myC_SetOperationState(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, ck_object_handle_t input2,
		      ck_object_handle_t input3)
{

  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 4);
  ck_rv_t ret;

  static value *C_SetOperationState_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_SetOperationState calling\n");
#endif
  if (C_SetOperationState_closure == NULL) {
    C_SetOperationState_closure = caml_named_value("C_SetOperationState");
  }
  if (C_SetOperationState_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SetOperationState\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  args[3] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input3, NULL);
  tuple = caml_callbackN(*C_SetOperationState_closure, 4, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_FindObjectsInit(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
		    unsigned long count)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_FindObjectsInit_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_FindObjectsInit calling\n");
#endif
  if (C_FindObjectsInit_closure == NULL) {
    C_FindObjectsInit_closure = caml_named_value("C_FindObjectsInit");
  }
  if (C_FindObjectsInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_FindObjectsInit\n");
    exit(-1);
  }
  /* P11 compliant */
  if (input1 == NULL && count > 0) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  /* If count is zero, we pass an empty list to CAML */
  if (count == 0) {
    args[1] = Atom(0);
  } else {
    args[1] =
	custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input1, count, NULL);
  }
  tuple = caml_callbackN(*C_FindObjectsInit_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_FindObjects(ck_session_handle_t input0, ck_object_handle_t * output2,
		unsigned long input1, unsigned long *output3)
{
  CAMLparam0();
  CAMLlocal2(tuple, _v3);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_FindObjects_closure = NULL;
  unsigned long i, len;

#ifdef DEBUG
  fprintf(stderr, "C_FindObjects calling\n");
#endif
  if (C_FindObjects_closure == NULL) {
    C_FindObjects_closure = caml_named_value("C_FindObjects");
  }
  if (C_FindObjects_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_FindObjects\n");
    exit(-1);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = copy_int64(input1);
  tuple = caml_callbackN(*C_FindObjects_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  /* P11 compliant, return RET if was called with invalid session */
  if (ret != CKR_OK) {
    CAMLreturn(ret);
  }

  /* P11 compliant */
  if (output2 == NULL || output3 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  len = Int64_val(Field(tuple, 2));
  i = 0;
  for (i = 0; i < len; i++) {
    _v3 = Field(Field(tuple, 1), i);
    camlidl_ml2c_pkcs11_ck_object_handle_t(_v3, &output2[i], NULL);
  }
  *output3 = len;

  CAMLreturn(ret);
}

ck_rv_t myC_FindObjectsFinal(ck_session_handle_t input0)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_FindObjectsFinal_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_FindObjectsFinal calling\n");
#endif
  if (C_FindObjectsFinal_closure == NULL) {
    C_FindObjectsFinal_closure = caml_named_value("C_FindObjectsFinal");
  }
  if (C_FindObjectsFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_FindObjectsFinal\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_FindObjectsFinal_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GenerateKey(ck_session_handle_t input0, struct ck_mechanism *input1,
		CK_ATTRIBUTE * input2, unsigned long count,
		ck_object_handle_t * output3)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_GenerateKey_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GenerateKey calling\n");
#endif

  if (C_GenerateKey_closure == NULL) {
    C_GenerateKey_closure = caml_named_value("C_GenerateKey");
  }
  if (C_GenerateKey_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GenerateKey\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input2, count, NULL);
  tuple = caml_callbackN(*C_GenerateKey_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output3, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GenerateKeyPair(ck_session_handle_t input0, struct ck_mechanism *input1,
		    CK_ATTRIBUTE * input2, unsigned long count,
		    CK_ATTRIBUTE * input3, unsigned long count2,
		    ck_object_handle_t * output4, ck_object_handle_t * output5)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 4);
  ck_rv_t ret;

  static value *C_GenerateKeyPair_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GenerateKeyPair calling\n");
#endif

  if (C_GenerateKeyPair_closure == NULL) {
    C_GenerateKeyPair_closure = caml_named_value("C_GenerateKeyPair");
  }
  if (C_GenerateKeyPair_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GenerateKeyPair\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input2, count, NULL);
  args[3] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input3, count2, NULL);
  tuple = caml_callbackN(*C_GenerateKeyPair_closure, 4, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output4, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 2), output5, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_CreateObject(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
		 unsigned long count, ck_object_handle_t * output2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_CreateObject_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_CreateObject calling\n");
#endif

  if (C_CreateObject_closure == NULL) {
    C_CreateObject_closure = caml_named_value("C_CreateObject");
  }
  if (C_CreateObject_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_CreateObject\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input1, count, NULL);
  tuple = caml_callbackN(*C_CreateObject_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output2, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_CopyObject(ck_session_handle_t input0, ck_object_handle_t input1,
	       CK_ATTRIBUTE * input2, unsigned long count,
	       ck_object_handle_t * output3)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_CopyObject_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_CopyObject calling\n");
#endif

  if (C_CopyObject_closure == NULL) {
    C_CopyObject_closure = caml_named_value("C_CopyObject");
  }
  if (C_CopyObject_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_CopyObject\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  args[2] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input2, count, NULL);
  tuple = caml_callbackN(*C_CopyObject_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output3, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_DestroyObject(ck_session_handle_t input0, ck_object_handle_t input1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DestroyObject_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_DestroyObject calling\n");
#endif

  if (C_DestroyObject_closure == NULL) {
    C_DestroyObject_closure = caml_named_value("C_DestroyObject");
  }
  if (C_DestroyObject_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DestroyObject\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  tuple = caml_callbackN(*C_DestroyObject_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GetAttributeValue(ck_session_handle_t input0, ck_object_handle_t input1,
		      struct ck_attribute *input2, unsigned long input3)
{
  CAMLparam0();
  CAMLlocal2(tuple, _v3);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_GetAttributeValue_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetAttributeValue calling, size templ: %lu\n", input3);
#endif
  if (C_GetAttributeValue_closure == NULL) {
    C_GetAttributeValue_closure = caml_named_value("C_GetAttributeValue");
  }
  if (C_GetAttributeValue_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetAttributeValue\n");
    exit(-1);
  }
  if (input2 == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  } else {
    args[2] =
	custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input2, input3, NULL);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  tuple = caml_callbackN(*C_GetAttributeValue_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  custom_pkcs11_ml2c_ck_attribute_array_to_buffer(Field(tuple, 1), input2,
						  &input3, NULL, ret);

  CAMLreturn(ret);
}

ck_rv_t
myC_SetAttributeValue(ck_session_handle_t input0, ck_object_handle_t input1,
		      CK_ATTRIBUTE * input2, unsigned long count)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_SetAttributeValue_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_SetAttributeValue calling\n");
#endif

  if (C_SetAttributeValue_closure == NULL) {
    C_SetAttributeValue_closure = caml_named_value("C_SetAttributeValue");
  }
  if (C_SetAttributeValue_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SetAttributeValue\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  args[2] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input2, count, NULL);
  tuple = caml_callbackN(*C_SetAttributeValue_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_GetObjectSize(ck_session_handle_t input0, ck_object_handle_t input1,
		  unsigned long *output2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_GetObjectSize_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetObjectSize calling\n");
#endif

  if (C_GetObjectSize_closure == NULL) {
    C_GetObjectSize_closure = caml_named_value("C_GetObjectSize");
  }
  if (C_GetObjectSize_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetObjectSize\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  tuple = caml_callbackN(*C_GetObjectSize_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  *output2 = Int64_val(Field(tuple, 1));

  CAMLreturn(ret);
}

ck_rv_t
myC_WrapKey(ck_session_handle_t input0, struct ck_mechanism *input1,
	    ck_object_handle_t input2, ck_object_handle_t input3,
	    unsigned char *output4, unsigned long *output4_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 4);
  ck_rv_t ret;

  static value *C_WrapKey_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_WrapKey calling\n");
#endif

  if (C_WrapKey_closure == NULL) {
    C_WrapKey_closure = caml_named_value("C_WrapKey");
  }
  if (C_WrapKey_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_WrapKey\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output4_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("WrapKey", WRAPKEY_OP, input0, NULL, 0, output4,
		    output4_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  args[3] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input3, NULL);
  tuple = caml_callbackN(*C_WrapKey_closure, 4, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(WrapKey, WRAPKEY_OP, input0, NULL, 0, output4,
		     output4_len);
}

ck_rv_t
myC_UnwrapKey(ck_session_handle_t input0, struct ck_mechanism *input1,
	      ck_object_handle_t input2, unsigned char *input3,
	      unsigned long input3_len, CK_ATTRIBUTE * input4,
	      unsigned long count, ck_object_handle_t * output5)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 5);
  ck_rv_t ret;

  static value *C_UnwrapKey_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_UnwrapKey calling\n");
#endif

  if (C_UnwrapKey_closure == NULL) {
    C_UnwrapKey_closure = caml_named_value("C_UnwrapKey");
  }
  if (C_UnwrapKey_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_UnwrapKey\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  args[3] = custom_pkcs11_c2ml_buffer_to_char_array(input3, input3_len);
  args[4] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input4, count, NULL);
  tuple = caml_callbackN(*C_UnwrapKey_closure, 5, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output5, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_DeriveKey(ck_session_handle_t input0, struct ck_mechanism *input1,
	      ck_object_handle_t input2, CK_ATTRIBUTE * input3,
	      unsigned long count, ck_object_handle_t * output4)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 4);
  ck_rv_t ret;

  static value *C_DeriveKey_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_DeriveKey calling\n");
#endif

  if (C_DeriveKey_closure == NULL) {
    C_DeriveKey_closure = caml_named_value("C_DeriveKey");
  }
  if (C_DeriveKey_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DeriveKey\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  args[3] =
      custom_pkcs11_c2ml_buffer_to_ck_attribute_array(input3, count, NULL);
  tuple = caml_callbackN(*C_DeriveKey_closure, 4, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);
  camlidl_ml2c_pkcs11_ck_object_handle_t(Field(tuple, 1), output4, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_DigestInit(ck_session_handle_t input0, struct ck_mechanism *input1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DigestInit_closure = NULL;
  if (C_DigestInit_closure == NULL) {
    C_DigestInit_closure = caml_named_value("C_DigestInit");
  }
  if (C_DigestInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DigestInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_DigestInit calling\n");
#endif
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, DIGEST_OP) != NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  tuple = caml_callbackN(*C_DigestInit_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Digest(ck_session_handle_t input0, unsigned char *input1,
	   unsigned long input1_len, unsigned char *output2,
	   unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_Digest_closure = NULL;
  /* Remember previous calls */
  p11_request_struct *elem;

  if (C_Digest_closure == NULL) {
    C_Digest_closure = caml_named_value("C_Digest");
  }
  if (C_Digest_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Digest\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
#ifdef DEBUG
  fprintf(stderr, "C_Digest calling\n");
#endif
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);

  /* Remember previous calls */
  check_linked_list("Digest", DIGEST_OP, input0, input1, input1_len, output2,
		    output2_len);

  tuple = caml_callbackN(*C_Digest_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(Digest, DIGEST_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_DigestUpdate(ck_session_handle_t input0, unsigned char *input1,
		 unsigned long input1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DigestUpdate_closure = NULL;
  if (C_DigestUpdate_closure == NULL) {
    C_DigestUpdate_closure = caml_named_value("C_DigestUpdate");
  }
  if (C_DigestUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DigestUpdate\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_DigestUpdate calling\n");
#endif
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_DigestUpdate_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_DigestFinal(ck_session_handle_t input0, unsigned char *output1,
		unsigned long *output1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_DigestFinal_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DigestFinal calling\n");
#endif

  if (C_DigestFinal_closure == NULL) {
    C_DigestFinal_closure = caml_named_value("C_DigestFinal");
  }
  if (C_DigestFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DigestFinal\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DigestFinal", DIGEST_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_DigestFinal_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DigestFinal, DIGEST_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t myC_DigestKey(ck_session_handle_t input0, ck_object_handle_t input1)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DigestKey_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_DigestKey calling\n");
#endif

  if (C_DigestKey_closure == NULL) {
    C_DigestKey_closure = caml_named_value("C_DigestKey");
  }
  if (C_DigestKey_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DigestKey\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input1, NULL);
  tuple = caml_callbackN(*C_DigestKey_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_SignInit(ck_session_handle_t input0, struct ck_mechanism *input1,
	     ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_SignInit_closure = NULL;
  if (C_SignInit_closure == NULL) {
    C_SignInit_closure = caml_named_value("C_SignInit");
  }
  if (C_SignInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_SignInit calling\n");
#endif
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, SIGN_OP) != NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_SignInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Sign(ck_session_handle_t input0, unsigned char *input1,
	 unsigned long input1_len, unsigned char *output2,
	 unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_Sign_closure = NULL;
  /* Remember previous calls */
  p11_request_struct *elem;

  if (C_Sign_closure == NULL) {
    C_Sign_closure = caml_named_value("C_Sign");
  }
  if (C_Sign_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Sign\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
#ifdef DEBUG
  fprintf(stderr, "C_Sign calling\n");
#endif
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);

  /* Remember previous calls */
  check_linked_list("Sign", SIGN_OP, input0, input1, input1_len, output2,
		    output2_len);

  tuple = caml_callbackN(*C_Sign_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(Sign, SIGN_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_SignUpdate(ck_session_handle_t input0, unsigned char *input1,
	       unsigned long input1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_SignUpdate_closure = NULL;
  if (C_SignUpdate_closure == NULL) {
    C_SignUpdate_closure = caml_named_value("C_SignUpdate");
  }
  if (C_SignUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignUpdate\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_SignUpdate calling\n");
#endif
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_SignUpdate_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_SignFinal(ck_session_handle_t input0, unsigned char *output1,
	      unsigned long *output1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_SignFinal_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_SignFinal calling\n");
#endif

  if (C_SignFinal_closure == NULL) {
    C_SignFinal_closure = caml_named_value("C_SignFinal");
  }
  if (C_SignFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignFinal\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("SignFinal", SIGN_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_SignFinal_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(SignFinal, SIGN_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_SignRecoverInit(ck_session_handle_t input0, struct ck_mechanism *input1,
		    ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_SignRecoverInit_closure = NULL;

  if (C_SignRecoverInit_closure == NULL) {
    C_SignRecoverInit_closure = caml_named_value("C_SignRecoverInit");
  }
  if (C_SignRecoverInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignRecoverInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_SignRecoverInit calling\n");
#endif

  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, SIGN_RECOVER_OP) != NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_SignRecoverInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_SignRecover(ck_session_handle_t input0, unsigned char *input1,
		unsigned long input1_len, unsigned char *output2,
		unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_SignRecover_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_SignRecover calling\n");
#endif

  if (C_SignRecover_closure == NULL) {
    C_SignRecover_closure = caml_named_value("C_SignRecover");
  }
  if (C_SignRecover_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignRecover\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("SignRecover", SIGN_RECOVER_OP, input0, input1, input1_len,
		    output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_SignRecover_closure, 2, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(SignRecover, SIGN_RECOVER_OP, input0, input1, input1_len,
		     output2, output2_len);
}

ck_rv_t
myC_VerifyRecoverInit(ck_session_handle_t input0,
		      struct ck_mechanism *input1, ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_VerifyRecoverInit_closure = NULL;

  if (C_VerifyRecoverInit_closure == NULL) {
    C_VerifyRecoverInit_closure = caml_named_value("C_VerifyRecoverInit");
  }
  if (C_VerifyRecoverInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_VerifyRecoverInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_VerifyRecoverInit calling\n");
#endif
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, VERIFY_RECOVER_OP) !=
      NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_VerifyRecoverInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_VerifyInit(ck_session_handle_t input0, struct ck_mechanism *input1,
	       ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_VerifyInit_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_VerifyInit calling\n");
#endif

  if (C_VerifyInit_closure == NULL) {
    C_VerifyInit_closure = caml_named_value("C_VerifyInit");
  }
  if (C_VerifyInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_VerifyInit\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_VerifyInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Verify(ck_session_handle_t input0, unsigned char *input1,
	   unsigned long input1_len, unsigned char *input2,
	   unsigned long input2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_Verify_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Verify calling\n");
#endif

  if (C_Verify_closure == NULL) {
    C_Verify_closure = caml_named_value("C_Verify");
  }
  if (C_Verify_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Verify\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  args[2] = custom_pkcs11_c2ml_buffer_to_char_array(input2, input2_len);
  tuple = caml_callbackN(*C_Verify_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_VerifyUpdate(ck_session_handle_t input0, unsigned char *input1,
		 unsigned long input1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_VerifyUpdate_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_VerifyUpdate calling\n");
#endif

  if (C_VerifyUpdate_closure == NULL) {
    C_VerifyUpdate_closure = caml_named_value("C_VerifyUpdate");
  }
  if (C_VerifyUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_VerifyUpdate\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_VerifyUpdate_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_VerifyFinal(ck_session_handle_t input0, unsigned char *input1,
		unsigned long input1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_VerifyFinal_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_VerifyFinal calling\n");
#endif

  if (C_VerifyFinal_closure == NULL) {
    C_VerifyFinal_closure = caml_named_value("C_VerifyFinal");
  }
  if (C_VerifyFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_VerifyFinal\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_VerifyFinal_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_VerifyRecover(ck_session_handle_t input0, unsigned char *input1,
		  unsigned long input1_len, unsigned char *output2,
		  unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_VerifyRecover_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_VerifyRecover calling\n");
#endif

  if (C_VerifyRecover_closure == NULL) {
    C_VerifyRecover_closure = caml_named_value("C_VerifyRecover");
  }
  if (C_VerifyRecover_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_VerifyRecover\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("VerifyRecover", VERIFY_RECOVER_OP, input0, input1,
		    input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_VerifyRecover_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(VerifyRecover, VERIFY_RECOVER_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_EncryptInit(ck_session_handle_t input0, struct ck_mechanism *input1,
		ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_EncryptInit_closure = NULL;
  if (C_EncryptInit_closure == NULL) {
    C_EncryptInit_closure = caml_named_value("C_EncryptInit");
  }
  if (C_EncryptInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_EncryptInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_EncryptInit calling\n");
#endif

  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, ENCRYPT_OP) != NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_EncryptInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Encrypt(ck_session_handle_t input0, unsigned char *input1,
	    unsigned long input1_len, unsigned char *output2,
	    unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;
  p11_request_struct *elem;

  static value *C_Encrypt_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_Encrypt calling\n");
#endif

  /* Remember previous calls */
  if (C_Encrypt_closure == NULL) {
    C_Encrypt_closure = caml_named_value("C_Encrypt");
  }
  if (C_Encrypt_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Encrypt\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);

  /* Remember previous calls */
  check_linked_list("Encrypt", ENCRYPT_OP, input0, input1, input1_len, output2,
		    output2_len);

  tuple = caml_callbackN(*C_Encrypt_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(Encrypt, ENCRYPT_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_EncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		  unsigned long input1_len, unsigned char *output2,
		  unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_EncryptUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_EncryptUpdate calling\n");
#endif

  if (C_EncryptUpdate_closure == NULL) {
    C_EncryptUpdate_closure = caml_named_value("C_EncryptUpdate");
  }
  if (C_EncryptUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_EncryptUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("EncryptUpdate", ENCRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_EncryptUpdate_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(EncryptUpdate, ENCRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_EncryptFinal(ck_session_handle_t input0, unsigned char *output1,
		 unsigned long *output1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_EncryptFinal_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_EncryptFinal calling\n");
#endif

  if (C_EncryptFinal_closure == NULL) {
    C_EncryptFinal_closure = caml_named_value("C_EncryptFinal");
  }
  if (C_EncryptFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_EncryptFinal\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("EncryptFinal", ENCRYPT_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_EncryptFinal_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(EncryptFinal, ENCRYPT_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_DigestEncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *output2,
			unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DigestEncryptUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DigestEncryptUpdate calling\n");
#endif

  if (C_DigestEncryptUpdate_closure == NULL) {
    C_DigestEncryptUpdate_closure = caml_named_value("C_DigestEncryptUpdate");
  }
  if (C_DigestEncryptUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DigestEncryptUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DigestEncryptUpdate", DIGEST_ENCRYPT_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_DigestEncryptUpdate_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DigestEncryptUpdate, DIGEST_ENCRYPT_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
}

ck_rv_t
myC_SignEncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_SignEncryptUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_SignEncryptUpdate calling\n");
#endif

  if (C_SignEncryptUpdate_closure == NULL) {
    C_SignEncryptUpdate_closure = caml_named_value("C_SignEncryptUpdate");
  }
  if (C_SignEncryptUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_SignEncryptUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("SignEncryptUpdate", SIGN_ENCRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_SignEncryptUpdate_closure, 2, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(SignEncryptUpdate, SIGN_ENCRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptInit(ck_session_handle_t input0, struct ck_mechanism *input1,
		ck_object_handle_t input2)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 3);
  ck_rv_t ret;

  static value *C_DecryptInit_closure = NULL;
  if (C_DecryptInit_closure == NULL) {
    C_DecryptInit_closure = caml_named_value("C_DecryptInit");
  }
  if (C_DecryptInit_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DecryptInit\n");
    exit(-1);
  }
#ifdef DEBUG
  fprintf(stderr, "C_DecryptInit calling\n");
#endif

  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, DECRYPT_OP) != NULL) {
    CAMLreturn(CKR_OPERATION_ACTIVE);
  }

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_c2ml_pkcs11_struct_ck_mechanism(input1, NULL);
  args[2] = camlidl_c2ml_pkcs11_ck_object_handle_t(&input2, NULL);
  tuple = caml_callbackN(*C_DecryptInit_closure, 3, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t
myC_Decrypt(ck_session_handle_t input0, unsigned char *input1,
	    unsigned long input1_len, unsigned char *output2,
	    unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_Decrypt_closure = NULL;
  /* Remember previous calls */
  p11_request_struct *elem;
  if (C_Decrypt_closure == NULL) {
    C_Decrypt_closure = caml_named_value("C_Decrypt");
  }
  if (C_Decrypt_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_Decrypt\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }
#ifdef DEBUG
  fprintf(stderr, "C_Decrypt calling\n");
#endif

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);

  /* Remember previous calls */
  check_linked_list("Decrypt", DECRYPT_OP, input0, input1, input1_len, output2,
		    output2_len);

  tuple = caml_callbackN(*C_Decrypt_closure, 2, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(Decrypt, DECRYPT_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_DecryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		  unsigned long input1_len, unsigned char *output2,
		  unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DecryptUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DecryptUpdate calling\n");
#endif

  if (C_DecryptUpdate_closure == NULL) {
    C_DecryptUpdate_closure = caml_named_value("C_DecryptUpdate");
  }
  if (C_DecryptUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DecryptUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DecryptUpdate", DECRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_DecryptUpdate_closure, 2, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DecryptUpdate, DECRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptFinal(ck_session_handle_t input0, unsigned char *output1,
		 unsigned long *output1_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_DecryptFinal_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DecryptFinal calling\n");
#endif

  if (C_DecryptFinal_closure == NULL) {
    C_DecryptFinal_closure = caml_named_value("C_DecryptFinal");
  }
  if (C_DecryptFinal_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DecryptFinal\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DecryptFinal", DECRYPT_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_DecryptFinal_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DecryptFinal, DECRYPT_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_DecryptDigestUpdate(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *output2,
			unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DecryptDigestUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DecryptDigestUpdate calling\n");
#endif

  if (C_DecryptDigestUpdate_closure == NULL) {
    C_DecryptDigestUpdate_closure = caml_named_value("C_DecryptDigestUpdate");
  }
  if (C_DecryptDigestUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DecryptDigestUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DecryptDigestUpdate", DECRYPT_DIGEST_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_DecryptDigestUpdate_closure, 2, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DecryptDigestUpdate, DECRYPT_DIGEST_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptVerifyUpdate(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *output2,
			unsigned long *output2_len)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 2);
  ck_rv_t ret;

  static value *C_DecryptVerifyUpdate_closure = NULL;
  p11_request_struct *elem;

#ifdef DEBUG
  fprintf(stderr, "C_DecryptVerifyUpdate calling\n");
#endif

  if (C_DecryptVerifyUpdate_closure == NULL) {
    C_DecryptVerifyUpdate_closure = caml_named_value("C_DecryptVerifyUpdate");
  }
  if (C_DecryptVerifyUpdate_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_DecryptVerifyUpdate\n");
    exit(-1);
  }
  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    CAMLreturn(CKR_ARGUMENTS_BAD);
  }

  /* Remember previous calls */
  check_linked_list("DecryptVerifyUpdate", DECRYPT_VERIFY_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  args[1] = custom_pkcs11_c2ml_buffer_to_char_array(input1, input1_len);
  tuple = caml_callbackN(*C_DecryptVerifyUpdate_closure, 2, args);

  camlidl_ml2c_pkcs11_ck_rv_t(Field(tuple, 0), &ret, NULL);

  handle_linked_list(DecryptVerifyUpdate, DECRYPT_VERIFY_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
}

ck_rv_t myC_GetFunctionStatus(ck_session_handle_t input0)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_GetFunctionStatus_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_GetFunctionStatus calling\n");
#endif

  if (C_GetFunctionStatus_closure == NULL) {
    C_GetFunctionStatus_closure = caml_named_value("C_GetFunctionStatus");
  }
  if (C_GetFunctionStatus_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_GetFunctionStatus\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_GetFunctionStatus_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_CancelFunction(ck_session_handle_t input0)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_CancelFunction_closure = NULL;

#ifdef DEBUG
  fprintf(stderr, "C_CancelFunction calling\n");
#endif

  if (C_CancelFunction_closure == NULL) {
    C_CancelFunction_closure = caml_named_value("C_CancelFunction");
  }
  if (C_CancelFunction_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_CancelFunction\n");
    exit(-1);
  }
  args[0] = camlidl_c2ml_pkcs11_ck_session_handle_t(&input0, NULL);
  tuple = caml_callbackN(*C_CancelFunction_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}

ck_rv_t myC_LoadModule(const char *libname)
{
  CAMLparam0();
  CAMLlocal1(tuple);
  CAMLlocalN(args, 1);
  ck_rv_t ret;

  static value *C_LoadModule_closure = NULL;
#ifdef DEBUG
  fprintf(stderr, "C_LoadModule calling for module %s to be loaded\n", libname);
#endif
  if (C_LoadModule_closure == NULL) {
    C_LoadModule_closure = caml_named_value("C_LoadModule");
  }
  if (C_LoadModule_closure == NULL) {
    fprintf(stderr, "\nError binding with caml C_LoadModule\n");
    exit(-1);
  }
  args[0] = caml_copy_string(libname);
  tuple = caml_callbackN(*C_LoadModule_closure, 1, args);
  camlidl_ml2c_pkcs11_ck_rv_t(tuple, &ret, NULL);

  CAMLreturn(ret);
}
