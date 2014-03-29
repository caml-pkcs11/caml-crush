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
    File:    src/bindings-pkcs11/pkcs11_functions.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* For custom allocation and free functions */
extern void *custom_malloc(size_t size);
extern void custom_free(void **to_free);

#include "helpers_pkcs11.h"
#include "pkcs11_functions.h"
#include "pkcs11_aliasing.h"

/* Endianness handling */
unsigned long get_local_arch(void)
{
  unsigned long rv;
  unsigned int test = 0xAABBCCDD;

  if (((unsigned char *)&test)[0] == 0xDD) {
    /* LittleEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      rv = LITTLE_ENDIAN_64;
    } else {
      rv = LITTLE_ENDIAN_32;
    }
  } else {
    /* BigEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      rv = BIG_ENDIAN_64;
    } else {
      rv = BIG_ENDIAN_32;
    }
  }

  return rv;
}


/* Global variable holding the current module handle        */
void *module_handle = NULL;
CK_C_GetFunctionList get_func_list;
CK_FUNCTION_LIST *pkcs11 = NULL;

CK_RV ML_CK_C_Daemonize(unsigned char *param, unsigned long param_len)
{
  CK_RV rv = 0;
  DEBUG_CALL(ML_CK_C_Daemonize, " calling\n");
  /* TODO: If you decide so, it is possible to implement some privilege
   * reduction primitives here. The advantage of doing it here is that you
   * would not need the "sandbox" launcher.
   * This is called after the OCaml netplex binds the socket.
   */
  /* Dummy stuff below */
  if (param != NULL) {
    param = NULL;
  }
  if (param_len != 0) {
    param_len = 0;
  }

  return rv;
}

CK_RV ML_CK_C_SetupArch(unsigned long client_arch)
{
  CK_RV rv;
  rv = get_local_arch();
  /* Let's detect the client_arch to activate the 32 bit code */
  switch (client_arch) {
  case LITTLE_ENDIAN_64:
  case LITTLE_ENDIAN_32:
  case BIG_ENDIAN_64:
  case BIG_ENDIAN_32:
    break;

  default:
    DEBUG_CALL(ML_CK_C_SetupArch,
	       " unsupported architecture %ld asked by client\n", client_arch);
    rv = UNSUPPORTED_ARCHITECTURE;
  }
  return rv;
}

/* We load the library */
CK_RV ML_CK_C_LoadModule( /*in */ const char *libname)
{
  CK_RV rv;
  DEBUG_CALL(ML_CK_C_LoadModule, " calling on %s\n", libname);

  module_handle = dlopen(libname, RTLD_NOW);
  if (module_handle == NULL) {
#ifdef DEBUG
    printf("ML_CK_C_LoadModule: Failed to dlopen(RTLD_NOW) module %s, trying RTLD_LAZY\n", libname);
#endif
    module_handle = dlopen(libname, RTLD_LAZY);
    if (module_handle == NULL) {
#ifdef DEBUG
      printf("ML_CK_C_LoadModule: Failed to dlopen(RTLD_LAZY) module %s, giving up\n", libname);
#endif
      return CKR_FUNCTION_FAILED;
    }
  }
  /* Weird allocation for ANSI C compliance */
  *(void **)(&get_func_list) = dlsym(module_handle, "C_GetFunctionList");
  if (get_func_list == NULL) {
#ifdef DEBUG
    printf
	("ML_CK_C_LoadModule: Failed to dlsym C_GetFunctionList in module %s\n",
	 libname);
#endif
    return CKR_FUNCTION_FAILED;
  }
  /* We've got the pointer, now get all the PKCS11 function pointers inside the module */
  rv = get_func_list(&pkcs11);
  DEBUG_RET(ML_CK_C_LoadModule, rv, " C_GetFunctionList in module %s\n",
	    libname);
  return rv;
}

CK_RV ML_CK_C_Initialize(void)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Initialize);

  DEBUG_CALL(ML_CK_C_Initialize, " calling\n");
  /* We launch C_Initialize with NULL arguments */
  rv = pkcs11->C_Initialize(NULL);
  DEBUG_RET(ML_CK_C_Initialize, rv, "\n");
  return rv;
}

CK_RV ML_CK_C_Finalize(void)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Finalize);

  DEBUG_CALL(ML_CK_C_Finalize, " calling\n");
  /* We launch C_Finalize with NULL arguments */
  rv = pkcs11->C_Finalize(NULL);
  DEBUG_RET(ML_CK_C_Finalize, rv, "\n");
  return rv;
}

CK_RV ML_CK_C_GetInfo( /*in */ CK_INFO_PTR info)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetInfo);

  DEBUG_CALL(ML_CK_C_GetInfo, " called\n");

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (info != NULL) {
    info->cryptoki_version.major = info->cryptoki_version.minor = info->flags =
	0;
    memset(info->manufacturer_id, 0, sizeof(info->manufacturer_id));
    memset(info->library_description, 0, sizeof(info->library_description));
    info->library_version.major = info->library_version.minor = 0;
  }

  rv = pkcs11->C_GetInfo(info);

  DEBUG_RET(ML_CK_C_GetInfo, rv, "\n");
  return rv;
}

CK_RV ML_CK_C_WaitForSlotEvent( /*in */ CK_FLAGS flags,	/* out */
			       CK_SLOT_ID * pSlot)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_WaitForSlotEvent);

  DEBUG_CALL(ML_CK_C_WaitForSlotEvent, " called with flags %lx\n", flags);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (pSlot != NULL) {
    *pSlot = -1;
  }

  /* Call real C_WaitForSlotEvent with NULL as third argument since it is reserved 
     for future versions */
  rv = pkcs11->C_WaitForSlotEvent(flags, pSlot, NULL_PTR);

  DEBUG_RET(ML_CK_C_WaitForSlotEvent, rv, "\n");

#ifdef USE_ALIASING
  /* ALIASING */
  if (rv == CKR_OK) {
    /* alias the slot ID */
    if (pSlot != NULL) {
      *pSlot = alias(*pSlot, SLOTID);
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_GetSlotList( /*in */ unsigned int token_present,	/*out */
			  CK_SLOT_ID * slot_list, /*in */ unsigned long count,
			  /*out */ unsigned long *real_count)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetSlotList);
  
  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(real_count == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

  /* Initialize the returned number to zero */
  *real_count = 0UL;
  /* If the token number is > 255, we give up */
  if (token_present > 255) {
    rv = CKR_TOKEN_NOT_RECOGNIZED;
    DEBUG_RET(ML_CK_C_GetSlotList, rv,
	      " called with token_present = %u > 255\n", token_present);
    return rv;
  }
  /* Do we want to get the number of slots? */
  if (count == 0) {
    rv = pkcs11->C_GetSlotList((unsigned char)token_present, NULL_PTR,
			       real_count);
    DEBUG_CALL(ML_CK_C_GetSlotList,
	       " called for token_present %u with count 0, got %ld slots\n",
	       token_present, *real_count);
    return rv;
  }
  /* Else, we really want to populate a slot_list */
  *real_count = count;
  rv = pkcs11->C_GetSlotList((unsigned char)token_present, slot_list,
			     real_count);

  DEBUG_RET(ML_CK_C_GetSlotList, rv,
	    " token %u with count %ld, got %ld slots\n", token_present,
	    count, *real_count);

#ifdef USE_ALIASING
  /* ALIASING */
  if (rv == CKR_OK) {
    unsigned int i;
    if (slot_list != NULL) {
      for (i = 0; i < *real_count; i++) {
        /* alias the slot ID */
        slot_list[i] = alias(slot_list[i], SLOTID);
      }
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_GetSlotInfo( /*in */ CK_SLOT_ID slot_id,	/*out */
			  CK_SLOT_INFO * info)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetSlotInfo);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetSlotInfo, " called with slot_id = %ld\n", slot_id);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (info != NULL) {
    info->flags = 0;
    memset(info->slot_description, 0, sizeof(info->slot_description));
    memset(info->manufacturer_id, 0, sizeof(info->manufacturer_id));
    info->hardware_version.major = info->hardware_version.minor = 0;
    info->firmware_version.major = info->firmware_version.minor = 0;
  }

  rv = pkcs11->C_GetSlotInfo(slot_id, info);

  DEBUG_RET(ML_CK_C_GetSlotInfo, rv, " slot_id %ld\n", slot_id);
  return rv;
}

CK_RV ML_CK_C_GetTokenInfo( /*in */ CK_SLOT_ID slot_id,	/*out */
			   CK_TOKEN_INFO * info)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetTokenInfo);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (info != NULL) {
    memset(info->label, 0, sizeof(info->label));
    memset(info->manufacturer_id, 0, sizeof(info->manufacturer_id));
    memset(info->model, 0, sizeof(info->model));
    memset(info->serial_number, 0, sizeof(info->serial_number));
    info->flags = 0;
    info->max_session_count = info->session_count = info->max_rw_session_count =
	info->rw_session_count = info->max_pin_len = info->min_pin_len =
	info->total_public_memory = info->free_public_memory =
	info->total_private_memory = info->free_private_memory = 0;
    memset(info->utc_time, 0, sizeof(info->utc_time));
    info->hardware_version.major = info->hardware_version.minor = 0;
    info->firmware_version.major = info->firmware_version.minor = 0;
  }

  DEBUG_CALL(ML_CK_C_GetTokenInfo, " called with slot_id = %ld\n", slot_id);

  rv = pkcs11->C_GetTokenInfo(slot_id, info);

  DEBUG_RET(ML_CK_C_GetTokenInfo, rv, " slot_id %ld\n", slot_id);
  return rv;
}

CK_RV ML_CK_C_OpenSession( /*in */ CK_SLOT_ID slot_id, /*in */ CK_FLAGS flags,
			  /*out */ CK_SESSION_HANDLE * session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_OpenSession);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_OpenSession, " called with slot_id = %ld\n", slot_id);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (session != NULL) {
    *session = CK_INVALID_HANDLE;
  }

  rv = pkcs11->C_OpenSession(slot_id, flags, NULL, NULL, session);

  DEBUG_RET(ML_CK_C_OpenSession, rv, " slot_id %ld, session handle %ld\n",
	    slot_id, *session);

#ifdef USE_ALIASING
  /* ALIASING */
  if (rv == CKR_OK) {
    if (session != NULL) {
      *session = alias(*session, SESSION);
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_CloseSession( /*in */ CK_SESSION_HANDLE session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_CloseSession);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_CloseSession, " called with session = %ld\n", session);

  rv = pkcs11->C_CloseSession(session);

  DEBUG_RET(ML_CK_C_CloseSession, rv, " session = %ld\n", session);

#ifdef USE_ALIASING
  /* If we were OK, we remove the session alias */
  if (rv == CKR_OK) {
    remove_original(session, SESSION);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_CloseAllSessions( /*in */ CK_SLOT_ID slot_id)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_CloseAllSessions);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_CloseAllSessions, " called with slot_id = %ld\n", slot_id);

  rv = pkcs11->C_CloseAllSessions(slot_id);

  DEBUG_RET(ML_CK_C_CloseAllSessions, rv, " slot_id = %ld\n", slot_id);

#ifdef USE_ALIASING
  /* If we were OK, we remove the session alias */
  if (rv == CKR_OK) {
    /* We only do this if there is one slot     */
    if (list_size(SLOTID) == 1) {
      destroy_list(OBJECT);
      destroy_list(SESSION);
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_GetSessionInfo( /*in */ CK_SESSION_HANDLE session,	/*out */
			     CK_SESSION_INFO * session_info)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetSessionInfo);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetSessionInfo, " called with session = %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (session_info != NULL) {
    session_info->slot_id = -1;
    session_info->state = session_info->flags = session_info->device_error = 0;
  }

  rv = pkcs11->C_GetSessionInfo(session, session_info);

  DEBUG_RET(ML_CK_C_GetSessionInfo, rv, " session %ld\n", session);

#ifdef USE_ALIASING
  /* Alias the result inside tje session info structure */
  /* ALIASING */
  if (rv == CKR_OK) {
    if (session_info != NULL) {
      session_info->slotID = alias(session_info->slotID, SLOTID);
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_Login( /*in */ CK_SESSION_HANDLE session,	/*in */
		    CK_USER_TYPE user_type, /*in */ unsigned char *pin,	/*in */
		    unsigned long pin_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Login);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Login, " called with session = %ld, user type %ld\n",
	     session, user_type);

  rv = pkcs11->C_Login(session, user_type, pin, pin_len);

  DEBUG_RET(ML_CK_C_Login, rv, " session = %ld, user type %ld\n", session,
	    user_type);
  return rv;
}

CK_RV ML_CK_C_Logout( /*in */ CK_SESSION_HANDLE session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Logout);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Logout, " called with session = %ld\n", session);

  rv = pkcs11->C_Logout(session);

  DEBUG_RET(ML_CK_C_Logout, rv, " session = %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_GetMechanismList( /*in */ CK_SLOT_ID slot_id,	/*out */
			       CK_MECHANISM_TYPE * mechanism_list,	/*in */
			       unsigned long count,	/*out */
			       unsigned long *real_count)
{
  CK_RV rv;
  unsigned long local_count;

  CHECK_MODULE_FUNCTION(C_GetMechanismList);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(real_count == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  /* Initialize the returned number to zero */
  *real_count = 0UL;
  /* Do we want to get the number of mechanisms? */
  if (count == 0) {
    rv = pkcs11->C_GetMechanismList(slot_id, NULL, &local_count);
    *real_count = local_count;
    DEBUG_CALL(ML_CK_C_GetMechanismList,
	       " called for slot_id %ld with count 0 got %ld mechanisms\n",
	       slot_id, *real_count);
    return rv;
  }
  /* Else, we really wan to populate a mechanism_list */
  *real_count = count;
  rv = pkcs11->C_GetMechanismList(slot_id, mechanism_list, real_count);

  DEBUG_RET(ML_CK_C_GetMechanismList, rv,
	    " slot_id %ld with count %ld, got %ld mechanisms\n", slot_id,
	    count, *real_count);
  return rv;
}

CK_RV ML_CK_C_GetMechanismInfo( /*in */ CK_SLOT_ID slot_id,	/*in */
			       CK_MECHANISM_TYPE mechanism,	/*out */
			       CK_MECHANISM_INFO * mechanism_info)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetMechanismInfo);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetMechanismInfo,
	     " called with slot_id = %ld and mech_type %ld\n", slot_id,
	     mechanism);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (mechanism_info != NULL) {
    mechanism_info->min_key_size = mechanism_info->max_key_size =
	mechanism_info->flags = 0;
  }

  rv = pkcs11->C_GetMechanismInfo(slot_id, mechanism, mechanism_info);

  DEBUG_RET(ML_CK_C_GetMechanismInfo, rv, " slot_id %ld and mech_type:%ld\n",
	    slot_id, mechanism);
  return rv;
}

CK_RV ML_CK_C_InitToken( /*in */ CK_SLOT_ID slot_id, /*in */ unsigned char *pin,
			/*in */ unsigned long pin_len,
			/*in */
			unsigned char *label)
{
  CK_RV rv;
  unsigned char tmp_label[33];
  CHECK_MODULE_FUNCTION(C_InitToken);

#ifdef USE_ALIASING
  /* UNALIASING */
  slot_id = unalias(slot_id, SLOTID);
  /*------------*/
#endif

  /* The label must be exactly 32 bytes long max as stated by the PKCS#11 standard */
  /* It must be padded with blank chars                                            */
  memset(tmp_label, ' ', sizeof(tmp_label));
  tmp_label[sizeof(tmp_label) - 1] = 0;
  if (strnlen((char *)label, 33) > 32) {
    memcpy(tmp_label, label, 32);
  } else {
    memcpy(tmp_label, label, strnlen((char *)label, 32));
  }
  DEBUG_CALL(ML_CK_C_InitToken,
	     " called will with slot_id = %ld, label %s\n", slot_id, tmp_label);

  /* If pin_len == 0, spec says we try protected authentication path by passing
     a NULL_PTR to function */
  if (pin_len == 0) {
    /* If CKF_PROTECTED_AUTHENTICATION_PATH is in the token features */
    /* lauch it                                                      */
    CK_TOKEN_INFO token_info;
    rv = pkcs11->C_GetTokenInfo(slot_id, &token_info);
    if (rv != CKR_OK) {
      /* If there was an issue with the C_GetTokenInfo, make a transparent call */
      rv = pkcs11->C_InitToken(slot_id, pin, pin_len, tmp_label);
      DEBUG_RET(ML_CK_C_InitToken, rv, " slot_id = %ld\n", slot_id);
      return rv;
    }
    if ((token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0) {
      rv = pkcs11->C_InitToken(slot_id, NULL_PTR, pin_len, tmp_label);
      DEBUG_RET(ML_CK_C_InitToken, rv, " slot_id = %ld\n", slot_id);
      return rv;
    } else {
      /* If there is no CKF_PROTECTED_AUTHENTICATION_PATH and the pin_len is null, return */
      /* CKR_PIN_INCORRECT                                                                */
      DEBUG_RET(ML_CK_C_InitToken, CKR_ARGUMENTS_BAD, " slot_id = %ld\n",
		slot_id);
      return CKR_ARGUMENTS_BAD;
    }
  }
  /* Else, we have a PIN */
  rv = pkcs11->C_InitToken(slot_id, pin, pin_len, tmp_label);

  DEBUG_RET(ML_CK_C_InitToken, rv, " slot_id = %ld\n", slot_id);
  return rv;
}

CK_RV ML_CK_C_InitPIN( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *pin, /*in */ unsigned long pin_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_InitPIN);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_InitPIN, " called with session = %ld\n", session);

  /* If pin_len == 0, spec says we try protected authentication path by passing
     a NULL_PTR to function */
  if (pin_len == 0) {
    /* If CKF_PROTECTED_AUTHENTICATION_PATH is in the token features */
    /* lauch it                                                      */
    /* First, get the slot ID of the current session                 */
    CK_SESSION_INFO session_info;
    CK_TOKEN_INFO token_info;
    rv = pkcs11->C_GetSessionInfo(session, &session_info);
    if (rv != CKR_OK) {
      /* If there was an issue with the C_GetSessionInfo, make a transparent call */
      rv = pkcs11->C_InitPIN(session, pin, pin_len);
      DEBUG_RET(ML_CK_C_InitPIN, rv, " session = %ld\n", session);
      return rv;
    }
    rv = pkcs11->C_GetTokenInfo(session_info.slotID, &token_info);
    if (rv != CKR_OK) {
      /* If there was an issue with the C_GetTokenInfo, make a transparent call   */
      rv = pkcs11->C_InitPIN(session, pin, pin_len);
      DEBUG_RET(ML_CK_C_InitPIN, rv, " session = %ld\n", session);
      return rv;
    }
    if ((token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0) {
      rv = pkcs11->C_InitPIN(session, NULL_PTR, pin_len);
      DEBUG_RET(ML_CK_C_InitPIN, rv, " session = %ld\n", session);
      return rv;
    } else {
      /* If there is no CKF_PROTECTED_AUTHENTICATION_PATH and the pin_len is null, return */
      /* CKR_PIN_INVALID                                                                  */
      DEBUG_RET(ML_CK_C_InitPIN, CKR_PIN_INVALID, " session = %ld\n", session);
      return CKR_PIN_INVALID;
    }
  }

  /* Else, we have a PIN */
  rv = pkcs11->C_InitPIN(session, pin, pin_len);

  DEBUG_RET(ML_CK_C_InitPIN, rv, " session = %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SetPIN( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *old_pin, /*in */ unsigned long old_pin_len,
		     /*in */ unsigned char *new_pin,
		     /*in */
		     unsigned long new_pin_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SetPIN);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SetPIN, " called with session = %ld\n", session);

  /* If pin_len == 0, spec says we try protected authentication path by passing
     a NULL_PTR to function */
  if (old_pin_len == 0 && new_pin_len == 0) {
    /* If CKF_PROTECTED_AUTHENTICATION_PATH is in the token features */
    /* lauch it                                                      */
    /* First, get the slot ID of the current session                 */
    CK_SESSION_INFO session_info;
    CK_TOKEN_INFO token_info;
    rv = pkcs11->C_GetSessionInfo(session, &session_info);
    if (rv != CKR_OK) {
      /* If there was an issue with the C_GetSessionInfo, make a transparent call */
      rv = pkcs11->C_SetPIN(session, old_pin, old_pin_len, new_pin,
			    new_pin_len);
      DEBUG_RET(ML_CK_C_SetPIN, rv, " session = %ld\n", session);
      return rv;
    }
    rv = pkcs11->C_GetTokenInfo(session_info.slotID, &token_info);
    if (rv != CKR_OK) {
      /* If there was an issue with the C_GetTokenInfo, make a transparent call   */
      rv = pkcs11->C_SetPIN(session, old_pin, old_pin_len, new_pin,
			    new_pin_len);
      DEBUG_RET(ML_CK_C_SetPIN, rv, " session = %ld\n", session);
      return rv;
    }
    if ((token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0) {
      rv = pkcs11->C_SetPIN(session, NULL_PTR, old_pin_len, NULL_PTR,
			    new_pin_len);
      DEBUG_RET(ML_CK_C_SetPIN, rv, " session = %ld\n", session);
      return rv;
    } else {
      /* If there is no CKF_PROTECTED_AUTHENTICATION_PATH and the pin_len is null, return */
      /* CKR_PIN_INVALID                                                                  */
      DEBUG_RET(ML_CK_C_SetPIN, CKR_PIN_INVALID, " session = %ld\n", session);
      return CKR_PIN_INVALID;
    }
  }

  /* Else, we have a PIN */
  rv = pkcs11->C_SetPIN(session, old_pin, old_pin_len, new_pin, new_pin_len);

  DEBUG_RET(ML_CK_C_SetPIN, rv, " session = %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SeedRandom( /*in */ CK_SESSION_HANDLE session,	/*in */
			 unsigned char *seed, /*in */ unsigned long seed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_InitPIN);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SeedRandom, " called with session = %ld\n", session);

  rv = pkcs11->C_SeedRandom(session, seed, seed_len);

  DEBUG_RET(ML_CK_C_SeedRandom, rv, " session = %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_GenerateRandom( /*in */ CK_SESSION_HANDLE session,	/*out */
			     unsigned char *random_data,	/*in */
			     unsigned long rand_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GenerateRandom);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GenerateRandom,
	     " called for session %ld and %ld random bytes should be generated\n",
	     session, rand_len);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (random_data != 0) {
    memset(random_data, 0, rand_len);
  }

  rv = pkcs11->C_GenerateRandom(session, random_data, rand_len);

  DEBUG_RET(ML_CK_C_GenerateRandom, rv,
	    " session %ld and %ld random bytes should have been generated\n",
	    session, rand_len);
  return rv;
}

CK_RV ML_CK_C_FindObjectsInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_ATTRIBUTE * templ, /*in */ unsigned long count)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_FindObjectsInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_FindObjectsInit,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  rv = pkcs11->C_FindObjectsInit(session, templ, count);

  DEBUG_RET(ML_CK_C_FindObjectsInit, rv,
	    " session %ld and template of %ld size\n", session, count);
  return rv;
}

CK_RV ML_CK_C_FindObjects( /*in */ CK_SESSION_HANDLE session,	/*out */
			  CK_OBJECT_HANDLE * object,	/*in */
			  unsigned long max_object_count,	/*out */
			  unsigned long *object_count)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_FindObjects);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  /* Initialize the object_count to zero */
  if (object_count != NULL) {
    *object_count = 0UL;
  }

  DEBUG_CALL(ML_CK_C_FindObjects,
	     " called for session %ld and max objects %ld\n", session,
	     max_object_count);

  rv = pkcs11->C_FindObjects(session, object, max_object_count, object_count);

  if (object_count != NULL) {
    DEBUG_RET(ML_CK_C_FindObjects, rv,
	    " called for session %ld and max objects %ld, got %ld\n",
	    session, max_object_count, *object_count);
  }

#ifdef USE_ALIASING
  /* Alias all the returned objects */
  /* ALIASING */
  if (rv == CKR_OK) {
    unsigned int i;
    if ((object != NULL) && (object_count != NULL)) {
      for (i = 0; i < *object_count; i++) {
        object[i] = alias(object[i], OBJECT);
      }
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_FindObjectsFinal( /*in */ CK_SESSION_HANDLE session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_FindObjectsFinal);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_FindObjectsFinal, " called for session %ld\n", session);

  rv = pkcs11->C_FindObjectsFinal(session);

  DEBUG_RET(ML_CK_C_FindObjectsFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_GenerateKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism, /*in */ CK_ATTRIBUTE * templ,
			  /*in */ unsigned long count,
			  /*out */
			  CK_OBJECT_HANDLE * phkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GenerateKey);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GenerateKey,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phkey != NULL) {
    *phkey = CK_INVALID_HANDLE;
  }

  /* We check if there is no param_len is 0, then we force mechanism.pParameter
     to NULL_PTR */
  if (mechanism.ulParameterLen == 0) {
    mechanism.pParameter = NULL_PTR;
  }
  /* If the template has size 0, we force a NULL pointers */
  if (count == 0) {
    templ = NULL_PTR;
  }

  rv = pkcs11->C_GenerateKey(session, &mechanism, templ, count, phkey);

  DEBUG_RET(ML_CK_C_GenerateKey, rv,
	    " session %ld and template of %ld size\n", session, count);

#ifdef USE_ALIASING
  /* Alias all the returned key object */
  /* ALIASING */
  if ((rv == CKR_OK) && (phkey != NULL)) {
    *phkey = alias(*phkey, OBJECT);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_GenerateKeyPair( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_MECHANISM mechanism,	/*in */
			      CK_ATTRIBUTE * pub_templ,	/*in */
			      unsigned long pub_count,	/*in */
			      CK_ATTRIBUTE * priv_templ,	/*in */
			      unsigned long priv_count,	/*out */
			      CK_OBJECT_HANDLE * phpubkey,	/*out */
			      CK_OBJECT_HANDLE * phprivkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GenerateKeyPair);

  DEBUG_CALL(ML_CK_C_GenerateKeyPair,
	     " called for session %ld and pub_template of %ld size and priv_template of %ld size\n",
	     session, pub_count, priv_count);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phpubkey != NULL) {
    *phpubkey = CK_INVALID_HANDLE;
  }
  if (phprivkey != NULL) {
    *phprivkey = CK_INVALID_HANDLE;
  }
#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  /* We check if there is no param_len is 0, then we force mechanism.pParameter to NULL_PTR */
  if (mechanism.ulParameterLen == 0) {
    mechanism.pParameter = NULL_PTR;
  }
  /* If one of the two templates has size zero, we force NULL pointers */
  if (pub_count == 0) {
    pub_templ = NULL_PTR;
  }
  if (priv_count == 0) {
    priv_templ = NULL_PTR;
  }
  rv = pkcs11->C_GenerateKeyPair(session, &mechanism, pub_templ, pub_count,
				 priv_templ, priv_count, phpubkey, phprivkey);

  DEBUG_RET(ML_CK_C_GenerateKeyPair, rv,
	    " session %ld and pub_template of %ld size and priv_template of %ld size\n",
	    session, pub_count, priv_count);

#ifdef USE_ALIASING
  /* Alias all the returned key objects */
  /* ALIASING */
  if (rv == CKR_OK) {
    if (phpubkey != NULL) {
      *phpubkey = alias(*phpubkey, OBJECT);
    }
    if (phprivkey != NULL) {
      *phprivkey = alias(*phprivkey, OBJECT);
    }
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_CreateObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			   CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			   /*out */ CK_OBJECT_HANDLE * phobject)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_CreateObject);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_CreateObject,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phobject != NULL) {
    *phobject = CK_INVALID_HANDLE;
  }

  rv = pkcs11->C_CreateObject(session, templ, count, phobject);

  DEBUG_RET(ML_CK_C_CreateObject, rv,
	    " session %ld and template of %ld size\n", session, count);

#ifdef USE_ALIASING
  /* Alias all the returned object */
  /* ALIASING */
  if ((rv == CKR_OK) && (phobject != NULL)) {
    *phobject = alias(*phobject, OBJECT);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_CopyObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_OBJECT_HANDLE hobject, /*in */ CK_ATTRIBUTE * templ,
			 /*in */ unsigned long count,
			 /*out */
			 CK_OBJECT_HANDLE * phnewobject)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_CopyObject);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hobject = unalias(hobject, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_CopyObject,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phnewobject != NULL) {
    *phnewobject = CK_INVALID_HANDLE;
  }

  rv = pkcs11->C_CopyObject(session, hobject, templ, count, phnewobject);

  DEBUG_RET(ML_CK_C_CopyObject, rv, " session %ld, new object handle %ld\n",
	    session, *phnewobject);

#ifdef USE_ALIASING
  /* Alias all the returned object */
  /* ALIASING */
  if ((rv == CKR_OK) && (phnewobject != NULL)) {
    *phnewobject = alias(*phnewobject, OBJECT);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_DestroyObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			    CK_OBJECT_HANDLE hobject)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DestroyObject);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hobject = unalias(hobject, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DestroyObject, " called for session %ld\n", session);

  rv = pkcs11->C_DestroyObject(session, hobject);

  DEBUG_RET(ML_CK_C_DestroyObject, rv, " session %ld\n", session);

  return rv;
}

CK_RV ML_CK_C_GetAttributeValue( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_OBJECT_HANDLE hobject,	/*in,out */
				CK_ATTRIBUTE * templ,	/*in */
				unsigned long count)
{
  CK_RV rv;
  CK_ULONG i = 0UL;
  CHECK_MODULE_FUNCTION(C_GetAttributeValue);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hobject = unalias(hobject, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetAttributeValue,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  /* Sanity check */
  if ((templ == NULL) && (count > 0)) {
    /* We normally shouldn't end here */
    return CKR_GENERAL_ERROR;
  }
  /* Setting NULL_PTR when needed */
  for (i = 0UL; i < count; i++) {
    if (templ[i].ulValueLen == 0) {
      DEBUG_CALL(ML_CK_C_GetAttributeValue, " adding NULL_PTR to template\n");
      templ[i].pValue = NULL_PTR;
    }
  }
  rv = pkcs11->C_GetAttributeValue(session, hobject, templ, count);

  DEBUG_RET(ML_CK_C_GetAttributeValue, rv,
	    " session %ld and template of %ld size\n", session, count);
  return rv;
}

CK_RV ML_CK_C_SetAttributeValue( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_OBJECT_HANDLE hobject,	/*in */
				CK_ATTRIBUTE * templ,	/*in */
				unsigned long count)
{
  CK_RV rv;
  CK_ULONG i = 0UL;
  CHECK_MODULE_FUNCTION(C_SetAttributeValue);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hobject = unalias(hobject, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SetAttributeValue,
	     " called for session %ld and template of %ld size\n", session,
	     count);

  /* Sanity check */
  if ((templ == NULL) && (count > 0)) {
    /* We normally shouldn't end here */
    return CKR_GENERAL_ERROR;
  }
  /* Setting NULL_PTR when needed */
  for (i = 0UL; i < count; i++) {
    if (templ[i].ulValueLen == 0) {
      printf("C_SetAttributeValue adding NULL_PTR to template\n");
      templ[i].pValue = NULL_PTR;
    }
  }
  rv = pkcs11->C_SetAttributeValue(session, hobject, templ, count);

  DEBUG_RET(ML_CK_C_SetAttributeValue, rv,
	    " session %ld and template of %ld size\n", session, count);
  return rv;
}

/* TODO When CKR_FUNCTION_NOT_SUPPORTED, the pointer gives invalid values */
CK_RV ML_CK_C_GetObjectSize( /*in */ CK_SESSION_HANDLE session,	/*in */
			    CK_OBJECT_HANDLE hobject,	/*out */
			    unsigned long *object_size)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetObjectSize);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hobject = unalias(hobject, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetObjectSize, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (object_size != NULL) {
    *object_size = 0;
  }

  rv = pkcs11->C_GetObjectSize(session, hobject, object_size);

  /* Sanity check */
  if ((rv != CKR_OK) && (object_size != NULL)) {
    *object_size = 0UL;
  }
  
  if (object_size != NULL) {
    DEBUG_RET(ML_CK_C_GetObjectSize, rv,
	    " session %ld and got object_size: %ld\n", session, *object_size);
  }

  return rv;
}

CK_RV ML_CK_C_WrapKey( /*in */ CK_SESSION_HANDLE session,	/*in */
		      CK_MECHANISM mechanism,	/*in */
		      CK_OBJECT_HANDLE hwrappingkey,	/*in */
		      CK_OBJECT_HANDLE hkey,
		      /*out */ unsigned char *wrapped_key,
		      /*in */
		      unsigned long *wrapped_key_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_WrapKey);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hwrappingkey = unalias(hwrappingkey, OBJECT);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_WrapKey,
	     " called for session %ld, wrapping key handle %ld and wrapped key handle %ld\n",
	     session, hwrappingkey, hkey);

  rv = pkcs11->C_WrapKey(session, &mechanism, hwrappingkey, hkey, wrapped_key,
			 wrapped_key_len);

  /* Sanity check */
  if ((rv != CKR_OK) && (wrapped_key_len != NULL)) {
    *wrapped_key_len = 0UL;
  }
  DEBUG_RET(ML_CK_C_WrapKey, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_UnwrapKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_MECHANISM mechanism,	/*in */
			CK_OBJECT_HANDLE hunwrappingkey,	/*in */
			unsigned char *wrapped_key,	/*in */
			unsigned long wrapped_key_len,	/*in */
			CK_ATTRIBUTE * templ, /*in */ unsigned long count,	/*out */
			CK_OBJECT_HANDLE * phunwrappedkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_UnwrapKey);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hunwrappingkey = unalias(hunwrappingkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_UnwrapKey,
	     " called for session %ld, unwrapping key %ld\n", session,
	     hunwrappingkey);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phunwrappedkey != NULL) {
    *phunwrappedkey = CK_INVALID_HANDLE;
  }

  rv = pkcs11->C_UnwrapKey(session, &mechanism, hunwrappingkey, wrapped_key,
			   wrapped_key_len, templ, count, phunwrappedkey);

  DEBUG_RET(ML_CK_C_UnwrapKey, rv, " session %ld\n", session);

#ifdef USE_ALIASING
  /* Alias all the returned object */
  /* ALIASING */
  if ((rv == CKR_OK) && (phunwrappedkey != NULL)) {
    *phunwrappedkey = alias(*phunwrappedkey, OBJECT);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_DeriveKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_MECHANISM mechanism,	/*in */
			CK_OBJECT_HANDLE hbasekey,
			/*in */ CK_ATTRIBUTE * templ,
			/*in */
			unsigned long count,
			/*out */ CK_OBJECT_HANDLE * phkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DeriveKey);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hbasekey = unalias(hbasekey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DeriveKey, " called for session %ld, key handle %ld\n",
	     session, hbasekey);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if (phkey != NULL) {
    *phkey = CK_INVALID_HANDLE;
  }

  rv = pkcs11->C_DeriveKey(session, &mechanism, hbasekey, templ, count, phkey);

  DEBUG_RET(ML_CK_C_DeriveKey, rv, " session %ld\n", session);

#ifdef USE_ALIASING
  /* Alias all the returned object */
  /* ALIASING */
  if ((rv == CKR_OK) && (phkey != NULL)) {
    *phkey = alias(*phkey, OBJECT);
  }
  /*------------*/
#endif

  return rv;
}

CK_RV ML_CK_C_DigestInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_MECHANISM mechanism)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DigestInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DigestInit, " called for session %ld\n", session);

  rv = pkcs11->C_DigestInit(session, &mechanism);

  DEBUG_RET(ML_CK_C_DigestInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_Digest( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *data, /*in */ unsigned long data_len,	/*out */
		     unsigned char *digest, /*in */ unsigned long *digest_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Digest);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Digest, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((digest != NULL) && (digest_len != NULL)) {
    memset(digest, 0, *digest_len);
  }
  rv = pkcs11->C_Digest(session, data, data_len, digest, digest_len);

  /* Sanity check */
  if ((rv != CKR_OK) && (digest_len != NULL)) {
    *digest_len = 0UL;
  }

  DEBUG_RET(ML_CK_C_Digest, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DigestUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char *data, /*in */ unsigned long data_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DigestUpdate);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DigestUpdate, " called for session %ld\n", session);

  rv = pkcs11->C_DigestUpdate(session, data, data_len);

  DEBUG_RET(ML_CK_C_DigestUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DigestKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DigestKey);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DigestKey, " called for session %ld\n", session);

  rv = pkcs11->C_DigestKey(session, hkey);

  DEBUG_RET(ML_CK_C_DigestKey, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DigestFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			  unsigned char *digest,	/*in */
			  unsigned long *digest_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DigestFinal);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DigestFinal, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((digest != NULL) && (digest_len != NULL)) {
    memset(digest, 0, *digest_len);
  }

  rv = pkcs11->C_DigestFinal(session, digest, digest_len);

  if ((rv != CKR_OK) && (digest_len != NULL)) {
    *digest_len = 0UL;
  }

  DEBUG_RET(ML_CK_C_DigestFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignInit( /*in */ CK_SESSION_HANDLE session,	/*in */
		       CK_MECHANISM mechanism, /*in */ CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignInit, " called for session %ld\n", session);

  rv = pkcs11->C_SignInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_SignInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignRecoverInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_MECHANISM mechanism,	/*in */
			      CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignRecoverInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignRecoverInit, " called for session %ld\n", session);

  rv = pkcs11->C_SignRecoverInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_SignRecoverInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV
ML_CK_C_Sign( /*in */ CK_SESSION_HANDLE session, /*in */ unsigned char *data,
	     /*in */ unsigned long data_len,
	     /*out */
	     unsigned char *signature, /*in */ unsigned long *signed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Sign);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Sign, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((signature != NULL) && (signed_len != NULL)) {
    memset(signature, 0, *signed_len);
  }

  rv = pkcs11->C_Sign(session, data, data_len, signature, signed_len);

  /* Sanity check */
  if ((rv != CKR_OK) && (signed_len != NULL)) {
    *signed_len = 0UL;
  }

  DEBUG_RET(ML_CK_C_Sign, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignRecover( /*in */ CK_SESSION_HANDLE session,	/*in */
			  unsigned char *data, /*in */ unsigned long data_len,
			  /*out */ unsigned char *signature,
			  /*in */
			  unsigned long *signed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignRecover);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignRecover, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((signature != NULL) && (signed_len != NULL)) {
    memset(signature, 0, *signed_len);
  }

  rv = pkcs11->C_SignRecover(session, data, data_len, signature, signed_len);

  /* Sanity check */
  if ((rv != CKR_OK) && (signed_len != NULL)) {
    *signed_len = 0UL;
  }

  DEBUG_RET(ML_CK_C_SignRecover, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			 unsigned char *data, /*in */ unsigned long data_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignUpdate);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignUpdate, " called for session %ld\n", session);

  rv = pkcs11->C_SignUpdate(session, data, data_len);

  DEBUG_RET(ML_CK_C_SignUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			unsigned char *signature,	/*in */
			unsigned long *signed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignFinal);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignFinal, " called for session %ld\n", session);

  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((signature != NULL) && (signed_len != NULL)) {
    memset(signature, 0, *signed_len);
  }

  rv = pkcs11->C_SignFinal(session, signature, signed_len);

  if ((rv != CKR_OK) && (signed_len != NULL)) {
    *signed_len = 0UL;
  }

  DEBUG_RET(ML_CK_C_SignFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_VerifyInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_MECHANISM mechanism, /*in */ CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_VerifyInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_VerifyInit, " called for session %ld\n", session);

  rv = pkcs11->C_VerifyInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_VerifyInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_VerifyRecoverInit( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_MECHANISM mechanism,	/*in */
				CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_VerifyRecoverInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_VerifyRecoverInit, " called for session %ld\n", session);

  rv = pkcs11->C_VerifyRecoverInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_VerifyRecoverInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_Verify( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *data, /*in */ unsigned long data_len,	/*in */
		     unsigned char *signature, /*in */ unsigned long signed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Verify);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Verify, " called for session %ld\n", session);

  rv = pkcs11->C_Verify(session, data, data_len, signature, signed_len);

  DEBUG_RET(ML_CK_C_Verify, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_VerifyRecover( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *signature,	/*in */
			    unsigned long signature_len,	/*out */
			    unsigned char **data,	/*in */
			    unsigned long *data_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_VerifyRecover);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(data == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_VerifyRecover, " called for session %ld size %ld\n",
	     session, signature_len);

  rv = pkcs11->C_VerifyRecover(session, signature, signature_len, NULL_PTR,
			       data_len);
  if (rv != CKR_OK) {
    if(data_len != NULL){
      *data_len = 0UL;
    }
    return rv;
  }
  if (data_len != NULL) {
    DEBUG_CALL(ML_CK_C_VerifyRecover,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *data_len);
    *data = (unsigned char *)custom_malloc(*data_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*data != NULL) && (data_len != NULL)) {
    memset(*data, 0, *data_len);
  }
  rv = pkcs11->C_VerifyRecover(session, signature, signature_len, *data,
			       data_len);

  if (rv != CKR_OK) {
    custom_free((void **)data);
    if(data_len != NULL){
      *data_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_VerifyRecover, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_VerifyUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char *data, /*in */ unsigned long data_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_VerifyUpdate);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_VerifyUpdate, " called for session %ld\n", session);

  rv = pkcs11->C_VerifyUpdate(session, data, data_len);

  DEBUG_RET(ML_CK_C_VerifyUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_VerifyFinal( /*in */ CK_SESSION_HANDLE session,	/*in */
			  unsigned char *signature,	/*in */
			  unsigned long signed_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_VerifyFinal);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_VerifyFinal, " called for session %ld\n", session);

  rv = pkcs11->C_VerifyFinal(session, signature, signed_len);

  DEBUG_RET(ML_CK_C_VerifyFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_EncryptInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism, /*in */ CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_EncryptInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_EncryptInit, " called for session %ld\n", session);

  rv = pkcs11->C_EncryptInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_EncryptInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_Encrypt( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *data, /*in */ unsigned long data_len,	/*out */
		      unsigned char **encrypted,	/*in */
		      unsigned long *encrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Encrypt);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(encrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Encrypt, " called for session %ld size %ld\n", session,
	     data_len);

  rv = pkcs11->C_Encrypt(session, data, data_len, NULL_PTR, encrypted_len);
  if (rv != CKR_OK) {
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }
  if (encrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_Encrypt,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *encrypted_len);

    *encrypted = (unsigned char *)custom_malloc(*encrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*encrypted != NULL) && (encrypted_len != NULL)) {
    memset(*encrypted, 0, *encrypted_len);
  }
  rv = pkcs11->C_Encrypt(session, data, data_len, *encrypted, encrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)encrypted);
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_Encrypt, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_EncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *data, /*in */ unsigned long data_len,
			    /*in */ unsigned char **encrypted,
			    /*in */
			    unsigned long *encrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_EncryptUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(encrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_EncryptUpdate, " called for session %ld size %ld\n",
	     session, data_len);

  rv = pkcs11->C_EncryptUpdate(session, data, data_len, NULL_PTR,
			       encrypted_len);
  if (rv != CKR_OK) {
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }
  if (encrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_EncryptUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *encrypted_len);

    *encrypted = (unsigned char *)custom_malloc(*encrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*encrypted != NULL) && (encrypted_len != NULL)) {
    memset(*encrypted, 0, *encrypted_len);
  }
  rv = pkcs11->C_EncryptUpdate(session, data, data_len, *encrypted,
			       encrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)encrypted);
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_EncryptUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DigestEncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *data,	/*in */
				  unsigned long data_len,	/*in */
				  unsigned char **encrypted,	/*in */
				  unsigned long *encrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DigestEncryptUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(encrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DigestEncryptUpdate,
	     " called for session %ld size %ld\n", session, data_len);

  rv = pkcs11->C_DigestEncryptUpdate(session, data, data_len, NULL_PTR,
				     encrypted_len);
  if (rv != CKR_OK) {
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }
  if (encrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_DigestEncryptUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *encrypted_len);

    *encrypted = (unsigned char *)custom_malloc(*encrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*encrypted != NULL) && (encrypted_len != NULL)) {
    memset(*encrypted, 0, *encrypted_len);
  }
  rv = pkcs11->C_DigestEncryptUpdate(session, data, data_len, *encrypted,
				     encrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)encrypted);
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_DigestEncryptUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SignEncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				unsigned char *data,	/*in */
				unsigned long data_len,	/*in */
				unsigned char **encrypted,	/*in */
				unsigned long *encrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SignEncryptUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(encrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SignEncryptUpdate, " called for session %ld size %ld\n",
	     session, data_len);

  rv = pkcs11->C_SignEncryptUpdate(session, data, data_len, NULL_PTR,
				   encrypted_len);
  if (rv != CKR_OK) {
    if (encrypted_len != NULL){
      *encrypted_len = 0UL;
    }
    return rv;
  }
  if (encrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_SignEncryptUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *encrypted_len);

    *encrypted = (unsigned char *)custom_malloc(*encrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*encrypted != NULL) && (encrypted_len != NULL)) {
    memset(*encrypted, 0, *encrypted_len);
  }

  rv = pkcs11->C_SignEncryptUpdate(session, data, data_len, *encrypted,
				   encrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)encrypted);
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_SignEncryptUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_EncryptFinal( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char **encrypted,	/*in */
			   unsigned long *encrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_EncryptFinal);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(encrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_EncryptFinal, " called for session %ld\n", session);

  rv = pkcs11->C_EncryptFinal(session, NULL_PTR, encrypted_len);
  if (rv != CKR_OK) {
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }
  if (encrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_EncryptFinal,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *encrypted_len);

    *encrypted = (unsigned char *)custom_malloc(*encrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*encrypted != NULL) && (encrypted_len != NULL)) {
    memset(*encrypted, 0, *encrypted_len);
  }

  rv = pkcs11->C_EncryptFinal(session, *encrypted, encrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)encrypted);
    if (encrypted_len != NULL) {
      *encrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_EncryptFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DecryptInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism, /*in */ CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DecryptInit);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hkey = unalias(hkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DecryptInit, " called for session %ld\n", session);

  rv = pkcs11->C_DecryptInit(session, &mechanism, hkey);

  DEBUG_RET(ML_CK_C_DecryptInit, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_Decrypt( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *encrypted,	/*in */
		      unsigned long encrypted_len,	/*out */
		      unsigned char **decrypted,	/*in */
		      unsigned long *decrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_Decrypt);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(decrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_Decrypt, " called for session %ld size %ld\n", session,
	     encrypted_len);

  rv = pkcs11->C_Decrypt(session, encrypted, encrypted_len, NULL_PTR,
			 decrypted_len);
  if (rv != CKR_OK) {
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }
  if (decrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_Decrypt,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *decrypted_len);

    *decrypted = (unsigned char *)custom_malloc(*decrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*decrypted != NULL) && (decrypted_len != NULL)) {
    memset(*decrypted, 0, *decrypted_len);
  }

  rv = pkcs11->C_Decrypt(session, encrypted, encrypted_len, *decrypted,
			 decrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)decrypted);
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_Decrypt, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DecryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *encrypted,	/*in */
			    unsigned long encrypted_len,	/*out */
			    unsigned char **decrypted,	/*in */
			    unsigned long *decrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DecryptUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(decrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/


#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DecryptUpdate, " called for session %ld size %ld\n",
	     session, encrypted_len);

  rv = pkcs11->C_DecryptUpdate(session, encrypted, encrypted_len, NULL_PTR,
			       decrypted_len);
  if (rv != CKR_OK) {
    if (decrypted_len != NULL){
      *decrypted_len = 0UL;
    }
    return rv;
  }
  if (decrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_DecryptUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *decrypted_len);

    *decrypted = (unsigned char *)custom_malloc(*decrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*decrypted != NULL) && (decrypted_len != NULL)) {
    memset(*decrypted, 0, *decrypted_len);
  }

  rv = pkcs11->C_DecryptUpdate(session, encrypted, encrypted_len, *decrypted,
			       decrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)decrypted);
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_DecryptUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DecryptFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			   unsigned char **decrypted,	/*in */
			   unsigned long *decrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DecryptFinal);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(decrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DecryptFinal, " called for session %ld size %ld\n",
	     session, *decrypted_len);

  rv = pkcs11->C_DecryptFinal(session, NULL_PTR, decrypted_len);
  if (rv != CKR_OK) {
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }
  if (decrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_DecryptFinal,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *decrypted_len);

    *decrypted = (unsigned char *)custom_malloc(*decrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*decrypted != NULL) && (decrypted_len != NULL)) {
    memset(*decrypted, 0, *decrypted_len);
  }

  rv = pkcs11->C_DecryptFinal(session, *decrypted, decrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)decrypted);
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_DecryptFinal, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DecryptDigestUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *encrypted,	/*in */
				  unsigned long encrypted_len,	/*out */
				  unsigned char **decrypted,	/*in */
				  unsigned long *decrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DecryptDigestUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(decrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DecryptDigestUpdate,
	     " called for session %ld size %ld\n", session, encrypted_len);

  rv = pkcs11->C_DecryptDigestUpdate(session, encrypted, encrypted_len,
				     NULL_PTR, decrypted_len);
  if (rv != CKR_OK) {
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }
  if (decrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_DecryptDigestUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *decrypted_len);

    *decrypted = (unsigned char *)custom_malloc(*decrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*decrypted != NULL) && (decrypted_len != NULL)) {
    memset(*decrypted, 0, *decrypted_len);
  }

  rv = pkcs11->C_DecryptDigestUpdate(session, encrypted, encrypted_len,
				     *decrypted, decrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)decrypted);
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_DecryptDigestUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_DecryptVerifyUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *encrypted,	/*in */
				  unsigned long encrypted_len,	/*out */
				  unsigned char **decrypted,	/*in */
				  unsigned long *decrypted_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_DecryptVerifyUpdate);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(decrypted == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_DecryptVerifyUpdate,
	     " called for session %ld size %ld\n", session, encrypted_len);

  rv = pkcs11->C_DecryptVerifyUpdate(session, encrypted, encrypted_len,
				     NULL_PTR, decrypted_len);
  if (rv != CKR_OK) {
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }
  if (decrypted_len != NULL) {
    DEBUG_CALL(ML_CK_C_DecryptVerifyUpdate,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *decrypted_len);

    *decrypted = (unsigned char *)custom_malloc(*decrypted_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*decrypted != NULL) && (decrypted_len != NULL)) {
    memset(*decrypted, 0, *decrypted_len);
  }

  rv = pkcs11->C_DecryptVerifyUpdate(session, encrypted, encrypted_len,
				     *decrypted, decrypted_len);

  if (rv != CKR_OK) {
    custom_free((void **)decrypted);
    if (decrypted_len != NULL) {
      *decrypted_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_DecryptVerifyUpdate, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_GetFunctionStatus( /*in */ CK_SESSION_HANDLE session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetFunctionStatus);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetFunctionStatus, " called for session %ld\n", session);

  rv = pkcs11->C_GetFunctionStatus(session);

  DEBUG_RET(ML_CK_C_GetFunctionStatus, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_CancelFunction( /*in */ CK_SESSION_HANDLE session)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_CancelFunction);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_CancelFunction, " called for session %ld\n", session);

  rv = pkcs11->C_CancelFunction(session);

  DEBUG_RET(ML_CK_C_CancelFunction, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_GetOperationState( /*in */ CK_SESSION_HANDLE session,	/*out */
				unsigned char **data,	/*in */
				unsigned long *data_len)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_GetOperationState);

  /****** Safeguard on input values *************/
  /* By design, some input values can't be NULL */
  /* (see functions in pkcs11_stubs.c where the */ 
  /*  functions here are called)                */
  /* We however check put a safeguard here      */
  if(data == NULL){
    return CKR_GENERAL_ERROR;  
  }
  /**********************************************/

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_GetOperationState, " called for session %ld\n", session);

  rv = pkcs11->C_GetOperationState(session, NULL_PTR, data_len);
  if (rv != CKR_OK) {
    if (data_len != NULL) {
      *data_len = 0UL;
    }
    return rv;
  }
  if (data_len != NULL) {
    DEBUG_CALL(ML_CK_C_GetOperationState,
	     " first call for session %ld returned needed size of %ld\n",
	     session, *data_len);

    *data = (unsigned char *)custom_malloc(*data_len * sizeof(char));
  }
  /* Fill the output with default invalid values in case */
  /* the PKCS#11 call fails                              */
  if ((*data != NULL) && (data_len != NULL)) {
    memset(*data, 0, *data_len);
  }

  rv = pkcs11->C_GetOperationState(session, *data, data_len);

  if (rv != CKR_OK) {
    custom_free((void **)data);
    if (data_len != NULL) {
      *data_len = 0UL;
    }
    return rv;
  }

  DEBUG_RET(ML_CK_C_GetOperationState, rv, " session %ld\n", session);
  return rv;
}

CK_RV ML_CK_C_SetOperationState( /*in */ CK_SESSION_HANDLE session,	/*in */
				unsigned char *data,	/*in */
				unsigned long data_len,	/*in */
				CK_OBJECT_HANDLE hencryptionkey,	/*in */
				CK_OBJECT_HANDLE hauthenticationkey)
{
  CK_RV rv;
  CHECK_MODULE_FUNCTION(C_SetOperationState);

#ifdef USE_ALIASING
  /* UNALIASING */
  session = unalias(session, SESSION);
  hencryptionkey = unalias(hencryptionkey, OBJECT);
  hauthenticationkey = unalias(hauthenticationkey, OBJECT);
  /*------------*/
#endif

  DEBUG_CALL(ML_CK_C_SetOperationState,
	     " called for session %ld, data size of %ld, encryption key handle %ld, authentication key handle %ld\n",
	     session, data_len, hencryptionkey, hauthenticationkey);

  rv = pkcs11->C_SetOperationState(session, data, data_len, hencryptionkey,
				   hauthenticationkey);

  DEBUG_RET(ML_CK_C_SetOperationState, rv, " session %ld\n", session);
  return rv;
}

void int_to_ulong_char_array( /*in */ unsigned long input,	/*out */
			     unsigned char *data)
{
  if (data != NULL) {
    *((unsigned long *)data) = input;
  }

  return;
}

void char_array_to_ulong( /*in */ unsigned char* data,	/* in */ size_t data_size,
                         /*out */ unsigned long* output)
{
  if (data_size > sizeof(unsigned long)){
    if (output != NULL) {
      memset(output, 0, sizeof(unsigned long));
    }
    return;
  }
  if ((data != NULL) && (output != NULL)) {
    memset(output, 0, sizeof(unsigned long));
    memcpy(output, data, data_size);
    return;
  }

  return;
}

#ifdef SERVER_ROLE
extern unsigned long peer_arch;
#endif
/* Host char array to network char array */
/* We only deal with 32-bit values       */
void hton_char_array( /*in */ unsigned char *input, unsigned long input_len,
                      /*out*/ unsigned char *output, unsigned long *output_len)
{
  unsigned int i;
  unsigned long arch;
  unsigned long data_size;
  /* We always output a 32-bit value */
#ifdef SERVER_ROLE
  arch = peer_arch;
#else
  arch = get_local_arch();
#endif
  if(input_len > 8){
    *output_len = 0;
    return;
  }
  if(input_len < 4){
    data_size = input_len;
  }
  else{
    data_size = 4;
  }
  *output_len = 4;
  if((input != NULL) && (output != NULL)){
    memset(output, 0, *output_len);
    switch (arch) {
      case LITTLE_ENDIAN_32:
      case LITTLE_ENDIAN_64:
        for(i=0; i < data_size; i++){
          output[3-i] = input[i];
        }
        break;
      case BIG_ENDIAN_32:
        for(i=0; i < data_size; i++){
          output[i] = input[i];
        }
        break;
      case BIG_ENDIAN_64:
        for(i=0; i < data_size; i++){
          output[3-i] = input[7-i];
        }
        break;
      default:
        break;
    }
  }
  return;
}

/* Network char array to host char array */
/* We only deal with 32-bit values       */
void ntoh_char_array( /*in */ unsigned char *input, unsigned long input_len,
                      /*out*/ unsigned char *output, unsigned long *output_len)
{
  unsigned int i;
  unsigned long arch;
  /* We always output a 32-bit value */
#ifdef SERVER_ROLE
  arch = peer_arch;
#else
  arch = get_local_arch();
#endif
  if(input_len != 4){
    *output_len = 0;
    return;
  }
  if((input != NULL) && (output != NULL)){
    switch (arch) {
      case LITTLE_ENDIAN_32:
        *output_len = 4;
        memset(output, 0, *output_len);
        for(i=0; i < 4; i++){
          output[i] = input[3-i];
        }
        break;
      case LITTLE_ENDIAN_64:
        *output_len = 8;
        memset(output, 0, *output_len);
        for(i=0; i < 4; i++){
          output[i] = input[3-i];
        }
        break;
      case BIG_ENDIAN_32:
        *output_len = 4;
        memset(output, 0, *output_len);
        for(i=0; i < 4; i++){
          output[i] = input[i];
        }
        break;
      case BIG_ENDIAN_64:
        *output_len = 8;
        memset(output, 0, *output_len);
        for(i=0; i < 4; i++){
          output[4+i] = input[i];
        }
        break;
      default:
        break;
    }
  }
  return;
}


