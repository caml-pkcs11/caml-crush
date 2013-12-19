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

    The current source code is part of the tests 6] source tree.

    Project: PKCS#11 Filtering Proxy
    File:    src/tests/c-based/main-shared.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <dlfcn.h>
#include "original_pkcs11.h"

/***** TODO : clean the code and make more tests ***/
/***** FIXME: the following code is ugly as is  ****/

int main(int argc, char **argv)
{
  int result;
  int i = 0;
  int j = 0;
  char *error;
  FILE *fp;
  void *handle;

  CK_RV ret = 1;
  CK_C_GetFunctionList pGetFunctionList = NULL;

  if (argc < 3) {
    printf("You must provide two args for dlopen mode ...\n");
    printf("%s (lazy|now) libpath\n", argv[0]);
    exit(-1);
  }
  if ((fp = fopen(argv[2], "r")) == NULL) {
    printf("Sorry P11 library %s can't be opened!\n", argv[2]);
    exit(-1);
  }
  fclose(fp);
  if (strcmp(argv[1], "lazy") == 0) {
    printf("Loading %s with RTLD_LAZY\n", argv[2]);
    handle = dlopen(argv[2], RTLD_LAZY);
  } else {
    if (strcmp(argv[1], "now") == 0) {
      printf("Loading with RTLD_NOW\n");
      handle = dlopen(argv[2], RTLD_NOW);
    } else {
      printf("Unknown dlopen parameter name %s\n", argv[1]);
      exit(0);
    }
  }

  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  dlerror();			/* Clear any existing error */

  /* Retrieve the entry point for C_GetFunctionList */
  pGetFunctionList = (CK_C_GetFunctionList) dlsym(handle, "C_GetFunctionList");
  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "%s\n", error);
    exit(EXIT_FAILURE);
  }

  /* Get the PKCS#11 function list */
  if (pGetFunctionList == NULL) {
    printf("Error while getting function list\n");
    exit(EXIT_FAILURE);
  }
  CK_FUNCTION_LIST_PTR p11 = NULL;
  (*pGetFunctionList) (&p11);

  ret = p11->C_Initialize(NULL);
  printf("C_Init ret %d\n", ret);

  CK_ULONG p11t_slot_count = 0;
  ret = p11->C_GetSlotList(1, NULL, &p11t_slot_count);
  printf("C_GetSlotList token present: yes ret %d, slot count %d\n", ret,
	 p11t_slot_count);

  ret = p11->C_GetSlotList(0, NULL, &p11t_slot_count);
  printf("C_GetSlotList token present: no ret %d, slot count %d\n", ret,
	 p11t_slot_count);

  /* GetSlotInfo  */
  CK_SLOT_INFO info;
  ret = p11->C_GetSlotInfo(0, &info);
  printf("C_GetSlotInfo slot %d ret %d, flags %d\n", 0, ret, info.flags);
  if (info.flags & CKF_TOKEN_PRESENT) {
    printf("Slot 0 is not present\n");
  } else {
    printf("Slot 0 is present\n");

  }

  ret = p11->C_GetSlotInfo(1, &info);
  printf("C_GetSlotInfo slot %d ret %d, flags %d\n", 1, ret, info.flags);
  if (info.flags & CKF_TOKEN_PRESENT) {
    printf("Slot 1 is not present\n");
  } else {
    printf("Slot 1 is present\n");
  }

  CK_INFO pInfo;
  ret = p11->C_GetInfo(&pInfo);
  printf("C_GetInfo ret %d\n", ret);
  printf("Cryptoki version %u.%u\n",
	 pInfo.cryptokiVersion.major, pInfo.cryptokiVersion.minor);
  printf("GetInfo flags %u\n", pInfo.flags);

  CK_MECHANISM_INFO mech_info;
  ret = p11->C_GetMechanismInfo(0, 1, &mech_info);
  printf("C_GetMechInfo ret %d\n", ret);
  printf("RSA_PKCS min: %lu %lu\n", mech_info.ulMinKeySize,
	 mech_info.ulMaxKeySize);
  CK_SESSION_HANDLE session;
  CK_BYTE buf1[10];
  ret = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
			   NULL, NULL, &session);
  printf("C_OpenSession ret %d session %d\n", ret, session);

  ret = p11->C_GenerateRandom(session, buf1, 10);
  printf("C_GeneRand ret %d\n", ret);
  ret = p11->C_Login(session, CKU_USER, "1234", 4);
  printf("C_Login ret %d\n", ret);

  CK_MECHANISM_TYPE array_mech[100];
  unsigned long len = 3;
  ret = p11->C_GetMechanismList(0, array_mech, &len);
  printf("C_GetMechList ret %d\n", ret);

  ret = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
			   NULL, NULL, &session);
  printf("C_OpenSession ret %d session %d\n", ret, session);

  unsigned char buff[50] = { 0 };
  unsigned long classz = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &classz, 8},
  };

  ret = p11->C_Login(session, CKU_USER, "1234", 4);
  printf("C_Login ret %d\n", ret);

  //ret = p11->C_FindObjectsInit(session, template, 1);
  ret = p11->C_FindObjectsInit(session, NULL, 0);
  printf("C_FindObjectInit ret %d\n", ret);

  unsigned long objcount = 1024;
  int maxobjcount = 8;
  CK_OBJECT_HANDLE objlist[8];
  ret = p11->C_FindObjects(session, objlist, maxobjcount, &objcount);
  printf("C_FindObject ret %d, %d elem returned\n", ret, objcount);

  ret = p11->C_FindObjectsFinal(session);
  printf("C_FindObjectFinal ret %d\n", ret);

  unsigned char *buff2;
  unsigned char *buff3;
  CK_BYTE *buff4;
  unsigned long class = 10;
/*
   CK_ATTRIBUTE stemplate[] ={
          {CKA_CLASS, NULL, 0},
          {CKA_LABEL, NULL, 0},
          {CKA_ID, NULL, 0},
          {CKA_VALUE, NULL, 0},
    }
     ;
*/
  for (j = 0; j < objcount; j++) {
    CK_ATTRIBUTE stemplate[] = {
      {CKA_CLASS, NULL, 0}
      ,
      {CKA_LABEL, NULL, 0}
      ,
      {CKA_ID, NULL, 0}
      ,
      {CKA_VALUE, NULL, 0}
      ,
    }
    ;
    ret = p11->C_GetAttributeValue(session, objlist[j], stemplate, 3);
    printf("FIRST C_GetAttribute %d, %d, %d\n", stemplate[0].ulValueLen,
	   stemplate[1].ulValueLen, stemplate[2].ulValueLen);
    printf("FIRST C_GetAttribute 0x%lx, 0x%lx, 0x%lx\n",
	   stemplate[0].pValue, stemplate[1].pValue, stemplate[2].pValue);

    buff2 = malloc(stemplate[1].ulValueLen * sizeof(unsigned char));
    buff3 = malloc(stemplate[2].ulValueLen * sizeof(unsigned char));
    buff4 = malloc(stemplate[3].ulValueLen * sizeof(CK_BYTE));

    CK_ATTRIBUTE sbtemplate[] = {
      {CKA_CLASS, &class, sizeof(class)}
      ,
      {CKA_LABEL, buff2, (stemplate[1].ulValueLen - 2)}
      ,
      {CKA_ID, buff3, stemplate[2].ulValueLen}
      ,
      {CKA_VALUE, buff4, stemplate[3].ulValueLen}
      ,
    };

    ret = p11->C_GetAttributeValue(session, objlist[j], sbtemplate, 3);

    printf("C_GetAttribute ret %d, CLASS is %d\n", ret, class);
    printf("C_GetAttribute ret %d, LABEL len :%d \n", ret,
	   stemplate[1].ulValueLen);
    for (i = 0; i < stemplate[1].ulValueLen; i++) {
      printf("%c", (unsigned char)buff2[i]);
      //printf(":");
    }
    printf("\n");
    /*
       printf("C_GetAttribute ret %d, size of VALUE: %d ID is : ", ret, (sbtemplate[3].ulValueLen));
       for (i=0; i< stemplate[3].ulValueLen; i++){
       printf("%x", buff4[i]);
       }
     */
    printf("\n");
    free(buff2);
    free(buff3);
    free(buff4);
  }

  CK_SESSION_INFO session_info;
  ret = p11->C_GetSessionInfo(session, &session_info);
  printf("C_GetSessionInfo ret %d, slot: %d\n", ret, session_info.slotID);
  printf("C_GetSessionInfo ret %d, state: %d\n", ret, session_info.state);

  //printf("C_GetAttribute ret %d, size of ID: %d ID is %x\n", ret, (sbtemplate[2].ulValueLen), sbtemplate[2].pValue);
  ret = p11->C_GenerateRandom(session, buff, 32);
  printf("C_GenerateRandom ret %d\n", ret);
/*
  printf("C_GenerateRandom: ", ret);
  for (i=0; i< 32; i++){
      printf("0x%x ", buff[i]);
  }
*/
/*
  int i = 0;
  unsigned long len = 5;
  printf("C_GenerateRandom END\n");
  CK_SESSION_HANDLE session2[30];
  for(i = 0; i< 30; i++){
      ret = p11->C_OpenSession(0, CKF_SERIAL_SESSION,
                NULL, NULL, &session2[i]);
      printf("C_OpenSession ret %d %d\n", ret, session2[i]);

      ret = p11->C_Login(session2[i], CKU_USER, "1234", 4);
      printf("C_Login ret %d\n", ret);

  }
*/
  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL, 0
  };

  unsigned char tosign[] = "test";
  unsigned long signed_len = 2;
  unsigned char *signed_data;
  unsigned char signed_data2[4] = { 0 };

  ret = p11->C_DecryptInit(session, &mech, objlist[2]);
  printf("C_DecryptInit ret %x\n", ret);

  ret = p11->C_SignInit(session, &mech, objlist[2]);
  printf("C_SignInit ret %x\n", ret);

  /* WRONG BEHAVIOR BELOW, */
  ret = p11->C_Sign(session, tosign, 4, NULL, &signed_len);
  printf
      ("C_Sign called with NULL, should return CKR_OK and len ret %x, needed len:%d\n",
       ret, signed_len);
  //signed_len = 2;
  signed_data = malloc(signed_len * sizeof(unsigned char));

  // Calling C_SignInit before fecthing
  ret = p11->C_SignInit(session, &mech, objlist[2]);
  printf("C_SignInit (bad) ret %x\n", ret);

  ret = p11->C_Sign(session, tosign, 4, signed_data, &signed_len);
  printf("C_Sign ret %x, needed len:%d\n", ret, signed_len);

  signed_data = malloc(signed_len * sizeof(unsigned char));

  ret = p11->C_Sign(session, tosign, 4, signed_data, &signed_len);
  printf("C_Sign ret %x, needed len:%d\n", ret, signed_len);

  ret = p11->C_SeedRandom(session, buff, 10);
  printf("C_SeedRandom ret %d\n", ret);

  ret = p11->C_CloseSession(session);
  printf("C_CloseSession ret %d\n", ret);

  ret = p11->C_CloseAllSessions(session_info.slotID);
  printf("C_CloseAllSessions ret %d\n", ret);

  ret = p11->C_Finalize(NULL);
  printf("C_Fini ret %d\n", ret);

  return 0;
}
