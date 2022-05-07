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

    The current source code is part of the tests 6] source tree.

    Project: PKCS#11 Filtering Proxy
    File:    src/tests/c-based/main-shared.c

-------------------------- MIT License HEADER ----------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <dlfcn.h>
#include "original_pkcs11.h"

/***** TODO : clean the code and make more tests ***/
/***** FIXME: the following code is ugly as is  ****/

int main(int argc, char **argv)
{
  int i = 0;
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
  printf("C_Initialize ret %d\n", ret);

  CK_ULONG p11t_slot_count = 0;
  CK_SLOT_ID_PTR pSlotList;
  ret = p11->C_GetSlotList(1, NULL, &p11t_slot_count);
  printf("C_GetSlotList token present: yes ret %d, slot count %d\n", ret,
         p11t_slot_count);
  if (ret != CKR_OK) {
    return 1;
  }
  if (p11t_slot_count < 1 ) {
    printf("No slot found, exiting\n");
    return 1;
  }


  pSlotList = (CK_SLOT_ID_PTR) malloc(p11t_slot_count*sizeof(CK_SLOT_ID));
  // Retrieve slot ID
  ret = p11->C_GetSlotList(1, pSlotList, &p11t_slot_count);
  printf("C_GetSlotList token present: yes ret %d, slot count %d\n", ret,
	 p11t_slot_count);


  CK_SESSION_HANDLE session;
  ret = p11->C_OpenSession(pSlotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
			   NULL, NULL, &session);
  printf("C_OpenSession ret %d session %d\n", ret, session);

  unsigned long classz = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &classz, 8},
  };

  ret = p11->C_Login(session, CKU_USER, "1234", 4);
  printf("C_Login ret %d\n", ret);

  ret = p11->C_FindObjectsInit(session, template, 1);
  
  unsigned long objcount = 0;
  int maxobjcount = 8;
  CK_OBJECT_HANDLE objlist[8];
  ret = p11->C_FindObjects(session, objlist, maxobjcount, &objcount);
  printf("C_FindObject ret %d, %d elem returned\n", ret, objcount);

  ret = p11->C_FindObjectsFinal(session);
  printf("C_FindObjectFinal ret %d\n", ret);

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL, 0
  };

  unsigned char tosign[] = "test";
  unsigned long signed_len = 0;
  unsigned char *signed_data;
  unsigned char signed_data2[4] = { 0 };

  for (i = 0; i < 4096; ++i){ 

    ret = p11->C_SignInit(session, &mech, objlist[0]);
    if (ret != CKR_OK) {
      printf("C_SignInit ret %x\n", ret);
      return 1;
    }
    ret = p11->C_Sign(session, tosign, 4, NULL, &signed_len);
    if (ret != CKR_OK) {
      printf("C_Sign ret %x, needed len:%d\n", ret, signed_len);
      return 1;
    }
    signed_data = malloc(signed_len * sizeof(unsigned char));

    ret = p11->C_Sign(session, tosign, 4, signed_data, &signed_len);
    if (ret != CKR_OK) {
      printf("C_Sign ret %x, needed len:%d\n", ret, signed_len);
      return 1;
    }

  }
  printf("Done signing\n");
  ret = p11->C_CloseSession(session);
  printf("C_CloseSession ret %d\n", ret);

  ret = p11->C_Finalize(NULL);
  printf("C_Finalize ret %d\n", ret);

  return 0;
}