/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI (2013-2015)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr],
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]
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
    File:    src/client-lib/modwrap.c

-------------------------- MIT License HEADER ----------------------------------*/
/* bindings include                                      */
/* We only redefine the custom allocs if we are building */
/* the C client (in the case of the OCaml client, we use */
/* the bindings).                                        */
#ifdef CRPC
#define CUSTOM_ALLOC
#endif
#include "modwrap.h"

#define MODNAME "caml-crush: "

/* Wrap around pthread for Windows as we do not want
 * the pthread dependency on this platform */
#ifdef WIN32
void pthread_mutex_init(LPCRITICAL_SECTION mymutex, void *useless){
  InitializeCriticalSection(mymutex);
  return;
}
void pthread_mutex_lock(LPCRITICAL_SECTION mymutex){
  EnterCriticalSection(mymutex);
  return;
}
void pthread_mutex_unlock(LPCRITICAL_SECTION mymutex){
  LeaveCriticalSection(mymutex);
  return;
}
void pthread_mutex_destroy(LPCRITICAL_SECTION mymutex){
  DeleteCriticalSection(mymutex);
  return;
}
#endif

/* -------------------------------- */
/*      Linked list functions       */

/* Add an element in the linked list */
p11_request_struct *add_element_to_list(ck_session_handle_t session,
					unsigned long operation_type,
					unsigned char *in, unsigned long in_len,
					unsigned char *out,
					unsigned long out_len)
{
  p11_request_struct *node, *newnode;
#ifndef CAMLRPC
  pthread_mutex_lock(&linkedlist_mutex);
#endif
  newnode = (p11_request_struct *) custom_malloc(sizeof(p11_request_struct));

  if (request_data == NULL) {
    request_data = newnode;
  } else {
    node = request_data;
    node->next = newnode;
  }
  newnode->session = session;
  newnode->operation_type = operation_type;
  newnode->in = in;
  newnode->in_len = in_len;
  newnode->out = out;
  newnode->out_len = out_len;

  newnode->next = NULL;

#ifndef CAMLRPC
  pthread_mutex_unlock(&linkedlist_mutex);
#endif

  return newnode;
}

/* Remove a node from the linked list */
int
remove_elements_from_filtering_list(ck_session_handle_t session,
				    unsigned long operation_type,
				    unsigned char *in, unsigned long in_len)
{
  p11_request_struct *node, *prevnode;
  unsigned int tremove = 0;
  node = request_data;
  prevnode = NULL;

#ifndef CAMLRPC
  pthread_mutex_lock(&linkedlist_mutex);
#endif

  while (node != NULL) {
    tremove = 0;
    if (node->session == session) {
      tremove++;
    }
    if (node->operation_type == operation_type) {
      tremove++;
    }
    if (node->in == in) {
      tremove++;
    }
    if (node->in_len == in_len) {
      tremove++;
    }
    if (tremove == 4) {
      /* Head case */
      if (prevnode == NULL) {
	request_data = node->next;
	/* Let's free our local output buffer if allocated */
	if (node->out != NULL) {
	  custom_free((void **)(&node->out));
	}
	custom_free((void **)(&node));
	node = request_data;
      }
      /* Non-head case */
      else {
	prevnode->next = node->next;
	/* Let's free our local output buffer if allocated */
	if (node->out != NULL) {
	  custom_free((void **)(&node->out));
	}
	custom_free((void **)(&node));
	node = prevnode->next;
      }
    } else {
      prevnode = node;
      node = node->next;
    }
  }
#ifndef CAMLRPC
  pthread_mutex_unlock(&linkedlist_mutex);
#endif

  return 0;
}

/* Remove a node from the linked list */
int remove_all_elements_from_filtering_list()
{
  p11_request_struct *node, *currnode;
  node = request_data;

#ifndef CAMLRPC
  pthread_mutex_lock(&linkedlist_mutex);
#endif

  while (node != NULL) {
    /* Let's free our local output buffer if allocated */
    currnode = node->next;
    if (node->out != NULL) {
      custom_free((void **)(&node->out));
    }
    custom_free((void **)(&node));
    node = currnode;
  }
#ifndef CAMLRPC
  pthread_mutex_unlock(&linkedlist_mutex);
#endif

  return 0;
}

/* Check if a node is inside the linked list according to matching criteria */
p11_request_struct *check_element_in_filtering_list(ck_session_handle_t session,
						    unsigned long
						    operation_type,
						    unsigned char *in,
						    unsigned long in_len)
{
  p11_request_struct *node;
  unsigned long found = 0;
  node = request_data;

#ifndef CAMLRPC
  pthread_mutex_lock(&linkedlist_mutex);
#endif

  while (node != NULL) {
    found = 0;
    if (node->session == session) {
      found++;
    }
    if (node->operation_type == operation_type) {
      found++;
    }
    if (node->in == in) {
      found++;
    }
    if (node->in_len == in_len) {
      found++;
    }
    if (found == 4) {
#ifndef CAMLRPC
      pthread_mutex_unlock(&linkedlist_mutex);
#endif
      return node;
    }
    node = node->next;
  }
#ifndef CAMLRPC
  pthread_mutex_unlock(&linkedlist_mutex);
#endif

  return NULL;
}

/* Check if a node is inside the linked list according to session/op type,
 * this is needed to check if a result was given and the client has not
 * yet fetched it.
*/
p11_request_struct *check_operation_active_in_filtering_list(ck_session_handle_t
							     session,
							     unsigned long
							     operation_type)
{
  p11_request_struct *node;
  unsigned long found = 0;
  node = request_data;

#ifndef CAMLRPC
  pthread_mutex_lock(&linkedlist_mutex);
#endif

  while (node != NULL) {
    found = 0;
    if (node->session == session) {
      found++;
    }
    if (node->operation_type == operation_type) {
      found++;
    }
    if (found == 2) {
#ifndef CAMLRPC
      pthread_mutex_unlock(&linkedlist_mutex);
#endif
      return node;
    }
    node = node->next;
  }
#ifndef CAMLRPC
  pthread_mutex_unlock(&linkedlist_mutex);
#endif

  return NULL;
}

/* -------------------------------- */
/*   Common sanitization function   */

void custom_sanitize_ck_mechanism(struct ck_mechanism *mech)
{
  /* FIXME: We only sanitize the most commonly used mechanisms.
   * This should also be done for other mechs that do not require params.
   */
  switch ((*mech).mechanism) {
  case CKM_RSA_PKCS:
  case CKM_RSA_9796:
  case CKM_RSA_X_509:
  case CKM_MD2_RSA_PKCS:
  case CKM_MD5_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS:
  case CKM_RIPEMD128_RSA_PKCS:
  case CKM_RIPEMD160_RSA_PKCS:
  case CKM_RSA_X9_31:
  case CKM_SHA1_RSA_X9_31:
  case CKM_DSA:
  case CKM_DSA_SHA1:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS:
    {
      (*mech).parameter = NULL;
      (*mech).parameter_len = 0;
    }
    /* Fallthrough */
  default:
    {
      if ((*mech).parameter_len > MAX_BUFF_LEN) {
#ifdef DEBUG
	fprintf(stderr,
		MODNAME"Detected garbage mech_params passing NULL,0 instead\n");
#endif
	(*mech).parameter_len = 0;
	(*mech).parameter = NULL;
      }
    }
  }
}

/* Functions when LIBNAME is read from a file */
#ifdef LIBNAME_FILE
/* Portable getline() function */
size_t mygetline(char *lineptr, FILE *stream) {
  char *p = lineptr;
  int c;

  if (lineptr == NULL) {
    fprintf(stderr, MODNAME"mygetline: lineptr is NULL\n");
    return -1;
  }
  if (stream == NULL) {
    fprintf(stderr, MODNAME"mygetline: stream is NULL\n");
    return -1;
  }
  c = fgetc(stream);
  if (c == EOF) {
    return -1;
  }
  while(c != EOF) {
    if ((p - lineptr) > (MAX_LIBNAME_LEN - 1)) {
      fprintf(stderr, MODNAME"mygetline: line is > to %d\n", MAX_LIBNAME_LEN);
      return -2;
    }
    *p++ = c;
    c = fgetc(stream);
    if (c == '\n') {
      break;
    }
  }
  *p++ = '\0';
  return p - lineptr - 1;
}

/* Function that returns the parsed LIBNAME from a file
 * the file is located in $HOME/.camlcrushlibname, caller has
 * to free the passed libname parameter.
 */
int get_libname_from_file(char *libname){
    int   count;
    char *home;
    size_t home_len = 0;
    char *file_path;
    size_t file_path_len = 0;
    FILE *file;

    home = getenv("HOME");
    if(!home){
        fprintf(stderr, MODNAME"get_libname_from_file: HOME variable not found\n");
        return -1;
    }
    home_len = strnlen(home, MAX_ENV_LEN);

	file_path_len = home_len + strlen(LIBNAME_FILE_NAME) + 2;
    file_path = custom_malloc(file_path_len);
    if(!file_path){
        fprintf(stderr, MODNAME"get_libname_from_file: malloc failed\n");
        return -1;
    }
	memset(file_path, 0, file_path_len);

    strncat(file_path, home, home_len);
    strncat(file_path+home_len, "/", 1);
    strncat(file_path+home_len+1, LIBNAME_FILE_NAME, strlen(LIBNAME_FILE_NAME));

    file = fopen(file_path, "r");
    if(!file){
        fprintf(stderr,
				MODNAME"get_libname_from_file: open failed for file %s\n",file_path);
        return -1;
    }

    count = mygetline(libname, file);
    if(count < 0){
        fprintf(stderr, MODNAME"get_libname_from_file: LIBNAME could not be read\n");
        return -1;
    }
    fclose(file);
    custom_free((void**)&file_path);
    return 0;
}
#endif /* LIBNAME_FILE */

/* Keep the pid of current process */
#ifndef WIN32
static pid_t local_pid = 0;
#endif

static ck_rv_t init_rv;

/* Init function is called when loading library */
#ifndef WIN32
__attribute__ ((constructor))
#endif
void init()
{
  ck_rv_t ret;
  /* libname override through environment variable */
  char *libname;
#ifdef LIBNAME_FILE
  char libname_file[32] = {0};
#endif

  init_rv = CKR_OK;
  /* Store the PID to match it in case of a fork */
#ifndef WIN32
  local_pid = getpid();
#endif

  /* Initialize global variables */
  pthread_mutex_init(&mutex, NULL);
#ifndef CAMLRPC
  pthread_mutex_init(&linkedlist_mutex, NULL);
#endif
  is_Blocking = 0;
  request_data = NULL;

  /* Initialize architecture detection */
  peer_arch = 0;
  my_arch = 0;

  /* try to find user-defined libname alias */
  libname = getenv(ENV_LIBNAME);

  if(libname != NULL){
    /* Use environment variable for libname alias */
#ifdef CAMLRPC
    ret = init_ml(libname);
#else
    ret = init_c(libname);
#endif
  }
  else{
#ifdef LIBNAME_FILE
    /* Find the LIBNAME in a file */
	if(get_libname_from_file(libname_file) != 0){
		fprintf(stderr, MODNAME"Init failed, could not find a LIBNAME\n");
		init_rv = CKR_DEVICE_ERROR;
		goto fail;
	}
#ifdef CAMLRPC
    ret = init_ml(libname_file);
#else
    ret = init_c(libname_file);
#endif
#else
    /* Use the default built-in libname */
#ifdef CAMLRPC
    ret = init_ml(xstr(LIBNAME));
#else
    ret = init_c(xstr(LIBNAME));
#endif
#endif /* LIBNAME_FILE */
  }

  /* Did we manage to detect arch ? */
  if ((peer_arch == 0 || peer_arch == 5) || (my_arch == 0 || my_arch == 5)) {
    fprintf(stderr, MODNAME"C_SetupArch: failed detecting architecture\n");
    init_rv = CKR_DEVICE_ERROR;
    goto fail;
  }

  if (ret != CKR_OK) {
	if(libname != NULL){
      fprintf(stderr,
		MODNAME"C_LoadModule: failed loading PKCS#11 module %s (read from env)\n",
		libname);
	}
	else{
#ifdef LIBNAME_FILE
    fprintf(stderr,
	    MODNAME"C_LoadModule: failed loading PKCS#11 module %s (read from file)\n",
	    libname_file);
#else
    fprintf(stderr, MODNAME"C_LoadModule: failed loading PKCS#11 module %s (builtin)\n",
	    xstr(LIBNAME));
#endif
	}
    fprintf(stderr, MODNAME"Init failed\n");
    init_rv = CKR_DEVICE_ERROR;
    goto fail;
  }
  return;

fail:
  pthread_mutex_destroy(&mutex);
#ifndef CAMLRPC
  pthread_mutex_destroy(&linkedlist_mutex);
#endif
}

/* Disconnect all stuff */
#ifndef WIN32
__attribute__ ((destructor))
#endif
void destroy()
{
#ifdef CAMLRPC
  destroy_ml();
#else
  destroy_c();
#endif
  /* destroy all remaining elements in linked list */
  remove_all_elements_from_filtering_list();
  return;
}

/* Windows initialization */
#ifdef WIN32
BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle, IN DWORD nReason, IN LPVOID Reserved){
 BOOLEAN bSuccess = TRUE;
 switch(nReason){
  case DLL_PROCESS_ATTACH:
       init();
       break;
 case DLL_PROCESS_DETACH:
       destroy();
       break;

 }
 return bSuccess;
}
#endif

/* -------------------------------- */
/*   Trampoline PKCS#11 functions   */

struct ck_function_list function_list = {
  {2, 20},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent
};

ck_rv_t C_Initialize(void *init_args)
{
  ck_rv_t ret;
  check_pid;
  if (init_rv != CKR_OK)
    return init_rv;

  pthread_mutex_lock(&mutex);

#ifdef CAMLRPC
  ret = myC_Initialize(init_args);
#else
  ret = myC_Initialize_C(init_args);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_Finalize(void *init_args)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Finalize(init_args);
#else
  ret = myC_Finalize_C(init_args);
#endif
  if (ret == CKR_OK) {
    /* If some thread are blocking, signal them that we've finalized */
    if (is_Blocking == 1) {
      is_Blocking = 2;
    }
  }
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetSlotList(CK_BBOOL input0, ck_slot_id_t * output2, unsigned long *output3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetSlotList(input0, output2, output3);
#else
  ret = myC_GetSlotList_C(input0, output2, output3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_GetInfo(struct ck_info * output0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetInfo(output0);
#else
  ret = myC_GetInfo_C(output0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_WaitForSlotEvent(ck_flags_t input0, ck_slot_id_t * output1, void *reserved)
{
  ck_rv_t ret;

  check_pid;
  if (input0 == CKF_DONT_BLOCK) {
#ifdef DEBUG
    fprintf(stderr, MODNAME"\nC_WaitForSlotEvent called with non block\n");
#endif
    pthread_mutex_lock(&mutex);
#ifdef CAMLRPC
    ret = myC_WaitForSlotEvent(input0, output1, reserved);
#else
    ret = myC_WaitForSlotEvent_C(input0, output1, reserved);
#endif
    pthread_mutex_unlock(&mutex);
    return ret;
  } else {
#ifdef DEBUG
    fprintf(stderr, MODNAME"\nC_WaitForSlotEvent called with block, return\n");
#endif
    while (1) {
      /* FIXME: usleep migth be deprecated in favor of nanosleep */
#ifdef WIN32
      Sleep(100);
#else
      usleep(50000);
#endif
      pthread_mutex_lock(&mutex);
      /* Did we C_Finalize? */
      if (is_Blocking == 2) {
	pthread_mutex_unlock(&mutex);
#ifdef DEBUG
	printf
	    ("\nC_WaitForSlotEvent RETURN because someone called C_Finalize\n");
#endif
	return CKR_CRYPTOKI_NOT_INITIALIZED;
      }
#ifdef CAMLRPC
      ret = myC_WaitForSlotEvent(CKF_DONT_BLOCK, output1, reserved);
#else
      ret = myC_WaitForSlotEvent_C(CKF_DONT_BLOCK, output1, reserved);
#endif
      /* No event, we'll block some more */
      if (ret == CKR_NO_EVENT) {
	is_Blocking = 1;
#ifdef DEBUG
	fprintf(stderr, MODNAME"\nC_WaitForSlotEvent NO EVENT, keep BLOCKING\n");
#endif
      }
      /* Got an event, we'll return */
      else {
	is_Blocking = 0;
#ifdef DEBUG
	fprintf(stderr, MODNAME"\nC_WaitForSlotEvent GOT EVENT\n");
#endif
      }
      pthread_mutex_unlock(&mutex);
      if (ret != CKR_NO_EVENT) {
	return ret;
      }
    }
  }
}

ck_rv_t C_GetSlotInfo(ck_slot_id_t input0, struct ck_slot_info * output1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetSlotInfo(input0, output1);
#else
  ret = myC_GetSlotInfo_C(input0, output1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_GetTokenInfo(ck_slot_id_t input0, struct ck_token_info * output1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetTokenInfo(input0, output1);
#else
  ret = myC_GetTokenInfo_C(input0, output1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_InitToken(ck_slot_id_t input0, unsigned char *input1,
	    unsigned long input1_len, unsigned char *input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_InitToken(input0, input1, input1_len, input2);
#else
  ret = myC_InitToken_C(input0, input1, input1_len, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_OpenSession(ck_slot_id_t input0, ck_flags_t input1, void *application,
	      ck_notify_t notify, ck_session_handle_t * output2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_OpenSession(input0, input1, application, notify, output2);
#else
  ret = myC_OpenSession_C(input0, input1, application, notify, output2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_CloseSession(ck_session_handle_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_CloseSession(input0);
#else
  ret = myC_CloseSession_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_CloseAllSessions(ck_slot_id_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_CloseAllSessions(input0);
#else
  ret = myC_CloseAllSessions_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetSessionInfo(ck_session_handle_t input0, struct ck_session_info * output1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetSessionInfo(input0, output1);
#else
  ret = myC_GetSessionInfo_C(input0, output1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Login(ck_session_handle_t input0, ck_user_type_t input1,
	unsigned char *input2, unsigned long input2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Login(input0, input1, input2, input2_len);
#else
  ret = myC_Login_C(input0, input1, input2, input2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_Logout(ck_session_handle_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Logout(input0);
#else
  ret = myC_Logout_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetMechanismList(ck_slot_id_t input0, ck_mechanism_type_t * output2,
		   unsigned long *output3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetMechanismList(input0, output2, output3);
#else
  ret = myC_GetMechanismList_C(input0, output2, output3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetMechanismInfo(ck_slot_id_t input0, ck_mechanism_type_t input1,
		   struct ck_mechanism_info * output2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetMechanismInfo(input0, input1, output2);
#else
  ret = myC_GetMechanismInfo_C(input0, input1, output2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_InitPIN(ck_session_handle_t input0, unsigned char *input1,
	  unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_InitPIN(input0, input1, input1_len);
#else
  ret = myC_InitPIN_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SetPIN(ck_session_handle_t input0, unsigned char *input1,
	 unsigned long input1_len, unsigned char *input2,
	 unsigned long input2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SetPIN(input0, input1, input1_len, input2, input2_len);
#else
  ret = myC_SetPIN_C(input0, input1, input1_len, input2, input2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SeedRandom(ck_session_handle_t input0, unsigned char *input1,
	     unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SeedRandom(input0, input1, input1_len);
#else
  ret = myC_SeedRandom_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GenerateRandom(ck_session_handle_t input0, unsigned char *output2,
		 unsigned long output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GenerateRandom(input0, output2, output2_len);
#else
  ret = myC_GenerateRandom_C(input0, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetOperationState(ck_session_handle_t input0, unsigned char *output1,
		    unsigned long *output1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetOperationState(input0, output1, output1_len);
#else
  ret = myC_GetOperationState_C(input0, output1, output1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SetOperationState(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, ck_object_handle_t input2,
		    ck_object_handle_t input3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SetOperationState(input0, input1, input1_len, input2, input3);
#else
  ret = myC_SetOperationState_C(input0, input1, input1_len, input2, input3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_FindObjectsInit(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
		  unsigned long count)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_FindObjectsInit(input0, input1, count);
#else
  ret = myC_FindObjectsInit_C(input0, input1, count);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_FindObjects(ck_session_handle_t input0, ck_object_handle_t * output2,
	      unsigned long input1, unsigned long *output3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_FindObjects(input0, output2, input1, output3);
#else
  ret = myC_FindObjects_C(input0, output2, input1, output3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_FindObjectsFinal(ck_session_handle_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_FindObjectsFinal(input0);
#else
  ret = myC_FindObjectsFinal_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GenerateKey(ck_session_handle_t input0, struct ck_mechanism * input1,
	      CK_ATTRIBUTE * input2, unsigned long count,
	      ck_object_handle_t * output3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GenerateKey(input0, input1, input2, count, output3);
#else
  ret = myC_GenerateKey_C(input0, input1, input2, count, output3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GenerateKeyPair(ck_session_handle_t input0, struct ck_mechanism * input1,
		  CK_ATTRIBUTE * input2, unsigned long count,
		  CK_ATTRIBUTE * input3, unsigned long count2,
		  ck_object_handle_t * output4, ck_object_handle_t * output5)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret =
      myC_GenerateKeyPair(input0, input1, input2, count, input3, count2,
			  output4, output5);
#else
  ret =
      myC_GenerateKeyPair_C(input0, input1, input2, count, input3, count2,
			    output4, output5);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_CreateObject(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
	       unsigned long count, ck_object_handle_t * output2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_CreateObject(input0, input1, count, output2);
#else
  ret = myC_CreateObject_C(input0, input1, count, output2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_CopyObject(ck_session_handle_t input0, ck_object_handle_t input1,
	     CK_ATTRIBUTE * input2, unsigned long count,
	     ck_object_handle_t * output3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_CopyObject(input0, input1, input2, count, output3);
#else
  ret = myC_CopyObject_C(input0, input1, input2, count, output3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_DestroyObject(ck_session_handle_t input0, ck_object_handle_t input1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DestroyObject(input0, input1);
#else
  ret = myC_DestroyObject_C(input0, input1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetAttributeValue(ck_session_handle_t input0, ck_object_handle_t input1,
		    struct ck_attribute * input2, unsigned long input3)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetAttributeValue(input0, input1, input2, input3);
#else
  ret = myC_GetAttributeValue_C(input0, input1, input2, input3);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SetAttributeValue(ck_session_handle_t input0, ck_object_handle_t input1,
		    CK_ATTRIBUTE * input2, unsigned long count)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SetAttributeValue(input0, input1, input2, count);
#else
  ret = myC_SetAttributeValue_C(input0, input1, input2, count);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_GetObjectSize(ck_session_handle_t input0, ck_object_handle_t input1,
		unsigned long *output2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetObjectSize(input0, input1, output2);
#else
  ret = myC_GetObjectSize_C(input0, input1, output2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_WrapKey(ck_session_handle_t input0, struct ck_mechanism * input1,
	  ck_object_handle_t input2, ck_object_handle_t input3,
	  unsigned char *output4, unsigned long *output4_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_WrapKey(input0, input1, input2, input3, output4, output4_len);
#else
  ret = myC_WrapKey_C(input0, input1, input2, input3, output4, output4_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_UnwrapKey(ck_session_handle_t input0, struct ck_mechanism * input1,
	    ck_object_handle_t input2, unsigned char *input3,
	    unsigned long input3_len, CK_ATTRIBUTE * input4,
	    unsigned long count, ck_object_handle_t * output5)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret =
      myC_UnwrapKey(input0, input1, input2, input3, input3_len, input4, count,
		    output5);
#else
  ret =
      myC_UnwrapKey_C(input0, input1, input2, input3, input3_len, input4,
		      count, output5);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DeriveKey(ck_session_handle_t input0, struct ck_mechanism * input1,
	    ck_object_handle_t input2, CK_ATTRIBUTE * input3,
	    unsigned long count, ck_object_handle_t * output4)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DeriveKey(input0, input1, input2, input3, count, output4);
#else
  ret = myC_DeriveKey_C(input0, input1, input2, input3, count, output4);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_DigestInit(ck_session_handle_t input0, struct ck_mechanism * input1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DigestInit(input0, input1);
#else
  ret = myC_DigestInit_C(input0, input1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Digest(ck_session_handle_t input0, unsigned char *input1,
	 unsigned long input1_len, unsigned char *output2,
	 unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Digest(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_Digest_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DigestUpdate(ck_session_handle_t input0, unsigned char *input1,
	       unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DigestUpdate(input0, input1, input1_len);
#else
  ret = myC_DigestUpdate_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DigestFinal(ck_session_handle_t input0, unsigned char *output1,
	      unsigned long *output1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DigestFinal(input0, output1, output1_len);
#else
  ret = myC_DigestFinal_C(input0, output1, output1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_DigestKey(ck_session_handle_t input0, ck_object_handle_t input1)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DigestKey(input0, input1);
#else
  ret = myC_DigestKey_C(input0, input1);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignInit(ck_session_handle_t input0, struct ck_mechanism * input1,
	   ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignInit(input0, input1, input2);
#else
  ret = myC_SignInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Sign(ck_session_handle_t input0, unsigned char *input1,
       unsigned long input1_len, unsigned char *output2,
       unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Sign(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_Sign_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignUpdate(ck_session_handle_t input0, unsigned char *input1,
	     unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignUpdate(input0, input1, input1_len);
#else
  ret = myC_SignUpdate_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignFinal(ck_session_handle_t input0, unsigned char *output1,
	    unsigned long *output1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignFinal(input0, output1, output1_len);
#else
  ret = myC_SignFinal_C(input0, output1, output1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignRecoverInit(ck_session_handle_t input0, struct ck_mechanism * input1,
		  ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignRecoverInit(input0, input1, input2);
#else
  ret = myC_SignRecoverInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignRecover(ck_session_handle_t input0, unsigned char *input1,
	      unsigned long input1_len, unsigned char *output2,
	      unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignRecover(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_SignRecover_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_VerifyRecoverInit(ck_session_handle_t input0, struct ck_mechanism * input1,
		    ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_VerifyRecoverInit(input0, input1, input2);
#else
  ret = myC_VerifyRecoverInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_VerifyInit(ck_session_handle_t input0, struct ck_mechanism * input1,
	     ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_VerifyInit(input0, input1, input2);
#else
  ret = myC_VerifyInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Verify(ck_session_handle_t input0, unsigned char *input1,
	 unsigned long input1_len, unsigned char *input2,
	 unsigned long input2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Verify(input0, input1, input1_len, input2, input2_len);
#else
  ret = myC_Verify_C(input0, input1, input1_len, input2, input2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_VerifyUpdate(ck_session_handle_t input0, unsigned char *input1,
	       unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_VerifyUpdate(input0, input1, input1_len);
#else
  ret = myC_VerifyUpdate_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_VerifyFinal(ck_session_handle_t input0, unsigned char *input1,
	      unsigned long input1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_VerifyFinal(input0, input1, input1_len);
#else
  ret = myC_VerifyFinal_C(input0, input1, input1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_VerifyRecover(ck_session_handle_t input0, unsigned char *input1,
		unsigned long input1_len, unsigned char *output2,
		unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_VerifyRecover(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_VerifyRecover_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_EncryptInit(ck_session_handle_t input0, struct ck_mechanism * input1,
	      ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_EncryptInit(input0, input1, input2);
#else
  ret = myC_EncryptInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Encrypt(ck_session_handle_t input0, unsigned char *input1,
	  unsigned long input1_len, unsigned char *output2,
	  unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Encrypt(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_Encrypt_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_EncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		unsigned long input1_len, unsigned char *output2,
		unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_EncryptUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_EncryptUpdate_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_EncryptFinal(ck_session_handle_t input0, unsigned char *output1,
	       unsigned long *output1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_EncryptFinal(input0, output1, output1_len);
#else
  ret = myC_EncryptFinal_C(input0, output1, output1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DigestEncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret =
      myC_DigestEncryptUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret =
      myC_DigestEncryptUpdate_C(input0, input1, input1_len, output2,
				output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_SignEncryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_SignEncryptUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret =
      myC_SignEncryptUpdate_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DecryptInit(ck_session_handle_t input0, struct ck_mechanism * input1,
	      ck_object_handle_t input2)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DecryptInit(input0, input1, input2);
#else
  ret = myC_DecryptInit_C(input0, input1, input2);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_Decrypt(ck_session_handle_t input0, unsigned char *input1,
	  unsigned long input1_len, unsigned char *output2,
	  unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_Decrypt(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_Decrypt_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DecryptUpdate(ck_session_handle_t input0, unsigned char *input1,
		unsigned long input1_len, unsigned char *output2,
		unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DecryptUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret = myC_DecryptUpdate_C(input0, input1, input1_len, output2, output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DecryptFinal(ck_session_handle_t input0, unsigned char *output1,
	       unsigned long *output1_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_DecryptFinal(input0, output1, output1_len);
#else
  ret = myC_DecryptFinal_C(input0, output1, output1_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DecryptDigestUpdate(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret =
      myC_DecryptDigestUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret =
      myC_DecryptDigestUpdate_C(input0, input1, input1_len, output2,
				output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t
C_DecryptVerifyUpdate(ck_session_handle_t input0, unsigned char *input1,
		      unsigned long input1_len, unsigned char *output2,
		      unsigned long *output2_len)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret =
      myC_DecryptVerifyUpdate(input0, input1, input1_len, output2, output2_len);
#else
  ret =
      myC_DecryptVerifyUpdate_C(input0, input1, input1_len, output2,
				output2_len);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_GetFunctionStatus(ck_session_handle_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_GetFunctionStatus(input0);
#else
  ret = myC_GetFunctionStatus_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_CancelFunction(ck_session_handle_t input0)
{
  ck_rv_t ret;
  pthread_mutex_lock(&mutex);
  check_pid;
#ifdef CAMLRPC
  ret = myC_CancelFunction(input0);
#else
  ret = myC_CancelFunction_C(input0);
#endif
  pthread_mutex_unlock(&mutex);
  return ret;
}

ck_rv_t C_GetFunctionList(struct ck_function_list ** ppFunctionList)
{

  if (ppFunctionList == NULL) {
#ifdef DEBUG
    fprintf(stderr,
	    MODNAME"C_GetFunctionList: ppFunctionList must not be a NULL_PTR\n");
#endif
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, MODNAME"Got ppFunctionList = 0x%p\n", (void *)(&function_list));
#endif
  *ppFunctionList = &function_list;

  return CKR_OK;
}
