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
    File:    src/bindings-pkcs11/pkcs11_functions.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
#define LITTLE_ENDIAN_64 1
#define LITTLE_ENDIAN_32 2
#define BIG_ENDIAN_64 3
#define BIG_ENDIAN_32 4
#define UNSUPPORTED_ARCHITECTURE 5

CK_RV ML_CK_C_Daemonize(unsigned char *param, unsigned long param_len);
CK_RV ML_CK_C_SetupArch( /*in */ unsigned long client_arch);
CK_RV ML_CK_C_LoadModule( /*in */ const char *libname);
CK_RV ML_CK_C_Initialize(void);
CK_RV ML_CK_C_Finalize(void);
CK_RV ML_CK_C_GetInfo( /*in */ CK_INFO_PTR info);
CK_RV ML_CK_C_WaitForSlotEvent( /*in */ CK_FLAGS flags,	/* out */
			       CK_SLOT_ID * pSlot);
CK_RV ML_CK_C_GetSlotList( /*in */ unsigned int token_present,	/*out */
			  CK_SLOT_ID * slot_list,	/*in */
			  unsigned long count,	/*out */
			  unsigned long *real_count);
CK_RV ML_CK_C_GetSlotInfo( /*in */ CK_SLOT_ID slot_id,	/*out */
			  CK_SLOT_INFO * info);
CK_RV ML_CK_C_GetTokenInfo( /*in */ CK_SLOT_ID slot_id,	/*out */
			   CK_TOKEN_INFO * info);
CK_RV ML_CK_C_OpenSession( /*in */ CK_SLOT_ID slot_id,	/*in */
			  CK_FLAGS flags,	/*out */
			  CK_SESSION_HANDLE * session);
CK_RV ML_CK_C_CloseSession( /*in */ CK_SESSION_HANDLE session);
CK_RV ML_CK_C_CloseAllSessions( /*in */ CK_SLOT_ID slot_id);
CK_RV ML_CK_C_GetSessionInfo( /*in */ CK_SESSION_HANDLE session,	/*out */
			     CK_SESSION_INFO * session_info);
CK_RV ML_CK_C_Login( /*in */ CK_SESSION_HANDLE session,	/*in */
		    CK_USER_TYPE user_type, /*in */ unsigned char *pin,
		    /*in */ unsigned long pin_len);
CK_RV ML_CK_C_Logout( /*in */ CK_SESSION_HANDLE session);
CK_RV ML_CK_C_GetMechanismList( /*in */ CK_SLOT_ID slot_id,	/*out */
			       CK_MECHANISM_TYPE * mechanism_list,	/*in */
			       unsigned long count,	/*out */
			       unsigned long *real_count);
CK_RV ML_CK_C_GetMechanismInfo( /*in */ CK_SLOT_ID slot_id,	/*in */
			       CK_MECHANISM_TYPE mechanism,	/*out */
			       CK_MECHANISM_INFO * mechanism_info);
CK_RV ML_CK_C_InitToken( /*in */ CK_SLOT_ID slot_id,	/*in */
			unsigned char *pin, /*in */ unsigned long pin_len,
			/*in */ unsigned char *label);
CK_RV ML_CK_C_InitPIN( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *pin, /*in */ unsigned long pin_len);
CK_RV ML_CK_C_SetPIN( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *old_pin,	/*in */
		     unsigned long old_pin_len,	/*in */
		     unsigned char *new_pin,	/*in */
		     unsigned long new_pin_len);
CK_RV ML_CK_C_SeedRandom( /*in */ CK_SESSION_HANDLE session,	/*in */
			 unsigned char *seed,	/*in */
			 unsigned long seed_len);
CK_RV ML_CK_C_GenerateRandom( /*in */ CK_SESSION_HANDLE session,	/*out */
			     unsigned char *rand,	/*in */
			     unsigned long rand_len);
CK_RV ML_CK_C_FindObjectsInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_ATTRIBUTE * templ,	/*in */
			      unsigned long count);
CK_RV ML_CK_C_FindObjects( /*in */ CK_SESSION_HANDLE session,	/*out */
			  CK_OBJECT_HANDLE * object,	/*in */
			  unsigned long max_object_count,	/*out */
			  unsigned long *object_count);
CK_RV ML_CK_C_FindObjectsFinal( /*in */ CK_SESSION_HANDLE session);
CK_RV ML_CK_C_GenerateKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism,	/*in */
			  CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			  /*out */ CK_OBJECT_HANDLE * phkey);
CK_RV ML_CK_C_GenerateKeyPair( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_MECHANISM mechanism,	/*in */
			      CK_ATTRIBUTE * pub_templ,	/*in */
			      unsigned long pub_count,	/*in */
			      CK_ATTRIBUTE * priv_templ,	/*in */
			      unsigned long priv_count,	/*out */
			      CK_OBJECT_HANDLE * phpubkey,	/*out */
			      CK_OBJECT_HANDLE * phprivkey);
CK_RV ML_CK_C_CreateObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			   CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			   /*out */ CK_OBJECT_HANDLE * phobject);
CK_RV ML_CK_C_CopyObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_OBJECT_HANDLE hobject,	/*in */
			 CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			 /*out */ CK_OBJECT_HANDLE * phnewobject);
CK_RV ML_CK_C_DestroyObject( /*in */ CK_SESSION_HANDLE session,	/*in */
			    CK_OBJECT_HANDLE phobject);
CK_RV ML_CK_C_GetAttributeValue( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_OBJECT_HANDLE phobject,	/*in,out */
				CK_ATTRIBUTE * templ,	/*in */
				unsigned long count);
CK_RV ML_CK_C_SetAttributeValue( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_OBJECT_HANDLE phobject,	/*in */
				CK_ATTRIBUTE * templ,	/*in */
				unsigned long count);
CK_RV ML_CK_C_GetObjectSize( /*in */ CK_SESSION_HANDLE session,	/*in */
			    CK_OBJECT_HANDLE phobject,	/*out */
			    unsigned long *object_size);
CK_RV ML_CK_C_WrapKey( /*in */ CK_SESSION_HANDLE session,	/*in */
		      CK_MECHANISM mechanism,	/*in */
		      CK_OBJECT_HANDLE hwrappingkey,	/*in */
		      CK_OBJECT_HANDLE hkey,	/*out */
		      unsigned char *wrapped_key,	/*in */
		      unsigned long *wrapped_key_len);
CK_RV ML_CK_C_UnwrapKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_MECHANISM mechanism,	/*in */
			CK_OBJECT_HANDLE hunwrappingkey,	/*in */
			unsigned char *wrapped_key,	/*in */
			unsigned long wrapped_key_len,	/*in */
			CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			/*out */ CK_OBJECT_HANDLE * phunwrappedkey);
CK_RV ML_CK_C_DeriveKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_MECHANISM mechanism,	/*in */
			CK_OBJECT_HANDLE hbasekey,	/*in */
			CK_ATTRIBUTE * templ, /*in */ unsigned long count,
			/*out */ CK_OBJECT_HANDLE * phkey);
CK_RV ML_CK_C_DigestInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_MECHANISM mechanism);
CK_RV ML_CK_C_Digest( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *data, /*in */ unsigned long data_len,
		     /*out */ unsigned char *digest,
		     /*in */
		     unsigned long *digest_len);
CK_RV ML_CK_C_DigestUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char *data,	/*in */
			   unsigned long data_len);
CK_RV ML_CK_C_DigestKey( /*in */ CK_SESSION_HANDLE session,	/*in */
			CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_DigestFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			  unsigned char *digest,	/*in */
			  unsigned long *digest_len);
CK_RV ML_CK_C_SignInit( /*in */ CK_SESSION_HANDLE session,	/*in */
		       CK_MECHANISM mechanism,	/*in */
		       CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_SignRecoverInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			      CK_MECHANISM mechanism,	/*in */
			      CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_Sign( /*in */ CK_SESSION_HANDLE session,	/*in */
		   unsigned char *data, /*in */ unsigned long data_len,
		   /*out */ unsigned char *signature,
		   /*in */
		   unsigned long *signed_len);
CK_RV ML_CK_C_SignRecover( /*in */ CK_SESSION_HANDLE session,	/*in */
			  unsigned char *data,	/*in */
			  unsigned long data_len,	/*out */
			  unsigned char *signature,	/*in */
			  unsigned long *signed_len);
CK_RV ML_CK_C_SignUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			 unsigned char *data,	/*in */
			 unsigned long data_len);
CK_RV ML_CK_C_SignFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			unsigned char *signature,	/*in */
			unsigned long *signed_len);
CK_RV ML_CK_C_VerifyInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			 CK_MECHANISM mechanism,	/*in */
			 CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_VerifyRecoverInit( /*in */ CK_SESSION_HANDLE session,	/*in */
				CK_MECHANISM mechanism,	/*in */
				CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_Verify( /*in */ CK_SESSION_HANDLE session,	/*in */
		     unsigned char *data, /*in */ unsigned long data_len,
		     /*in */ unsigned char *signature,
		     /*in */
		     unsigned long signed_len);
CK_RV ML_CK_C_VerifyRecover( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *signature,	/*in */
			    unsigned long signature_len,	/*out */
			    unsigned char **data,	/*in */
			    unsigned long *data_len);
CK_RV ML_CK_C_VerifyUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char *data,	/*in */
			   unsigned long data_len);
CK_RV ML_CK_C_VerifyFinal( /*in */ CK_SESSION_HANDLE session,	/*in */
			  unsigned char *signature,	/*in */
			  unsigned long signed_len);
CK_RV ML_CK_C_EncryptInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism,	/*in */
			  CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_Encrypt( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *data, /*in */ unsigned long data_len,
		      /*out */ unsigned char **encrypted,
		      /*in */
		      unsigned long *encrypted_len);
CK_RV ML_CK_C_EncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *data,	/*in */
			    unsigned long data_len,	/*in */
			    unsigned char **encrypted,	/*in */
			    unsigned long *encrypted_len);
CK_RV ML_CK_C_DigestEncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *data,	/*in */
				  unsigned long data_len,	/*in */
				  unsigned char **encrypted,	/*in */
				  unsigned long *encrypted_len);
CK_RV ML_CK_C_SignEncryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				unsigned char *data,	/*in */
				unsigned long data_len,	/*in */
				unsigned char **encrypted,	/*in */
				unsigned long *encrypted_len);
CK_RV ML_CK_C_EncryptFinal( /*in */ CK_SESSION_HANDLE session,	/*in */
			   unsigned char **encrypted,	/*in */
			   unsigned long *encrypted_len);
CK_RV ML_CK_C_DecryptInit( /*in */ CK_SESSION_HANDLE session,	/*in */
			  CK_MECHANISM mechanism,	/*in */
			  CK_OBJECT_HANDLE hkey);
CK_RV ML_CK_C_Decrypt( /*in */ CK_SESSION_HANDLE session,	/*in */
		      unsigned char *encrypted,	/*in */
		      unsigned long encrypted_len,	/*out */
		      unsigned char **decrypted,	/*in */
		      unsigned long *decrypted_len);
CK_RV ML_CK_C_DecryptUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
			    unsigned char *encrypted,	/*in */
			    unsigned long encrypted_len,	/*out */
			    unsigned char **decrypted,	/*in */
			    unsigned long *decrypted_len);
CK_RV ML_CK_C_DecryptFinal( /*in */ CK_SESSION_HANDLE session,	/*out */
			   unsigned char **decrypted,	/*in */
			   unsigned long *decrypted_len);
CK_RV ML_CK_C_DecryptDigestUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *encrypted,	/*in */
				  unsigned long encrypted_len,	/*out */
				  unsigned char **decrypted,	/*in */
				  unsigned long *decrypted_len);
CK_RV ML_CK_C_DecryptVerifyUpdate( /*in */ CK_SESSION_HANDLE session,	/*in */
				  unsigned char *encrypted,	/*in */
				  unsigned long encrypted_len,	/*out */
				  unsigned char **decrypted,	/*in */
				  unsigned long *decrypted_len);
CK_RV ML_CK_C_GetFunctionStatus( /*in */ CK_SESSION_HANDLE session);
CK_RV ML_CK_C_CancelFunction( /*in */ CK_SESSION_HANDLE session);
CK_RV ML_CK_C_GetOperationState( /*in */ CK_SESSION_HANDLE session,	/*out */
				unsigned char **data,	/*in */
				unsigned long *data_len);
CK_RV ML_CK_C_SetOperationState( /*in */ CK_SESSION_HANDLE session,	/*in */
				unsigned char *data,	/*in */
				unsigned long data_len,	/*in */
				CK_OBJECT_HANDLE hencryptionkey,	/*in */
				CK_OBJECT_HANDLE hauthenticationkey);
