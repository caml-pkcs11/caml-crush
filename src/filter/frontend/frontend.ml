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

    The current source code is part of the PKCS#11 filter 4] source tree:

           |                                             
 ----------------------                                  
| 4] PKCS#11 filter    |                                 
 ----------------------                                  
           |                                             

    Project: PKCS#11 Filtering Proxy
    File:    src/filter/frontend/frontend.ml

************************** CeCILL-B HEADER ***********************************)
open Printf

(********************************************************************************)
(*                       CUSTOM PURPOSE FUNCTIONS                               *)
(********************************************************************************)

let c_SetupArch = Filter.c_SetupArch

(********************************************************************************)
(*                      GENERAL PURPOSE FUNCTIONS                               *)
(********************************************************************************)

let c_LoadModule = Filter.c_LoadModule

let c_Initialize () = Filter.c_Initialize ()

let c_GetInfo () = Filter.c_GetInfo ()

(********************************************************************************)
(*                      SLOT AND TOKEN MANAGEMENT FUNCTIONS                     *)
(********************************************************************************)


let c_GetSlotList = Filter.c_GetSlotList

let c_GetSlotInfo = Filter.c_GetSlotInfo

let c_GetTokenInfo = Filter.c_GetTokenInfo

let c_WaitForSlotEvent = Filter.c_WaitForSlotEvent

let c_GetMechanismList = Filter.c_GetMechanismList

let c_GetMechanismInfo = Filter.c_GetMechanismInfo

let c_InitToken = Filter.c_InitToken

let c_InitPIN = Filter.c_InitPIN

let c_SetPIN = Filter.c_SetPIN


(********************************************************************************)
(*                      SESSION MANAGEMENT FUNCTIONS                            *)
(********************************************************************************)

let c_OpenSession = Filter.c_OpenSession

let c_CloseSession = Filter.c_CloseSession

let c_CloseAllSessions = Filter.c_CloseAllSessions

let c_GetSessionInfo = Filter.c_GetSessionInfo

let c_GetOperationState = Filter.c_GetOperationState

let c_SetOperationState = Filter.c_SetOperationState

let c_Login = Filter.c_Login

let c_Logout = Filter.c_Logout

(********************************************************************************)
(*                      OBJECT MANAGEMENT FUNCTIONS                            *)
(********************************************************************************)

let c_Finalize () = Filter.c_Finalize ()

let c_CreateObject = Filter.c_CreateObject

let c_CopyObject = Filter.c_CopyObject

let c_DestroyObject = Filter.c_DestroyObject

let c_GetObjectSize = Filter.c_GetObjectSize

let c_GetAttributeValue = Filter.c_GetAttributeValue

let c_SetAttributeValue = Filter.c_SetAttributeValue

let c_FindObjectsInit = Filter.c_FindObjectsInit

let c_FindObjects = Filter.c_FindObjects

let c_FindObjectsFinal = Filter.c_FindObjectsFinal


(********************************************************************************)
(*                      ENCRYPTION FUNCTIONS                                    *)
(********************************************************************************)

let c_EncryptInit = Filter.c_EncryptInit

let c_Encrypt = Filter.c_Encrypt

let c_EncryptUpdate = Filter.c_EncryptUpdate

let c_EncryptFinal = Filter.c_EncryptFinal


(********************************************************************************)
(*                      DECRYPTION FUNCTIONS                                    *)
(********************************************************************************)

let c_DecryptInit = Filter.c_DecryptInit

let c_Decrypt = Filter.c_Decrypt

let c_DecryptUpdate = Filter.c_DecryptUpdate

let c_DecryptFinal = Filter.c_DecryptFinal


(********************************************************************************)
(*                     MESSAGE DIGESTING FUNCTIONS                              *)
(********************************************************************************)

let c_DigestInit = Filter.c_DigestInit

let c_Digest = Filter.c_Digest

let c_DigestUpdate = Filter.c_DigestUpdate

let c_DigestKey = Filter.c_DigestKey

let c_DigestFinal = Filter.c_DigestFinal

(********************************************************************************)
(*                     SIGNING AND MAC SIGNING FUNCTIONS                        *)
(********************************************************************************)

let c_SignInit = Filter.c_SignInit

let c_SignRecoverInit = Filter.c_SignRecoverInit

let c_Sign = Filter.c_Sign

let c_SignRecover = Filter.c_SignRecover

let c_SignUpdate = Filter.c_SignUpdate

let c_SignFinal = Filter.c_SignFinal

(********************************************************************************)
(*                     FUNCTIONS FOR VERYFING SIGNATURES AND MAC                *)
(********************************************************************************)

let c_VerifyInit = Filter.c_VerifyInit

let c_VerifyRecoverInit = Filter.c_VerifyRecoverInit

let c_Verify = Filter.c_Verify

let c_VerifyRecover = Filter.c_VerifyRecover

let c_VerifyUpdate = Filter.c_VerifyUpdate

let c_VerifyFinal = Filter.c_VerifyFinal

(********************************************************************************)
(*                     DUAL-PURPOSE CRYPTOGRAPHIC FUNCTIONS                     *)
(********************************************************************************)

let c_DigestEncryptUpdate = Filter.c_DigestEncryptUpdate

let c_DecryptDigestUpdate = Filter.c_DecryptDigestUpdate

let c_SignEncryptUpdate = Filter.c_SignEncryptUpdate

let c_DecryptVerifyUpdate = Filter.c_DecryptVerifyUpdate

(********************************************************************************)
(*                     KEY MANAGEMENT FUNCTIONS                                 *)
(********************************************************************************)

let c_GenerateKey = Filter.c_GenerateKey

let c_GenerateKeyPair = Filter.c_GenerateKeyPair


let c_WrapKey = Filter.c_WrapKey

let c_UnwrapKey = Filter.c_UnwrapKey

let c_DeriveKey = Filter.c_DeriveKey

(********************************************************************************)
(*                     RANDOM NUMBER GENERATION FUNCTIONS                       *)
(********************************************************************************)

let c_SeedRandom = Filter.c_SeedRandom

let c_GenerateRandom = Filter.c_GenerateRandom

(********************************************************************************)
(*                     PARALLEL FUNCTION MANAGEMENT FUNCTIONS                   *)
(********************************************************************************)

let c_GetFunctionStatus = Filter.c_GetFunctionStatus

let c_CancelFunction = Filter.c_CancelFunction
