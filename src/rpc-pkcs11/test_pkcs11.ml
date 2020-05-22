(************************* MIT License HEADER ************************************
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

    The current source code is part of the RPC 2] source tree:
                          --------  socket (TCP or Unix)  --------------------
                         |2] RPC  |<+++++++++++++++++++> |                    |
                         |  Layer | [SSL/TLS optional]   |  --------          |
                          --------                       | |2] RPC  |         |
                                                         | |  Layer |         |
                                                         |  --------          |
                                                          --------------------

    Project: PKCS#11 Filtering Proxy
    File:    src/rpc-pkcs11/test_pkcs11.ml

************************** MIT License HEADER ***********************************)
open Printf

let blah = Client.c_Initialize ();;


let (ret_value, slot_list_, count) = Client.c_GetSlotList 0 0;;
printf "Ret value = %d, Count = %d, slot_list =" ret_value count;; 
Pkcs11.print_int_array slot_list_;;

let (ret_value, slot_list_, count) = Client.c_GetSlotList 0 count;;
printf "Ret value = %d, Count = %d, slot_list =" ret_value count;; 
Pkcs11.print_int_array slot_list_;;

let print_slots = fun slot ->
let (ret_valuea, slot_info_) = Client.c_GetSlotInfo slot in
let (ret_valueb, token_info_) = Client.c_GetTokenInfo slot in
(* Slot info *)
let slot_desc = Pkcs11.byte_array_to_string slot_info_.Pkcs11.ck_slot_info_slot_description in
(* Token info *)
let token_label = Pkcs11.byte_array_to_string token_info_.Pkcs11.ck_token_info_label in
let token_manufacturer_id = Pkcs11.byte_array_to_string token_info_.Pkcs11.ck_token_info_manufacturer_id in
let token_model = Pkcs11.byte_array_to_string token_info_.Pkcs11.ck_token_info_model in
let token_serial_number = Pkcs11.byte_array_to_string token_info_.Pkcs11.ck_token_info_serial_number in
let token_utc_time = Pkcs11.byte_array_to_string token_info_.Pkcs11.ck_token_info_utc_time in
if ret_valuea = Pkcs11.cKR_OK then printf "Slot description: %s\n" slot_desc;
if ret_valueb = Pkcs11.cKR_OK then 
printf "  Token label:  %s\n" token_label;
printf "  Token id:     %s\n" token_manufacturer_id;
printf "  Token model:  %s\n" token_model;
printf "  Token serial: %s\n" token_serial_number;
printf "  Token UTC:    %s\n" token_utc_time;;

let x = Array.iter print_slots slot_list_;;

let slot_id = 0;;

(* InitToken *)
let label = Pkcs11.string_to_byte_array "TestPkcs11" in 
let so_pin = Pkcs11.string_to_byte_array "87654321" in
ret_value = Client.c_InitToken slot_id so_pin label;;

(* InitPIN *)
let (ret_value, session) = Client.c_OpenSession slot_id (Pkcs11.cKF_SERIAL_SESSION lor Pkcs11.cKF_RW_SESSION);;
let so_pin = Pkcs11.string_to_byte_array "87654321" in
ret_value = Client.c_Login session Pkcs11.cKU_SO so_pin;;

let user_pin = Pkcs11.string_to_byte_array "0000" in
ret_value = Client.c_InitPIN session user_pin;;

ret_value = Client.c_Logout session;;
let ret_value = Client.c_CloseSession session;;

(* SetPIN *)
let (ret_value, session) = Client.c_OpenSession slot_id (Pkcs11.cKF_SERIAL_SESSION lor Pkcs11.cKF_RW_SESSION);;
let user_pin = Pkcs11.string_to_byte_array "0000";;
ret_value = Client.c_Login session Pkcs11.cKU_USER user_pin;;

let new_user_pin = Pkcs11.string_to_byte_array "1234";;
ret_value = Client.c_SetPIN session user_pin new_user_pin;;

ret_value = Client.c_Logout session;;
let ret_value = Client.c_CloseSession session;;


(* GetMechList *)
let (ret_value, mechanism_list_, count) = Client.c_GetMechanismList slot_id 0;;
let (ret_value, mechanism_list_, count) = Client.c_GetMechanismList slot_id count;;
printf "cKM Array below\n";;
let mechanisms = Array.map Pkcs11.match_cKM_value mechanism_list_ in
Pkcs11.print_string_array mechanisms;;

(* GetMechInfo *)
let (ret_value, mechanism_info_) = Client.c_GetMechanismInfo slot_id Pkcs11.cKM_RSA_PKCS;;
printf "GetMechanismInfo example below\n";;
printf "CKM_RSA_PKCS MinKeySize:    %d\n" mechanism_info_.Pkcs11.ck_mechanism_info_min_key_size;;
printf "CKM_RSA_PKCS MaxKeySize:    %d\n" mechanism_info_.Pkcs11.ck_mechanism_info_max_key_size;;

(* GenerateKeyPair *)
let (ret_value, session) = Client.c_OpenSession slot_id (Pkcs11.cKF_SERIAL_SESSION lor Pkcs11.cKF_RW_SESSION);;
let user_pin = Pkcs11.string_to_byte_array "1234";;
ret_value = Client.c_Login session Pkcs11.cKU_USER user_pin;;

(* Template utils *)

(* MechanismChoice *)
let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN ; Pkcs11.parameter = [| |] };;
(* PublicTemplate *)
let modulus_bits = Pkcs11.int_to_ulong_byte_array 512;;
let public_exponent = Pkcs11.int_to_ulong_byte_array 3;;
let public_exponent = Pkcs11.string_to_byte_array (Pkcs11.pack "010001");;
let label = Pkcs11.string_to_byte_array "mylabel";;
let id = Pkcs11.string_to_byte_array "123";;
let pubclass = Pkcs11.int_to_ulong_byte_array Pkcs11.cKO_PUBLIC_KEY;;
let privclass = Pkcs11.int_to_ulong_byte_array Pkcs11.cKO_PRIVATE_KEY;;
let keytype = Pkcs11.int_to_ulong_byte_array Pkcs11.cKK_RSA;;
let x1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = pubclass};;
let x2 = { Pkcs11.type_ = Pkcs11.cKA_MODULUS_BITS; Pkcs11.value = modulus_bits};;
let x3 = { Pkcs11.type_ = Pkcs11.cKA_TOKEN; Pkcs11.value = Pkcs11.true_};;
let x4 = { Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = id};;
let x5 = { Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = label};;
let x6 = { Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.true_};;
let x7 = { Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.true_};;
let x8 = { Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.true_};;
let x9 = { Pkcs11.type_ = Pkcs11.cKA_PUBLIC_EXPONENT; Pkcs11.value = public_exponent};;
let pub_template = [| x1; x2; x3; x4; x5; x6; x7; x8; x9 |];;
(* PrivateTemplate *)
let y1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = privclass};;
let y3 = { Pkcs11.type_ = Pkcs11.cKA_TOKEN; Pkcs11.value = Pkcs11.true_};;
let y4 = { Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = id};;
let y5 = { Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = label};;
let y6 = { Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.true_};;
let y7 = { Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.true_};;
let y8 = { Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.true_};;
let y9 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = Pkcs11.true_};;
let priv_template = [| y1; y3; y4; y5; y6; y7; y8; y9 |];;
(* GenerateKeyPair *)
let (ret_value, pubkey_, privkey_) = Client.c_GenerateKeyPair session my_mech pub_template priv_template;;

(* SetAttributeValue *)
let newlabel = Pkcs11.string_to_byte_array "newlabel";;
let z1 = { Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = newlabel};;
let mod_template = [| z1 |];;
let ret_value =  Client.c_SetAttributeValue session pubkey_ mod_template;;

(* GetObjectSize *)
let (ret_value, size_) =  Client.c_GetObjectSize session pubkey_;;
printf "PubKeySize: %d\n" size_;;


(* Sign *)
let tosign = Pkcs11.string_to_byte_array "mysecretdata";;
let sign_mech = { Pkcs11.mechanism = Pkcs11.cKM_SHA1_RSA_PKCS ; Pkcs11.parameter = [| |] };;
let ret_value = Client.c_SignInit session sign_mech privkey_;;
let (ret_value, signed_data_) = Client.c_Sign session tosign ;;
printf "--------------\n";;
printf "SIGNED DATA\n";;
Pkcs11.print_hex_array signed_data_;;
printf "--------------\n";;

let ret_value = Client.c_VerifyInit session sign_mech pubkey_;;
let ret_value = Client.c_Verify session tosign signed_data_;;
printf "--------------\n";;
printf "C_Verify returned %s\n" (Pkcs11.match_cKR_value ret_value);;
printf "--------------\n";;

let tosign = Pkcs11.string_to_byte_array "mysecretdata2";;
let ret_value = Client.c_VerifyInit session sign_mech pubkey_;;
let ret_value = Client.c_Verify session tosign signed_data_;;
printf "--------------\n";;
printf "C_Verify MUST have FAILED, returned %s\n" (Pkcs11.match_cKR_value ret_value);;
printf "--------------\n";;

(* Encrypt *)
let tocrypt = Pkcs11.string_to_byte_array "mysecretdata";;
let crypt_mech = { Pkcs11.mechanism = Pkcs11.cKM_RSA_PKCS ; Pkcs11.parameter = [| |] };;
let ret_value = Client.c_EncryptInit session crypt_mech pubkey_;;
let (ret_value, crypted_data_) = Client.c_Encrypt session tocrypt ;;
printf "--------------\n";;
printf "ENCRYPTED DATA\n";;
Pkcs11.print_hex_array crypted_data_;;
printf "--------------\n";;

(* Decrypt *)
let ret_value = Client.c_DecryptInit session crypt_mech privkey_;;
let (ret_value, decrypted_data_) = Client.c_Decrypt session crypted_data_ ;;
printf "--------------\n";;
printf "DECRYPTED DATA\n";;
Pkcs11.print_char_array decrypted_data_;;
printf "--------------\n";;

(* GetAttributeValue *)
let x1 = { Pkcs11.type_ = Pkcs11.cKA_MODULUS; Pkcs11.value = [||]};;
let x2 = { Pkcs11.type_ = Pkcs11.cKA_PUBLIC_EXPONENT; Pkcs11.value = [||]};;
let modbit_template = [| x1; x2 |];;

let (ret_value, modbit_template) = Client.c_GetAttributeValue session pubkey_ modbit_template;;
let (ret_value, modbit_template) = Client.c_GetAttributeValue session pubkey_ modbit_template;;
printf "--------------\n";;
printf "CKA_MODULUS and CKA_PUBLIC_EXPONENT templates\n";;
Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;;
Pkcs11.print_hex_array modbit_template.(1).Pkcs11.value;;

(* PublicTemplate *)
let x1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = pubclass};;
let x2 = { Pkcs11.type_ = Pkcs11.cKA_KEY_TYPE; Pkcs11.value = keytype};;
let x3 = { Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.true_};;
let x4 = { Pkcs11.type_ = Pkcs11.cKA_TOKEN; Pkcs11.value = Pkcs11.true_};;

let pub_template = Array.append modbit_template [| x1; x2; x3; x4 |];;

let (ret_value, pubkey_) = Client.c_CreateObject session pub_template;;

printf "--------------\n";;
(* PrivateTemplate *)
let y2 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE_EXPONENT; Pkcs11.value = [||]};;
let modbit_template = [| y2 |];;
let (ret_value, modbit_template) = Client.c_GetAttributeValue session privkey_ modbit_template;; 
let (ret_value, modbit_template) = Client.c_GetAttributeValue session privkey_ modbit_template;;
printf "CKA_PRIVATE_EXPONENT template *before* destruction\n";;
Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;;

(* DestroyObject *)
(* let ret_value =  Client.c_DestroyObject session privkey_;; *)
let modbit_template = [| y2 |];;
let (ret_value, modbit_template) = Client.c_GetAttributeValue session privkey_ modbit_template;; 
let (ret_value, modbit_template) = Client.c_GetAttributeValue session privkey_ modbit_template;;
printf "CKA_PRIVATE_EXPONENT template *after* destruction\n";;
Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;;
printf "--------------\n";;

let y1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = privclass};;
let y2 = { Pkcs11.type_ = Pkcs11.cKA_KEY_TYPE; Pkcs11.value = keytype};;
let y3 = { Pkcs11.type_ = Pkcs11.cKA_TOKEN; Pkcs11.value = Pkcs11.true_};;
let y4 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = Pkcs11.true_};;
let y5 = { Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.true_};;
let y6 = { Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.true_};;
let y7 = { Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.true_};;
let y8 = { Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.false_};;
let y9 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE_EXPONENT; Pkcs11.value = [||]};;

let newpriv_template = Array.append modbit_template [| y1; y2; y3; y4; y6; y7; y8; y9 |];;

let (ret_value, newprivkey_) = Client.c_CreateObject session newpriv_template;;


let ret_value =  Client.c_FindObjectsInit session [|  |];;
let (ret_value, found_, number_) =  Client.c_FindObjects session 10;;
let ret_value =  Client.c_FindObjectsFinal session;;
printf "Found %d objects\n" number_;;


(* ret_value = Client.c_Logout session;;
let ret_value = Client.c_CloseSession session;;*)


(* Let's open a session for the _Random ops *)
let (ret_value, session) = Client.c_OpenSession slot_id Pkcs11.cKF_SERIAL_SESSION;;

(* GetSessionInfo *)
let (ret_value, session_info_) = Client.c_GetSessionInfo session;;
printf "GetSessionInfo example below\n";;
printf "CKS_R0_USER_FUNCTIONS: %d\n" Pkcs11.cKS_RO_USER_FUNCTIONS;;
printf "Session state        : %d\n" session_info_.Pkcs11.ck_session_info_state;;

(* CloseAllSessions *)
(**
let ret_value = Client.c_CloseAllSessions 0;;
*)

(* SeedRandom *)
let pin = Pkcs11.string_to_byte_array "1234" in
ret_value = Client.c_Login session Pkcs11.cKU_USER pin;;

let rand = Pkcs11.string_to_byte_array "ThisIsSuperMegaRandom" in
ret_value = Client.c_SeedRandom session rand;;

 
(* GenerateRandom *)
let rand_len = 32;;
let (ret_value, rand_array) = Client.c_GenerateRandom session rand_len;;
printf "--------------\n";;
printf "Random string of length %d got from C_GenerateRandom:\n" rand_len;;
Pkcs11.print_hex_array rand_array;;


(* Generate a symmetric Key *)
(* Template *)
let x1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = privclass};;

let priv_template = [| y1; y3; y4; y5; y6; y7; y8; y9 |];;

(* GenerateKey *)
let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES_KEY_GEN ; Pkcs11.parameter = [| |] };;
let (ret_value, deskey_) = Client.c_GenerateKey session my_mech [| |];;

(* Dump the private key we have created *)
let y2 = { Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [||]};;
let deskey_template = [| y2 |];;
let (ret_value, deskey_template) = Client.c_GetAttributeValue session deskey_ deskey_template;; 
let (ret_value, deskey_template) = Client.c_GetAttributeValue session deskey_ deskey_template;;
printf "--------------\n";;
printf "DES key value generated with C_GenerateKey:\n";;
Pkcs11.print_hex_array deskey_template.(0).Pkcs11.value;;

(* Wrap the DES key with the public RSA key *)
let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES_ECB ; Pkcs11.parameter = [| |] };;
let (ret_value, wrapped_key_) = Client.c_WrapKey session my_mech deskey_ privkey_;;
printf "--------------\n";;
printf "Wrapped RSA DES: %d\n" ret_value;;
printf "Wrapped RSA private key with DES_ECB:\n";;
Pkcs11.print_hex_array wrapped_key_;;

(* Try to Unwrap the key *)
let y1 = { Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = privclass};;
let y4 = { Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = id};;
let y5 = { Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = label};;
let y6 = { Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.true_};;
let y7 = { Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.true_};;
let y8 = { Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.true_};;
let y9 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = Pkcs11.true_};;

let priv_template = [| y1; y3; y4; y5; y6; y7; y8; y9 |];;
(* This call should fail because the session is RO *)
let (ret_value, unwrapped_key_handle_) = Client.c_UnwrapKey session my_mech deskey_ wrapped_key_ priv_template;;
(* Open a new RW session *)
let (ret_value, session) = Client.c_OpenSession slot_id (Pkcs11.cKF_SERIAL_SESSION lor Pkcs11.cKF_RW_SESSION);;
let user_pin = Pkcs11.string_to_byte_array "1234";;
ret_value = Client.c_Login session Pkcs11.cKU_USER user_pin;;
(* This call should succeed since the session is RW now *)
let (ret_value, unwrapped_key_handle_) = Client.c_UnwrapKey session my_mech deskey_ wrapped_key_ priv_template;;
(* Now extract the key *)
let y2 = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE_EXPONENT; Pkcs11.value = [||]};;
let unwrappedkey_template = [| y2 |];;
let (ret_value, unwrappedkey_template) = Client.c_GetAttributeValue session unwrapped_key_handle_ unwrappedkey_template;; 
let (ret_value, unwrappedkey_template) = Client.c_GetAttributeValue session unwrapped_key_handle_ unwrappedkey_template;;
printf "--------------\n";;
printf "CKA_PRIVATE_EXPONENT template after Unwrap with the DES key\n";;
Pkcs11.print_hex_array unwrappedkey_template.(0).Pkcs11.value;;


(* Derive a key (we first generate a DH key pair) *)
(* MechanismChoice *)
let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_DH_PKCS_KEY_PAIR_GEN ; Pkcs11.parameter = [| |] };;
(* PublicTemplate *)
let prime = Pkcs11.string_to_byte_array (Pkcs11.pack "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");;
let base = Pkcs11.int_to_ulong_byte_array 2;;
let x1 = { Pkcs11.type_ = Pkcs11.cKA_PRIME; Pkcs11.value = prime };;
let x2 = { Pkcs11.type_ = Pkcs11.cKA_BASE; Pkcs11.value = base };;
let pub_dh_template = [| x1; x2 |];;
(* PrivateTemplate *)
let priv_dh_template = [| { Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = Pkcs11.true_} |];;
(* GenerateKeyPair *)
let (ret_value, pubkeydh_, privkeydh_) = Client.c_GenerateKeyPair session my_mech pub_dh_template priv_dh_template;;

(* Derivation *)
let pub_attr_template = [| { Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [| |]} |];;
let (ret_value, pub_attr_template) = Client.c_GetAttributeValue session pubkeydh_ pub_attr_template;;
let my_derive_mech = { Pkcs11.mechanism = Pkcs11.cKM_DH_PKCS_DERIVE ; Pkcs11.parameter = Array.make 128 '0'};;
let my_derive_templ = [| {Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = Pkcs11.int_to_ulong_byte_array Pkcs11.cKO_SECRET_KEY} ; {Pkcs11.type_ = Pkcs11.cKA_KEY_TYPE; Pkcs11.value = Pkcs11.int_to_ulong_byte_array Pkcs11.cKK_DES}; {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.true_} ; {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.true_} |];;
let (ret_value, derived_key_handle_) = Client.c_DeriveKey session my_derive_mech privkeydh_ my_derive_templ;;
let y2 = { Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [||]};;
let derived_key_template = [| y2 |];;
let (ret_value, derived_key_template) = Client.c_GetAttributeValue session derived_key_handle_ derived_key_template;;
let (ret_value, derived_key_template) = Client.c_GetAttributeValue session derived_key_handle_ derived_key_template;;
printf "--------------\n";;
printf "DH derived key template after derivation with the DES key\n";;
Pkcs11.print_hex_array derived_key_template.(0).Pkcs11.value;;



(* Digest *)
let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_MD5 ; Pkcs11.parameter = [| |] };;
let ret_value = Client.c_DigestInit session my_mech ;;
let string_to_digest = "the brown fox jumps over the lazy dog";;
let data = Pkcs11.string_to_byte_array string_to_digest;;
let ret_value = Client.c_DigestUpdate session data;;
let (ret_value, digest_) = Client.c_DigestFinal session;;
printf "--------------\n";;
printf "MD5 digest of '%s' through Update/Final is:\n" string_to_digest;;
Pkcs11.print_hex_array digest_;;
(** let ret_value = Client.c_DigestInit session my_mech;;
let (ret_value, digest_) = Client.c_Digest session data;;
printf "MD5 digest of '%s' through direct digest is:\n" string_to_digest;;
Pkcs11.print_hex_array digest_;; **)


(* Logout and finalize *)
ret_value = Client.c_Logout session;;
let ret_value = Client.c_CloseSession session;;

let ret_value = Client.c_CloseAllSessions slot_id;;
(* Logout on BAD Session ID *)
ret_value = Client.c_Logout 20;;
Client.c_Finalize ();;

