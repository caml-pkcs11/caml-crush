(************************* CeCILL-B HEADER ************************************
    Copyright ANSSI (2014)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr] and Marion
    DAUBIGNARD [marion.daubignard@ssi.gouv.fr]

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
    File:    src/tests/ocaml/p11_common.ml

************************** CeCILL-B HEADER ***********************************)
open Printf
open Config_file

exception C_InitializeError
exception C_FinalizeError
exception C_GetInfoError
exception C_WaitForSlotEventError
exception C_GetSlotListError
exception C_GetSlotListError
exception C_GetSlotInfoError
exception C_GetTokenInfoError
exception C_OpenSessionError
exception C_CloseSessionError
exception C_CloseAllSessionsError
exception C_GetSessionInfoError
exception C_LoginError
exception C_LogoutError
exception C_GetMechanismListError
exception C_GetMechanismListError
exception C_GetMechanismInfoError
exception C_InitTokenError
exception C_InitTokenError
exception C_InitPINError
exception C_InitPINError
exception C_SetPINError
exception C_SetPINError
exception C_SeedRandomError
exception C_GenerateRandomError
exception C_FindObjectsInitError
exception C_FindObjectsError
exception C_FindObjectsFinalError
exception C_GenerateKeyError
exception C_GenerateKeyPairError
exception C_CreateObjectError
exception C_CopyObjectError
exception C_DestroyObjectError
exception C_GetAttributeValueError
exception C_SetAttributeValueError
exception C_GetObjectSizeError
exception C_WrapKeyError
exception C_UnwrapKeyError
exception C_DeriveKeyError
exception C_DigestInitError
exception C_DigestError
exception C_DigestUpdateError
exception C_DigestKeyError
exception C_DigestFinalError
exception C_SignInitError
exception C_SignRecoverInitError
exception C_SignError
exception C_SignRecoverError
exception C_SignUpdateError
exception C_SignFinalError
exception C_VerifyInitError
exception C_VerifyRecoverInitError
exception C_VerifyError
exception C_VerifyRecoverError
exception C_DecryptError
exception C_VerifyUpdateError
exception C_VerifyFinalError
exception C_EncryptInitError
exception C_EncryptError
exception C_EncryptError
exception C_EncryptUpdateError
exception C_EncryptUpdateError
exception C_DigestEncryptUpdateError
exception C_DigestEncryptUpdateError
exception C_SignEncryptUpdateError
exception C_SignEncryptUpdateError
exception C_EncryptFinalError
exception C_EncryptFinalError
exception C_DecryptInitError
exception C_DecryptError
exception C_DecryptError
exception C_DecryptUpdateError
exception C_DecryptUpdateError
exception C_DecryptFinalError
exception C_DecryptFinalError
exception C_DecryptDigestUpdateError
exception C_DecryptDigestUpdateError
exception C_DecryptVerifyUpdateError
exception C_DecryptVerifyUpdateError
exception C_GetFunctionStatusError
exception C_CancelFunctionError
exception C_GetOperationStateError
exception C_GetOperationStateError
exception C_SetOperationStateError

exception UnsupportedRSAKeySize



(* A few macro for attributes *)
  
let attr_decrypt = { Pkcs11.type_ =Pkcs11.cKA_DECRYPT ; Pkcs11.value = Pkcs11.true_ }
let attr_encrypt = { Pkcs11.type_ =Pkcs11.cKA_ENCRYPT ; Pkcs11.value = Pkcs11.true_ }
let attr_wrap = { Pkcs11.type_ =Pkcs11.cKA_WRAP ; Pkcs11.value = Pkcs11.true_ }
let attr_unwrap = { Pkcs11.type_ =Pkcs11.cKA_UNWRAP ; Pkcs11.value = Pkcs11.true_ }
let attr_decryptf = { Pkcs11.type_ =Pkcs11.cKA_DECRYPT ; Pkcs11.value = Pkcs11.false_ }
let attr_encryptf = { Pkcs11.type_ =Pkcs11.cKA_ENCRYPT ; Pkcs11.value = Pkcs11.false_ }
let attr_wrapf = { Pkcs11.type_ =Pkcs11.cKA_WRAP ; Pkcs11.value = Pkcs11.false_ }
let attr_unwrapf = { Pkcs11.type_ =Pkcs11.cKA_UNWRAP ; Pkcs11.value = Pkcs11.false_ }
let attr_sensitive = { Pkcs11.type_ =Pkcs11.cKA_SENSITIVE ; Pkcs11.value = Pkcs11.true_ }
let attr_sensitivef = { Pkcs11.type_ =Pkcs11.cKA_SENSITIVE ; Pkcs11.value = Pkcs11.false_ }
let attr_always_sensitive = { Pkcs11.type_ =Pkcs11.cKA_ALWAYS_SENSITIVE ; Pkcs11.value = Pkcs11.true_ }
let attr_always_sensitivef = { Pkcs11.type_ =Pkcs11.cKA_ALWAYS_SENSITIVE ; Pkcs11.value = Pkcs11.false_ }
let attr_extractable = { Pkcs11.type_ =Pkcs11.cKA_EXTRACTABLE ; Pkcs11.value = Pkcs11.true_ }
let attr_extractablef = { Pkcs11.type_ =Pkcs11.cKA_EXTRACTABLE ; Pkcs11.value = Pkcs11.false_ }
let attr_never_extractable = { Pkcs11.type_ =Pkcs11.cKA_NEVER_EXTRACTABLE ; Pkcs11.value = Pkcs11.true_ }
let attr_never_extractablef = { Pkcs11.type_ =Pkcs11.cKA_NEVER_EXTRACTABLE ; Pkcs11.value = Pkcs11.false_ }
let attr_token = { Pkcs11.type_ =Pkcs11.cKA_TOKEN ; Pkcs11.value = Pkcs11.true_ }
let attr_tokenf = { Pkcs11.type_ =Pkcs11.cKA_TOKEN ; Pkcs11.value = Pkcs11.false_ }

let template_token_wd = [| attr_wrap ; attr_decrypt ; attr_token |]
let template_session_wd = [| attr_wrap ; attr_decrypt ; attr_tokenf |]
let template_token_ue = [| attr_unwrap ; attr_encrypt ; attr_token |]
let template_session_ue = [| attr_unwrap ; attr_encrypt ; attr_tokenf |]
let template_sensitive_conflict = [| attr_sensitivef ; attr_always_sensitive |]
let template_extractable_conflict = [| attr_extractable ; attr_never_extractable |]
let template_wu =  [| attr_wrap ; attr_unwrap |]

let init_module =
let group = new group in
  let p11_libname = new string_cp ~group ["Libname"] "" "PKCS#11 Library to use" in
  group#read "./pkcs11.conf";
  let libname = p11_libname#get in
    if libname = "" then
      failwith "Libname cannot be empty"
    else
      (* We should check for LoadModule return values *)
      Pkcs11.mL_CK_C_LoadModule (Pkcs11.string_to_char_array libname)

(* Append one element to template array *)
let templ_append template type_ value_ =
    let template = Array.append template [| { Pkcs11.type_ = type_; Pkcs11.value = value_}|] in
    (template)

(* Append one string element to template array tuple *)
let append_rsa_template type_ value_ pub_template priv_template =
    let (pub_template, priv_template) = match value_ with
        None -> (pub_template, priv_template)
        | Some x  -> (templ_append pub_template type_ (Pkcs11.string_to_char_array x),
                        templ_append priv_template type_ (Pkcs11.string_to_char_array x)) in
    (pub_template, priv_template)

(* Check return value and raise string on errors *)
let check_ret ret_value except continue =
    let msg = Pkcs11.match_cKR_value ret_value in
        match msg with
            "cKR_OK" -> msg
            | _ -> if continue = true then msg else failwith msg
            (*| _ -> if continue = true then msg else raise (except)*)

(* Returns true if the result is cKR_OK, returns false otherwise *)
let check_ret_ok ret_value =
  Pkcs11.match_cKR_value ret_value = "cKR_OK" 


(* Function for checking if one element is in a list *)
let check_element_in_list the_list element =
   (* Find the element *)
  let found = try Some (List.find (fun a -> compare a element = 0) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
    (true)

(* Function to get the intersection of two lists *)
let intersect l1 l2 =
  let intersection = List.filter (fun a -> check_element_in_list l2 a = true) l1 in
  (intersection)

let fetch_pin =
    let group = new group in
      let p11_user_pin = new string_cp ~group ["Pin"] "" "PKCS#11 Pin to use" in
      group#read "./pkcs11.conf";
      let conf_user_pin = p11_user_pin#get in
        if conf_user_pin = "" then
          failwith "Pin cannot be empty"
        else
          conf_user_pin

let print_slots = fun slot ->
    let (ret_valuea, slot_info_) = Pkcs11.mL_CK_C_GetSlotInfo slot in
    let (ret_valueb, token_info_) = Pkcs11.mL_CK_C_GetTokenInfo slot in
    (* Slot info *)
    let slot_desc = Pkcs11.char_array_to_string slot_info_.Pkcs11.ck_slot_info_slot_description in
    (* Token info *)
    let token_label = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_label in
    let token_manufacturer_id = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_manufacturer_id in
    let token_model = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_model in
    let token_serial_number = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_serial_number in
    let token_utc_time = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_utc_time in
    let token_max_session_count = token_info_.Pkcs11.ck_token_info_max_session_count in
    if ret_valuea = Pkcs11.cKR_OK then printf "Slot description: %s\n" slot_desc;
    if ret_valueb = Pkcs11.cKR_OK then 
    printf "  Token label:  %s\n" token_label;
    printf "  Token id:     %s\n" token_manufacturer_id;
    printf "  Token model:  %s\n" token_model;
    printf "  Token serial: %s\n" token_serial_number;
    printf "  Token UTC:    %s\n" token_utc_time;
    printf "  Token max_session:  %s\n" (Nativeint.to_string token_max_session_count)

(* High level GetMechanismList *)
let get_mechanism_list_for_slot slot_id =
    let (ret_value, _, count) = Pkcs11.mL_CK_C_GetMechanismList slot_id 0n in
    let _ = check_ret ret_value C_GetMechanismListError false in
    printf "C_GetMechanismList ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, mechanism_list_, _) = Pkcs11.mL_CK_C_GetMechanismList slot_id count in
    let _ = check_ret ret_value C_GetMechanismListError false in
    printf "C_GetMechanismList ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "cKM Array below\n";
    (mechanism_list_)

let generate_rsa_template keysize keyslabel keysid =
    let pub_template = [||] in
    let priv_template = [||] in

    let pubclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in

    let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
    let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in

    let public_exponent = Pkcs11.string_to_char_array (Pkcs11.pack "010001") in
    let pub_template = templ_append pub_template Pkcs11.cKA_PUBLIC_EXPONENT public_exponent in

    let modulus_bits = match keysize with
        512n -> Pkcs11.int_to_ulong_char_array keysize
        |1024n -> Pkcs11.int_to_ulong_char_array keysize
        |2048n -> Pkcs11.int_to_ulong_char_array keysize
        |4096n -> Pkcs11.int_to_ulong_char_array keysize
        |8192n -> Pkcs11.int_to_ulong_char_array keysize
        |16384n -> Pkcs11.int_to_ulong_char_array keysize
        | _ -> raise UnsupportedRSAKeySize in
    let pub_template = templ_append pub_template Pkcs11.cKA_MODULUS_BITS modulus_bits in
           
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_LABEL keyslabel pub_template priv_template in
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_ID keysid pub_template priv_template in

    let pub_template = templ_append pub_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_ENCRYPT Pkcs11.true_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_VERIFY Pkcs11.true_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_WRAP Pkcs11.true_ in

    let priv_template = templ_append priv_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_SIGN Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_UNWRAP Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_EXTRACTABLE Pkcs11.true_ in
    (pub_template, priv_template)

let generate_generic_rsa_template keysize keyslabel keysid =
    let pub_template = [||] in
    let priv_template = [||] in

    let pubclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in

    let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
    let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in

    let public_exponent = Pkcs11.string_to_char_array (Pkcs11.pack "010001") in
    let pub_template = templ_append pub_template Pkcs11.cKA_PUBLIC_EXPONENT public_exponent in

    let modulus_bits = match keysize with
        512n -> Pkcs11.int_to_ulong_char_array keysize
        |1024n -> Pkcs11.int_to_ulong_char_array keysize
        |2048n -> Pkcs11.int_to_ulong_char_array keysize
        |4096n -> Pkcs11.int_to_ulong_char_array keysize
        |8192n -> Pkcs11.int_to_ulong_char_array keysize
        |16384n -> Pkcs11.int_to_ulong_char_array keysize
        | _ -> raise UnsupportedRSAKeySize in
    let pub_template = templ_append pub_template Pkcs11.cKA_MODULUS_BITS modulus_bits in
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_LABEL keyslabel pub_template priv_template in
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_ID keysid pub_template priv_template in
    let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    (pub_template, priv_template)

let generate_weak_generic_rsa_template keyslabel =
    let pub_template = [||] in
    let priv_template = [||] in

    let pubclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in

    let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
    let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in   
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_LABEL keyslabel pub_template priv_template in
    let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    (pub_template, priv_template)

let update_generic_rsa_template attr_template template_to_upd= 
  let aux_update temp elem = 
    let (pub_template, priv_template) = temp in
    match elem with 
    | m when m=attr_wrap -> (Array.append pub_template [|attr_wrap|], priv_template)
    | m when m=attr_wrapf -> (Array.append pub_template [|attr_wrapf|], priv_template)
    | m when m=attr_unwrap -> (pub_template,Array.append priv_template [|attr_unwrap|])
    | m when m=attr_unwrapf -> (pub_template,Array.append priv_template [|attr_unwrapf|])
    | m when m=attr_decrypt -> (pub_template,Array.append priv_template [|attr_decrypt|])
    | m when m=attr_decryptf -> (pub_template,Array.append priv_template [|attr_decryptf|])
    | m when m=attr_encrypt ->  (Array.append pub_template [|attr_encrypt|], priv_template)
    | m when m=attr_encryptf ->  (Array.append pub_template [|attr_encryptf|] , priv_template)
    | m when m=attr_sensitive -> (pub_template,Array.append priv_template [|attr_sensitive|] ) 
    | m when m=attr_sensitivef -> (pub_template,Array.append priv_template [|attr_sensitivef|])  
    | m when m=attr_always_sensitive -> (pub_template,Array.append priv_template [|attr_always_sensitive|])
    | m when m=attr_always_sensitivef -> (pub_template,Array.append priv_template [|attr_always_sensitivef|])
    | m when m=attr_extractable -> (pub_template,Array.append priv_template [|attr_extractable|] )
    | m when m=attr_extractablef -> (pub_template,Array.append priv_template [|attr_extractablef|]) 
    | m when m=attr_never_extractable -> (pub_template,Array.append priv_template [|attr_never_extractable|] )
    | m when m=attr_never_extractablef -> (pub_template,Array.append priv_template [|attr_never_extractablef|])
    | m when m=attr_token ->  (Array.append pub_template [|attr_token|],
		     Array.append priv_template [|attr_token|])
    | m when m=attr_tokenf -> (Array.append pub_template [|attr_tokenf|],
		     Array.append priv_template [|attr_tokenf|])
    | _ -> failwith "update_generic_rsa_template_error : attribute is not listed!\n"
  in 		    
  Array.fold_left aux_update template_to_upd attr_template


(* TODO: we force a 1024 bit key here, one might want to support other sizes *)
let generate_rsa_key_pair session _ pub_template priv_template = 
    (* MechanismChoice *)
    let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN ; Pkcs11.parameter = [| |] } in
    (* GenerateKeyPair *)
    let (ret_value, pubkey_, privkey_) = Pkcs11.mL_CK_C_GenerateKeyPair session my_mech pub_template priv_template in
    let _ = check_ret ret_value C_GenerateKeyPairError false in
    printf "C_GenerateKeyPair ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    (pubkey_, privkey_)

 

let destroy_some_object session handle = 
    let ret_value = Pkcs11.mL_CK_C_DestroyObject session handle in
    let _ = check_ret ret_value C_DestroyObjectError false in

    (ret_value)

let sign_some_data session mechanism privkey_ data = 

    let ret_value = Pkcs11.mL_CK_C_SignInit session mechanism privkey_ in
    let _ = check_ret ret_value C_SignInitError false in

    let tosign = Pkcs11.string_to_char_array data in
    let (ret_value, signed_data_) = Pkcs11.mL_CK_C_Sign session tosign in
    let _ = check_ret ret_value C_SignInitError false in

    (signed_data_)

let digest_some_data session mechanism data = 
    let ret_value = Pkcs11.mL_CK_C_DigestInit session mechanism in
    let _ = check_ret ret_value C_DigestInitError false in

    let todigest = Pkcs11.string_to_char_array data in
    let (ret_value, digested_data_) = Pkcs11.mL_CK_C_Digest session todigest in
    let _ = check_ret ret_value C_DigestError false in

    (digested_data_)

let digestupdate_some_data session mechanism data = 
    let ret_value = Pkcs11.mL_CK_C_DigestInit session mechanism in
    let _ = check_ret ret_value C_DigestInitError false in

    let todigest = Pkcs11.string_to_char_array data in
    let ret_value = Pkcs11.mL_CK_C_DigestUpdate session todigest in
    let _ = check_ret ret_value C_DigestUpdateError false in

    let (ret_value, digested_data_) = Pkcs11.mL_CK_C_DigestFinal session in
    let _ = check_ret ret_value C_DigestFinalError false in

    (digested_data_)

let verify_some_data session mechanism pubkey_ rawdata_ signed_data_ = 

    let ret_value = Pkcs11.mL_CK_C_VerifyInit session mechanism pubkey_ in
    let _ = check_ret ret_value C_VerifyInitError false in

    let tocheck = Pkcs11.string_to_char_array rawdata_ in

    let ret_value = Pkcs11.mL_CK_C_Verify session tocheck signed_data_ in
    let _ = check_ret ret_value C_VerifyError false in

    (ret_value)

let encrypt_some_data session mechanism key_ data = 
    let toenc = Pkcs11.string_to_char_array data in

    let ret_value = Pkcs11.mL_CK_C_EncryptInit session mechanism key_ in
    let _ = check_ret ret_value C_EncryptInitError false in

    let (ret_value, enc_data_) = Pkcs11.mL_CK_C_Encrypt session toenc in
    let _ = check_ret ret_value C_EncryptError false in

    (enc_data_)

let decrypt_some_data session mechanism key_ encrypted_data = 

    let ret_value = Pkcs11.mL_CK_C_DecryptInit session mechanism key_ in
    let _ = check_ret ret_value C_DecryptInitError false in

    let (ret_value, dec_data_) = Pkcs11.mL_CK_C_Decrypt session encrypted_data in
    let _ = check_ret ret_value C_DecryptError false in

    (dec_data_)

let find_objects session attrs maxobj =
    let ret_value =  Pkcs11.mL_CK_C_FindObjectsInit session attrs in
    let _ = check_ret ret_value C_FindObjectsInitError false in
    printf "C_FindObjectsInit ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let (ret_value, found_, number_) =  Pkcs11.mL_CK_C_FindObjects session maxobj in
    let _ = check_ret ret_value C_FindObjectsError false in
    printf "C_FindObjects ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let ret_value =  Pkcs11.mL_CK_C_FindObjectsFinal session in
    let _ = check_ret ret_value C_FindObjectsFinalError false in
    printf "C_FindObjectsFinal ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    (found_, number_)

  
let sprintf_bool_value_of_attribute value =
  match value with
  | v when v=0n -> "cKA_FALSE"
  | v when v=1n -> "cKA_TRUE"
  | _-> "not a boolean value!"

