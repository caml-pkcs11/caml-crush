(************************* MIT License HEADER ************************************
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

    The current source code is part of the PKCS#11 filter 4] source tree:

           |
 ----------------------
| 4] PKCS#11 filter    |
 ----------------------
           |

    Project: PKCS#11 Filtering Proxy
    File:    src/filter/filter/p11fix_patches/conflicting_attributes_patch.ml

************************** MIT License HEADER ***********************************)
(***********************************************************************)
(* The conflicting attributes patch:                                   *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)
let conflicting_attributes key_segregation = if compare key_segregation true = 0 then
                             (* If we segregate key usage, we add the sign-verify/encrypt-decrypt conflicting attributes *)
                             [|
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE}, {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE}, {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                (** Addition for key segregation **)
                                ({Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                              |]
                              else
                              [|
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE}, {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE}, {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                              |]

let conflicting_attributes_patch fun_name arg = 
  match fun_name with
  (* Is it a creation function (i.e. PKCS#11 function that create new objects?) *)
    ("C_CreateObject" | "C_CopyObject" | "C_UnwrapKey" | "C_GenerateKey" | "C_DeriveKey") -> 
      let attributes_array = (match fun_name with
          "C_CreateObject" -> let (_, extracted_attributes_array) = deserialize arg in (extracted_attributes_array)
        | ("C_CopyObject" | "C_GenerateKey") -> let (_, _, extracted_attributes_array) = deserialize arg in (extracted_attributes_array)
        | "C_UnwrapKey" -> let (_, _, _, _, extracted_attributes_array) = deserialize arg in (extracted_attributes_array)
        | "C_DeriveKey" -> let (_, _, _, extracted_attributes_array) = deserialize arg in (extracted_attributes_array)
        (* We should not end up here ... *)
        | _ -> [||]
      ) in
      let check = detect_conflicting_attributes fun_name [||] attributes_array (conflicting_attributes !segregate_usage) in
      if check = true then
        (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
      else
        (serialize (false, ()))
  | "C_GenerateKeyPair" -> 
      let (sessionh, mechanism, pub_attributes, priv_attributes) = deserialize arg in
      (* For asymmetric keys, we have to check conflicting attributes on the fused template *)
      let check = detect_conflicting_attributes fun_name [||] (Array.concat [pub_attributes; priv_attributes]) (conflicting_attributes !segregate_usage) in
      if check = true then
        (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)))
      else
          (serialize (false, ()))
  (* It is an attributes modification function *)
  | "C_SetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let s = "[User defined extensions] C_SettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): in CONFLICTING_ATTRIBUTES\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let check = detect_conflicting_attributes fun_name templates_values attributes (conflicting_attributes !segregate_usage) in
          if check = true then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else
            (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ())) 


(*** This patch is an addendum to the original CryptokiX patch            ***)
(*** We need it to check EXISTING objects on the token when they are used ***)
let conflicting_attributes_patch_on_existing_objects fun_name arg = 
  match fun_name with
  (* Crypto operations *)
    ("C_EncryptInit" | "C_DecryptInit" | "C_SignInit" | "C_SignRecoverInit" | "C_VerifyInit" | "C_VerifyRecoverInit") -> 
     let (sessionh, _, ckobjecthandlet_) = deserialize arg in
     let check = detect_conflicting_attributes_on_existing_object fun_name sessionh ckobjecthandlet_ (conflicting_attributes !segregate_usage) in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID)))
     else
       (serialize (false, ()))
  | "C_DeriveKey" ->
     let (sessionh, _, initial_key_handle, _) = deserialize arg in
     let check = detect_conflicting_attributes_on_existing_object fun_name sessionh initial_key_handle (conflicting_attributes !segregate_usage) in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
     else
       (serialize (false, ()))
  | "C_DigestKey" -> 
     let (sessionh, ckobjecthandlet_) = deserialize arg in
     let check = detect_conflicting_attributes_on_existing_object fun_name sessionh ckobjecthandlet_ (conflicting_attributes !segregate_usage) in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID)))
     else
       (serialize (false, ()))
  | "C_WrapKey" -> 
     let (sessionh, _, wrapping_handle, wrapped_handle) = deserialize arg in
     let check_one = detect_conflicting_attributes_on_existing_object fun_name sessionh wrapping_handle (conflicting_attributes !segregate_usage) in
     let check_two = detect_conflicting_attributes_on_existing_object fun_name sessionh wrapped_handle (conflicting_attributes !segregate_usage) in
     if (compare check_one true = 0) || (compare check_two true = 0) then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, [||])))
     else
       (serialize (false, ()))
  | "C_UnwrapKey" ->
     let (sessionh, _, unwrapping_handle, _, _) = deserialize arg in
     let check = detect_conflicting_attributes_on_existing_object fun_name sessionh unwrapping_handle (conflicting_attributes !segregate_usage) in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
     else
       (serialize (false, ()))
  | "C_FindObjects" ->
    let (sessionh, _) = deserialize arg in
    (* We filter the global object list and remove objects that don't fit our policy *)
    let new_current_find_objects_filtered_handles = !current_find_objects_filtered_handles in
    Array.iter (
      fun handle -> 
        let check = detect_conflicting_attributes_on_existing_object fun_name sessionh handle (conflicting_attributes !segregate_usage) in
        if compare check true = 0 then
          current_find_objects_filtered_handles := Array.of_list (
             (* Remove the handle from the array since it is a 'bad' object *)
              List.filter (
                  fun curr_handle -> if compare handle curr_handle = 0 then false else true
                ) (Array.to_list !current_find_objects_filtered_handles)
            )
        else
          ()
    ) new_current_find_objects_filtered_handles;
    (serialize (false, ())) 
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ())) 

(***********************************************************************)
