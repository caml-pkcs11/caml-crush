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
    File:    src/filter/filter/p11fix_patches/secure_templates_patch.ml

************************** MIT License HEADER ***********************************)
(***********************************************************************)
(* The secure templates patch:                                         *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

(* Key generation possible templates *)
let key_generation_templates key_segregation = if compare key_segregation true = 0 then
                                (* If we enforce encrypt-decrypt/sign-verify segregation *)
                                [|
                                   (* Wrap and/or Unwrap *)
                                   [| 
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                   |];
                                   (* Encrypt and/or decrypt *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                   |];
                                    (* Sign and/or verify *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                   |];          
                                |]
                                (******************************************************************)
                                else
                                [|
                                   (* Wrap and/or Unwrap *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                   |];
                                   (* Encrypt and/or decrypt *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                   |];
                                |]
                                (******************************************************************)

(* Key creation and import templates *)
let key_creation_import_templates key_segregation = if compare key_segregation true = 0 then
                                (* If we enforce encrypt-decrypt/sign-verify segregation *)
                                [|
                                  (* Unwrap and/or encrypt but no sign/verify *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                  |];
                                  (* Unwrap and/or sign/verify but no encrypt *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                  |];
                                |]
                                (******************************************************************)
                                else
                                [|
                                  (* Unwrap and/or encrypt *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                  |];
                                |]
                                (******************************************************************)


let secure_templates_sticky_attributes key_segregation = if compare key_segregation true = 0 then
                        (* If we segregate key usage, we add the sign-verify in the sticky attributes *)
                        [|
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           (** Addition for key segregation **)
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                         |]
                         else
                         [|
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                         |]


let check_is_template_secure fun_name template secure_templates = 
  let check = Array.fold_left (
    fun curr_check secure_temp ->
      (curr_check || not(check_are_templates_nonconforming fun_name template secure_temp))
  ) false secure_templates in
  (check)

let secure_templates_patch fun_name arg =
  match fun_name with
  (* We forbid C_SetAttributeValue calls on key type objects *)
  ("C_SetAttributeValue") -> 
    let (sessionh, objecth, attributes) = deserialize arg in
    (* Are we dealing with a key? *)
    let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = [||]}|] in
    if compare ret Pkcs11.cKR_OK <> 0 then
      (* We should not end up here ... Send an error *)
      (serialize (true, (Pkcs11.cKR_GENERAL_ERROR)))
    else
      let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth templates in
      if compare (is_object_class_key templates) true = 0 then
        (* We have a key type *)
        (* Are we trying to change a sticky attribute? Extract the critical attributes *)
        let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
        if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
          if (compare ret Pkcs11.cKR_OK <> 0) then
            if compare fun_name "C_CopyObject" = 0 then
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
            else
             (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else
            let s = "[User defined extensions] C_SettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n)" in netplex_log_critical s; failwith s;
        else
          let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
          if compare ret Pkcs11.cKR_OK <> 0 then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else 
            (* We got the critical attributes, now check if a sticky attributes is (un)set *)
            let check = detect_sticky_attributes fun_name templates_values attributes (secure_templates_sticky_attributes !segregate_usage) in
            if check = true then
              (* If yes: return an error *)
              let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES (for STICKY attribute) asked during %s" fun_name in
              let _ = print_debug info_string 1 in
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
            else
              (* Passtrhough *)
              (serialize (false, ()))
      else
        (* Passtrhough *)
        (serialize (false, ()))
  (* Key generation *)
  | "C_GenerateKey" -> 
    let (_, _, attributes_array) = deserialize arg in
    (* Check if the asked template is conforming with one of the generation templates *)
    if compare (check_is_template_secure fun_name attributes_array (key_generation_templates !segregate_usage)) true = 0 then
      (* Template is secure, passthrough *)
      (serialize (false, ()))
    else
      (* Templa is NOT secure, block the function *)
      let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
      let _ = print_debug info_string 1 in
      (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
  | "C_GenerateKeyPair" -> 
    let (_, _, pub_attributes_array, priv_attributes_array) = deserialize arg in
    (* Check if the asked template is conforming with one of the generation templates, work on the fused template *)
    let fused_attributes_array = Array.concat [pub_attributes_array; priv_attributes_array] in
    if compare (check_is_template_secure fun_name fused_attributes_array (key_generation_templates !segregate_usage)) true = 0 then
      (* Template is secure, passthrough *)
      (serialize (false, ()))
    else
      (* Templa is NOT secure, block the function *)
      let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
      let _ = print_debug info_string 1 in
      (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)))
  (* Key creation/import *) 
  | ("C_UnwrapKey" | "C_CreateObject" | "C_CopyObject" | "C_DeriveKey") -> 
    let (sessionh, objecth, attributes_array) = (match fun_name with
        "C_UnwrapKey" -> let (sessionh, _, _, _, extracted_attributes_array) = deserialize arg in (sessionh, Pkcs11.cK_INVALID_HANDLE, extracted_attributes_array)
      | "C_CreateObject" -> let (sessionh, extracted_attributes_array) = deserialize arg in (sessionh, Pkcs11.cK_INVALID_HANDLE, extracted_attributes_array)
      | "C_CopyObject" -> let (sessionh, objecth, extracted_attributes_array) = deserialize arg in (sessionh, objecth, extracted_attributes_array)
      | "C_DeriveKey" -> let (sessionh, _, objecth, extracted_attributes_array) = deserialize arg in (sessionh, objecth, extracted_attributes_array)
      (* We should not end up here ... *)
      | _ -> (Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE, [||])
    ) in
    (* Check if the asked template is conforming with one of the creation templates *)
    if compare (check_is_template_secure fun_name attributes_array (key_creation_import_templates !segregate_usage)) true = 0 then
      (* Template is secure, passthrough *)
      (serialize (false, ()))
    else
      (* In the case of CreateObject or CopyObject on non key objects, passthrough *)
      if compare fun_name "C_CreateObject" = 0 then
        if compare (is_object_class_key attributes_array) false = 0 then
          (* Passthrough *)
          (serialize (false, ()))
        else
          (* Templa is NOT secure, block the function *)
          let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
          let _ = print_debug info_string 1 in
          (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
      else
        if compare fun_name "C_CopyObject" = 0 then
          (* Extract the cKA_CLASS of the existing object *)
          let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = [||]}|] in
          if compare ret Pkcs11.cKR_OK <> 0 then
            (* We should not end up here ... Send an error *)
            (serialize (true, (Pkcs11.cKR_GENERAL_ERROR)))
          else
            let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth templates in
            (* Are we dealing with a key? *)
            if compare (is_object_class_key templates) false = 0 then
              (* We do not have a key type, passthrough *)
              (serialize (false, ()))
            else
              (* We have a key type, forbid the function *)
              let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
              let _ = print_debug info_string 1 in
              (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
        else
          (* Templa is NOT secure, block the function *)
          let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
          let _ = print_debug info_string 1 in
          (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
  (* Passthrough in other cases *)
  | _ -> (serialize (false, ()))
 
