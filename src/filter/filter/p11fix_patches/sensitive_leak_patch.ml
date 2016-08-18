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
    File:    src/filter/filter/p11fix_patches/sensitive_leak_patch.ml

************************** MIT License HEADER ***********************************)
(***********************************************************************)
(* The patch preventing directly reading or writhing to sensitive or   *)
(* extractable keys.                                                   *)
(* This patch also prevents directly setting CKA_ALWAYS_SENSITIVE and  *)
(* CKA_NEVER_EXTRACTABLE                                               *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

(* Specific cases where the sensitive part of the key is not a CKA_VALUE *)
(* FIXME: Check if there is no other algorithm than RSA falling in this category *)
(* FIXME: This function is kind of ugly, it can be rewritten in a more elegant way *)
let handle_object_sensitive_not_cka_value fun_name sessionh objecth attributes =
  (* Get the key type if it is relevant *)
  if is_existing_object_class_private_key sessionh objecth  = true then
    let (ret, templates) = filter_getAttributeValue sessionh objecth [| { Pkcs11.type_ = Pkcs11.cKA_KEY_TYPE; Pkcs11.value = [||] } |] in
    let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
    if compare ret Pkcs11.cKR_OK <> 0 then
      (* There was an error, fallback to the CKA_VALUE check *)
      (2, Pkcs11.cKR_OK, [||])
    else
      if compare (Pkcs11.char_array_to_ulong templates_values.(0).Pkcs11.value) Pkcs11.cKK_RSA = 0 then
        (* We have RSA key *)
        if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_PRIVATE_EXPONENT attributes) true = 0) 
           || (compare (check_is_attribute_asked fun_name Pkcs11.cKA_PRIME_1 attributes) true = 0)
           || (compare (check_is_attribute_asked fun_name Pkcs11.cKA_PRIME_2 attributes) true = 0)
           || (compare (check_is_attribute_asked fun_name Pkcs11.cKA_EXPONENT_1 attributes) true = 0)
           || (compare (check_is_attribute_asked fun_name Pkcs11.cKA_EXPONENT_2 attributes) true = 0)
           || (compare (check_is_attribute_asked fun_name Pkcs11.cKA_COEFFICIENT attributes) true = 0) then
          (* We have a RSA key and some sensitive attributes are asked *)
          let filtered_attributes = attributes in
          let (filtered_attributes, positions_private_exp) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_PRIVATE_EXPONENT in
          let (filtered_attributes, positions_prime_1) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_PRIME_1 in
          let (filtered_attributes, positions_prime_2) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_PRIME_2 in
          let (filtered_attributes, positions_exp_1) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_EXPONENT_1 in
          let (filtered_attributes, positions_exp_2) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_EXPONENT_2 in
          let (filtered_attributes, positions_coeff) = remove_asked_specific_type_from_template filtered_attributes Pkcs11.cKA_COEFFICIENT in
          let (ret, returned_attributes) = Backend.c_GetAttributeValue sessionh objecth filtered_attributes in
          (* Now, we reinsert the sensitive types in the template with zeroes *)
          let filtered_attributes = insert_purged_value_type_in_template filtered_attributes (Array.concat [ positions_private_exp; positions_prime_1; positions_prime_2; positions_exp_1; positions_exp_2; positions_coeff ]) in
          (1, ret, filtered_attributes)
        else
          (* We have a RSA key without asking for sensitive attributes, passthrough *)
          (0, Pkcs11.cKR_OK, [||])
      else 
        (* Not a RSA key, fallback to the CKA_VALUE check *)
        (2, Pkcs11.cKR_OK, [||])
   else
     (* Not a private key, fallback to the CKA_VALUE check *)
     (2, Pkcs11.cKR_OK, [||])

let prevent_sensitive_leak_patch fun_name arg = 
  match fun_name with
    "C_GetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (getAttributeValueErrors ret, attributes)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in let _ = netplex_log_critical s in netplex_log_critical s; failwith s;
        else
          (* If the object is sensitive or non-extractable, and we ask for a sensitive attribute, we return an error *)
          if ((compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) 
              || (compare (check_is_attribute_set fun_name Pkcs11.cKA_EXTRACTABLE templates_values) true = 0)) then
            (* Specific cases where CKA_VALUE is NOT (or not only ...) the sensitive part of the object *)
            let (check, ret, filtered_attributes) = handle_object_sensitive_not_cka_value fun_name sessionh objecth attributes in
            match check with
              |0 -> 
                (* Case 0: we pass through without doing anything *)
                (serialize (false, ())) 
              |1 ->
                (* Case 1: we return a specific error *)
                (serialize (true, (ret, filtered_attributes))) 
              |2 -> 
                (* Case 2: we fall in the case where we want to test the specific CKA_VALUE case *)
                (* Key type has sensitive value in CKA_VALUE attribute *)
                if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_VALUE attributes) true = 0) then 
                  let error_type = 
                    if (compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) then "SENSITIVE" else "NON EXTRACTABLE" in
                  let info_string = Printf.sprintf "[User defined extensions]: SENSITIVE_LEAK asked during %s for a %s key" fun_name error_type in
                  let _ = print_debug info_string 1 in
                  (* We expurge the template from the value type and call the backend *)
                  let (new_attributes, positions) = remove_asked_value_type_from_template attributes in
                  let (ret, returned_attributes) = Backend.c_GetAttributeValue sessionh objecth new_attributes in
                  (* Now, we reinsert the value type in the template with zeroes *)
                  let filtered_attributes = insert_purged_value_type_in_template returned_attributes positions in
                  (serialize (true, (Pkcs11.cKR_ATTRIBUTE_SENSITIVE, filtered_attributes)))
                else
                  (* If we are here, we passthrough the call *)
                  (serialize (false, ()))
              |_ ->
                (* This case should not happen by construction *)
                 let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when checking for sensitive or extractible object attributes\n" in let _ = netplex_log_critical s in netplex_log_critical s; failwith s;        
           else
             (* If we are here, we passthrough the call *)
             (serialize (false, ()))
  | "C_SetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
        else
          let s = "[User defined extensions] C_SettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
        else
          (* If the object is sensitive or non-extractable, and we ask for a value to be set, we return an error *)
          if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_VALUE attributes) true = 0) && 
             ((compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) 
              || (compare (check_is_attribute_set fun_name Pkcs11.cKA_EXTRACTABLE templates_values) true = 0)) then
            let error_type = 
              if (compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) then "SENSITIVE" else "NON EXTRACTABLE" in
            let info_string = Printf.sprintf "[User defined extensions]: SENSITIVE_LEAK asked during %s for a %s key" fun_name error_type in
            let _ = print_debug info_string 1 in
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
          else
            (* If we ask for a modification of CKA_NEVER_EXTRACTABLE or CKA_ALWAYS_SENSITIVE, return an error *)
            if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_ALWAYS_SENSITIVE attributes) true = 0) ||
               (compare (check_is_attribute_asked fun_name Pkcs11.cKA_NEVER_EXTRACTABLE attributes) true = 0) then
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
            (* If we end up here, passthrough *)
            else           
              (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
