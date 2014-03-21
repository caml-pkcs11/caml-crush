(***********************************************************************)
(* The secure templates patch:                                         *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

(* Key generation possible templates *)
let key_generation_templates key_segregation = if compare key_segregation true = 0 then
                                (* If we enforce encrypt-decrypt/sign-verify segregation *)
                                [|
                                   (* Wrap and Unwrap *)
                                   [| 
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                   |];
                                   (* Encrypt and decrypt *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                   |];
                                    (* Sign and verify *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                   |];          
                                |]
                                (******************************************************************)
                                else
                                [|
                                   (* Wrap and Unwrap *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                   |];
                                   (* Encrypt and decrypt *)
                                   [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                   |];
                                |]
                                (******************************************************************)

(* Key creation and import templates *)
let key_creation_import_templates key_segregation = if compare key_segregation true = 0 then
                                (* If we enforce encrypt-decrypt/sign-verify segregation *)
                                [|
                                  (* Unwrap and encrypt *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                  |];
                                  (* Unwrap and sign/verify *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                  |];
                                  (* Encrypt and sign/verify *)
                                   [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                  |];
                                |]
                                (******************************************************************)
                                else
                                [|
                                  (* Unwrap and encrypt *)
                                  [|
                                    {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                    {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                                  |];
                                |]
                                (******************************************************************)

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
        (* We have a key type, forbid the function *)
        let info_string = Printf.sprintf "[User defined extensions]: Bad SECURE_TEMPLATES asked during %s" fun_name in
        let _ = print_debug info_string 1 in
        (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
      else
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
    (* Check if the asked template is conforming with one of the generation templates *)
    if compare ((check_is_template_secure fun_name pub_attributes_array (key_generation_templates !segregate_usage)) &&
                (check_is_template_secure fun_name priv_attributes_array (key_generation_templates !segregate_usage))) true = 0 then
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
 
