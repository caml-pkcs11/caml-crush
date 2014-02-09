(***********************************************************************)
(* We sanitize the creation templates to avoid default values          *)
(* Default attributes we want to apply when not defined by a creation template *)
let default_sanitized_attributes_secret_key_ = [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE};
                                      {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE};
                                    |]
let default_sanitized_attributes_secret_key = ref default_sanitized_attributes_secret_key_

let default_sanitized_attributes_private_key_ = [|
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE};
                                      {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE};
                                    |]
let default_sanitized_attributes_private_key = ref default_sanitized_attributes_private_key_

let default_sanitized_attributes_public_key_ = [|
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                      {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE};
                                    |]
let default_sanitized_attributes_public_key = ref default_sanitized_attributes_public_key_


let sanitize_creation_templates fun_name attributes_array object_class_ =
  match object_class_ with
     None -> (* No object class have been extracted from the token, this should not happen *)
      (None)
    | Some object_class -> 
      begin
      match Pkcs11.match_cKO_value object_class with  
        ("cKO_SECRET_KEY" | "cKO_PRIVATE_KEY" | "cKO_PUBLIC_KEY") ->
          let default_sanitized_attributes = (match Pkcs11.match_cKO_value object_class with 
              "cKO_SECRET_KEY" -> !default_sanitized_attributes_secret_key
            | "cKO_PRIVATE_KEY" -> !default_sanitized_attributes_private_key
            | "cKO_PUBLIC_KEY" -> !default_sanitized_attributes_public_key
            | _ -> [||]
          ) in
          (* Append the default sanitized to the given template *)
          let new_attributes_array = Array.fold_left (
            fun new_attributes_tmp curr_sanitized -> 
              (* Check if the sanitized attribute is in the given template *)
              let check = Array.fold_left (
                fun curr_check curr_attr -> 
                  if compare curr_attr.Pkcs11.type_ curr_sanitized.Pkcs11.type_ = 0 then 
                    (curr_check || true)
                  else
                    (curr_check || false)
              ) false attributes_array in
              if compare check true = 0 then
                (* If the attribute is found, we don't append the default value *)
                (new_attributes_tmp) 
              else
                (* If the attribute is NOT found, we append it to the current list *)
                (Array.append new_attributes_tmp [| curr_sanitized |])
            ) attributes_array default_sanitized_attributes in
            (Some new_attributes_array)
         (* The template does not concern a key ... We do not touch it *)
         | _ -> (Some attributes_array)
      end

let sanitize_creation_templates_patch fun_name arg =
  match fun_name with
          "C_CreateObject" -> 
             let (sessionh, extracted_attributes_array) = deserialize arg in 
             (* Get the object type from the template *)
             let object_class = get_object_class extracted_attributes_array in
             let new_attributes_array_ = sanitize_creation_templates fun_name extracted_attributes_array object_class in
             begin
             match new_attributes_array_ with
                 None -> (serialize (true, (Pkcs11.cKR_TEMPLATE_INCOMPLETE, Pkcs11.cK_INVALID_HANDLE)))
               | Some new_attributes_array -> (serialize (true, Backend.c_CreateObject sessionh new_attributes_array))
             end
        (******)
        | "C_GenerateKey" -> 
             let (sessionh, mechanism, extracted_attributes_array) = deserialize arg in
             let new_attributes_array_ = sanitize_creation_templates fun_name extracted_attributes_array (Some Pkcs11.cKO_SECRET_KEY) in
             (serialize (true, Backend.c_GenerateKey sessionh mechanism (get new_attributes_array_))) 
        (******)
        | "C_UnwrapKey" -> 
             let (sessionh, mechanism, unwrappingh, wrappedh, extracted_attributes_array) = deserialize arg in
             (* Get the object type from the template *)
             let object_class = get_object_class extracted_attributes_array in
             let new_attributes_array_ = sanitize_creation_templates fun_name extracted_attributes_array object_class in
             begin
             match new_attributes_array_ with
                 None -> (serialize (true, (Pkcs11.cKR_TEMPLATE_INCOMPLETE, Pkcs11.cK_INVALID_HANDLE)))
               | Some new_attributes_array -> (serialize (true, Backend.c_UnwrapKey sessionh mechanism unwrappingh wrappedh new_attributes_array)) 
             end
        (******)
        | "C_DeriveKey" -> 
             let (sessionh, mechanism, keyh, extracted_attributes_array) = deserialize arg in
             (* Get the object type from the template *)
             let object_class = get_object_class extracted_attributes_array in
             let new_attributes_array_ = sanitize_creation_templates fun_name extracted_attributes_array object_class in
             begin
             match new_attributes_array_ with
                 None -> (serialize (true, (Pkcs11.cKR_TEMPLATE_INCOMPLETE, Pkcs11.cK_INVALID_HANDLE)))
               | Some new_attributes_array -> (serialize (true, Backend.c_DeriveKey sessionh mechanism keyh new_attributes_array)) 
             end
        (******)
        | "C_GenerateKeyPair" -> 
             let (sessionh, mechanism, pub_attributes, priv_attributes) = deserialize arg in 
             let new_pub_attributes_array_ = sanitize_creation_templates fun_name pub_attributes (Some Pkcs11.cKO_PUBLIC_KEY) in
             let new_priv_attributes_array_ = sanitize_creation_templates fun_name priv_attributes (Some Pkcs11.cKO_PRIVATE_KEY) in
             (serialize (true, Backend.c_GenerateKeyPair sessionh mechanism (get new_pub_attributes_array_) (get new_priv_attributes_array_)))
        (******)
        | _ -> (serialize (false, ()))
