(***********************************************************************)
(* The sticky attributes patch:                                        *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)
(* If we segregate key usage, we add the sign-verify as sticky *)
let sticky_attributes key_segregation = if compare key_segregation true = 0 then
                        (* If we segregate key usage, we add the sign-verify in the sticky attributes *) 
                        [|
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           (** Addition for key segregation **)
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                         |]
                         else
                         [|
                           {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE};
                           {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                           {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                         |]


let sticky_attributes_patch fun_name arg = 
  match fun_name with
  (* Copy object case *)
  ("C_CopyObject" | "C_SetAttributeValue") ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          if compare fun_name "C_CopyObject" = 0 then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
          else
           (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n)" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          if compare fun_name "C_CopyObject" = 0 then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
          else
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          (* Check for sticky attributes transitions *)
          let check = detect_sticky_attributes fun_name templates_values attributes (sticky_attributes !segregate_usage) in
          if check = true then
            if compare fun_name "C_CopyObject" = 0 then
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
            else
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else
            (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
