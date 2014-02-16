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
                         |]

let check_for_sticky_attribute fun_name old_attribute new_attribute = 
  let oatype = old_attribute.Pkcs11.type_ in
  let oavalue = old_attribute.Pkcs11.value in
  let natype = new_attribute.Pkcs11.type_ in
  let navalue = new_attribute.Pkcs11.value in
  if compare oatype natype = 0 then
    let check = Array.fold_left (
      fun curr_check curr_attr ->
        (* Detect a sticky attribute if the type is the same but we try to (un)set it *)
        if (compare oatype curr_attr.Pkcs11.type_ = 0) && (compare natype curr_attr.Pkcs11.type_ = 0) 
           && (compare oavalue curr_attr.Pkcs11.value = 0) 
           && (compare navalue curr_attr.Pkcs11.value <> 0) then 
           let info_string = Printf.sprintf "[User defined extensions]: STICKY_ATTRIBUTES asked during %s for %s=%s to %s" fun_name  
            (Pkcs11.match_cKA_value oatype) (Pkcs11.sprint_bool_attribute_value (Pkcs11.char_array_to_bool (old_attribute.Pkcs11.value))) (Pkcs11.sprint_bool_attribute_value (Pkcs11.char_array_to_bool (new_attribute.Pkcs11.value))) in
          let _ = print_debug info_string 1 in
          (curr_check || true)
        else
          (curr_check || false)
    ) false (sticky_attributes !segregate_usage) in
    (check)
  else
    (false)

let detect_sticky_attributes fun_name attributes new_attributes = 
  let check = Array.fold_left (
    fun curr_check curr_attr ->
      let tmp_check = Array.fold_left (
        fun tmp_check curr_new_attr ->
          (tmp_check || (check_for_sticky_attribute fun_name curr_attr curr_new_attr))
      ) false new_attributes in
      (curr_check || tmp_check)
  ) false attributes in
  (check) 

let sticky_attributes_patch fun_name arg = 
  match fun_name with
  (* Copy object case *)
  ("C_CopyObject" | "C_SetAttributeValue") ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue (Backend.c_GetAttributeValue sessionh objecth (critical_attributes !segregate_usage)) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          if compare fun_name "C_CopyObject" = 0 then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
          else
           (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n)" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = Backend.c_GetAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          if compare fun_name "C_CopyObject" = 0 then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
          else
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          (* Check for sticky attributes transitions *)
          let check = detect_sticky_attributes fun_name templates_values attributes in
          if check = true then
            if compare fun_name "C_CopyObject" = 0 then
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
            else
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else
            (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
