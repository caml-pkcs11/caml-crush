(***********************************************************************)
(* The patch preventing directly reading or writhing to sensitive or   *)
(* extractable keys.                                                   *)
(* This patch also prevents directly setting CKA_ALWAYS_SENSITIVE and  *)
(* CKA_NEVER_EXTRACTABLE                                               *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

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
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth attributes in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (getAttributeValueErrors ret, templates_values)))
        else
          (* If the object is sensitive or non-extractable, and we ask for a value, we return an error *)
          if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_VALUE attributes) true = 0) && 
             ((compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) 
              || (compare (check_is_attribute_set fun_name Pkcs11.cKA_EXTRACTABLE templates_values) true = 0)) then
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
