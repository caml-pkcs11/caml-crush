(***********************************************************************)
(* The patch preventing directly reading sensitive or extractable keys *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)


(* Check if sensitive is set to TRUE in the given attributes array *)
let check_is_sensitive fun_name attributes = 
  let check = Array.fold_left (
    fun check_tmp attr ->
      if (compare attr.Pkcs11.type_ Pkcs11.cKA_SENSITIVE = 0) && 
         (compare attr.Pkcs11.value (Pkcs11.bool_to_char_array Pkcs11.cK_TRUE) = 0) then
        (check_tmp || true)
      else
        (check_tmp || false)
  ) false attributes in
  (check)

(* Check if extractable is set to FALSE in the given attributes array *)
let check_is_nonextractable fun_name attributes = 
  let check = Array.fold_left (
    fun check_tmp attr ->
      if (compare attr.Pkcs11.type_ Pkcs11.cKA_EXTRACTABLE = 0) && 
         (compare attr.Pkcs11.value (Pkcs11.bool_to_char_array Pkcs11.cK_FALSE) = 0) then
        (check_tmp || true)
      else
        (check_tmp || false)
  ) false attributes in
  (check)

(* Check if the Value attribute is asked in the given template *)
let check_is_value_asked fun_name attributes = 
  let check = Array.fold_left (
    fun check_tmp attr ->
      if (compare attr.Pkcs11.type_ Pkcs11.cKA_VALUE = 0) then 
        (check_tmp || true)
      else
        (check_tmp || false)
  ) false attributes in
  (check)

let prevent_sensitive_leak_patch fun_name arg = 
  match fun_name with
    "C_GetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue (Backend.c_GetAttributeValue sessionh objecth (critical_attributes !segregate_usage)) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (getAttributeValueErrors ret, templates)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = Backend.c_GetAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (getAttributeValueErrors ret, templates)))
        else
          (* If the object is sensitive or non-extractable, and we ask for a value, we return an error *)
          if (compare (check_is_value_asked fun_name attributes) true = 0) && 
             ((compare (check_is_sensitive fun_name templates_values) true = 0) 
              || (compare (check_is_nonextractable fun_name templates_values) true = 0)) then
            let error_type = 
              if (compare (check_is_sensitive fun_name templates_values) true = 0) then "SENSITIVE" else "NON EXTRACTABLE" in
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
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
