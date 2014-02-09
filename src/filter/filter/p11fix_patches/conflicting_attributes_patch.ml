(***********************************************************************)
(* The conflicting attributes patch:                                   *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)
let conflicting_attributes_ = [|
                                ({Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE});
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = bool_to_char_array Pkcs11.cK_FALSE});
                              |]
let conflicting_attributes = ref conflicting_attributes_

let check_for_attribute_value function_name atype avalue attributes_list =
  let check = Array.fold_left (
    fun curr_check curr_attr -> 
      let curr_type = curr_attr.Pkcs11.type_ in
      let curr_value = curr_attr.Pkcs11.value in
      if (compare curr_type atype = 0) && (compare curr_value avalue = 0) then
        (curr_check || true)
      else
        (curr_check || false)
  ) false attributes_list in
  (check)

let detect_conflicting_attributes function_name attributes new_attributes =
  (* Merge the attributes to get a good overview *)
  let full_list_attributes = merge_templates attributes new_attributes in 
  (* Now, check the given attributes list against conflicting attributes *)
  (* For each conflicting couple, check if it satisfied in the attributes list *)
  let check = Array.fold_left (
    fun curr_check cr_attr -> 
      (* Extract the current cnflicting attributes to check *)
      let first_a = fst cr_attr in
      let first_a_type = first_a.Pkcs11.type_ in
      let first_a_value = first_a.Pkcs11.value in
      let second_a = snd cr_attr in
      let second_a_type = second_a.Pkcs11.type_ in
      let second_a_value = second_a.Pkcs11.value in
      (* Parse the full list and check for our values if a proper type is found *)
      let block_it = (check_for_attribute_value function_name first_a_type first_a_value full_list_attributes) && 
                     (check_for_attribute_value function_name second_a_type second_a_value full_list_attributes) in
        if block_it = true then
          let info_string = Printf.sprintf "[User defined extensions]: CONFLICTING_ATTRIBUTES asked during %s for %s=%s and %s=%s" function_name  
          (Pkcs11.match_cKA_value first_a_type) (sprint_attribute_value (char_array_to_bool first_a_value)) (Pkcs11.match_cKA_value second_a_type) (sprint_attribute_value (char_array_to_bool second_a_value)) in
          let _ = print_debug info_string 1 in
          (curr_check || block_it)
        else
          (curr_check || block_it)
  ) false !conflicting_attributes in
  (check) 


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
      let check = detect_conflicting_attributes fun_name [||] attributes_array in
      if check = true then
        (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
      else
        (serialize (false, ()))
  | "C_GenerateKeyPair" -> 
      let (sessionh, mechanism, pub_attributes, priv_attributes) = deserialize arg in
      let check = detect_conflicting_attributes fun_name [||] priv_attributes in
      if check = true then
        (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)))
      else
        let check = detect_conflicting_attributes fun_name [||] pub_attributes in
        if check = true then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)))
        else          
          (serialize (false, ()))
  (* It is an attributes modification function *)
  | "C_SetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue (Backend.c_GetAttributeValue sessionh objecth !critical_attributes) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = Backend.c_GetAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
        else
          let check = detect_conflicting_attributes fun_name templates_values attributes in
          if check = true then
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)))
          else
            (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ())) 
(***********************************************************************)
