(***************************************************************************)
(* The non local objects patch:                                        *****)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *****)

(* When using the CryptokiX patches, we want to avoid key created through  *)
(* C_CreateObject to circumvent the protections                            *)
(* Hence, we filter C_CreateObject and do not allow WRAP/UNWRAP attributes *)
(* set with C_SetAttributeValue/C_CopyObject  for non local                *)
(* objects - i.e. CKA_LOCAL set to FALSE -                                 *)

let non_local_objects_dangerous_attributes = [| 
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                      (* We should not be able to set CKA_LOCAL according to the standard, we enforce this however *)
                                      (* for C_CreateObject, C_CopyObject and C_SetAttribute                                       *)
                                      {Pkcs11.type_ = Pkcs11.cKA_LOCAL; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                               |]


let non_local_objects_patch fun_name arg =
  match fun_name with
  ("C_CreateObject")  ->
    let (_, extracted_attributes_array) = deserialize arg in
    (* First, we check if we are dealing with a key *)
    if compare (is_object_class_key extracted_attributes_array) true = 0 then
      let check = Array.fold_left (
        fun curr_check attr -> (curr_check || find_existing_attribute_value extracted_attributes_array attr)
      ) false non_local_objects_dangerous_attributes in
      if compare check true = 0 then
        (* We have found one of our dangerous attributes, this is not good! *)
        let info_string = Printf.sprintf "[User defined extensions]: NON_LOCAL_OBJECTS modification blocked during %s" fun_name in
        let _ = print_debug info_string 1 in
        (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
      else
        (* If all is ok, passthrough *)
        (serialize (false, ()))
    else
        (serialize (false, ()))
  | ("C_CopyObject" | "C_SetAttributeValue") ->
    let (sessionh, objecth, extracted_attributes_array) = deserialize arg in
    (* First, we check if we are dealing with a key *)
    if compare (is_existing_object_class_key sessionh objecth) true = 0 then
      (* Check if one of the dangerous attributes is concerned *)
      let check = Array.fold_left (
        fun curr_check attr -> (curr_check || find_existing_attribute_value extracted_attributes_array attr)
      ) false non_local_objects_dangerous_attributes in
      if compare check true = 0 then
        (* We have found one of our dangerous attributes, let's check if we must filter this call *)
        (* Extract the CKA_LOCAL attribute *)
        let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_LOCAL; Pkcs11.value = [||]}|] in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (* We cannot extract the CKA_LOCAL, which means that it is not a key *)
          (serialize (false, ()))
        else
          (* Extract the CKA_LOCAL value *)
          let (ret, templates_values) = Backend.c_GetAttributeValue sessionh objecth templates in
          if compare ret Pkcs11.cKR_OK <> 0 then
            (* We should not end up here ... *)
            let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_LOCAL (it is not possible to get these attributes from the backend ...)\n" in netplex_log_critical s; failwith s;
          else
            (* Check for CKA_LOCAL, if FALSE we give an error *)
            if compare (Pkcs11.char_array_to_bool templates_values.(0).Pkcs11.value) Pkcs11.cK_FALSE = 0 then
              (* The object is not local, block the call *)
              let info_string = Printf.sprintf "[User defined extensions]: NON_LOCAL_OBJECTS modification blocked during %s" fun_name in
              let _ = print_debug info_string 1 in
              if compare fun_name "C_CopyObject" = 0 then
                (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
              else
                (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT)))
            else
              (* No dangerous attribute us concerned ... *)
              (serialize (false, ()))
      else
        (* No dangerous attribute us concerned ... *)
        (serialize (false, ()))
    else
      (* No dangerous attribute us concerned ... *)
      (serialize (false, ()))
  | _ -> (serialize (false, ()))
