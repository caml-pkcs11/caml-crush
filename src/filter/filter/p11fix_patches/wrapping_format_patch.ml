(***********************************************************************)
(* The wrapping format patch:                                          *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

(* Include the CMAC helpers here *)
INCLUDE "p11fix_patches/cmac.ml"

(* Create a buffer from critical attributes *)
let template_array_to_char_array templates =
  let out_array = Array.map (
    fun temp ->
      let check_value = get_existing_attribute_value templates temp in 
      if compare check_value [||] = 0 then
          (* Attribute not found, we put a "0xff" so that we can import it *)
          (Char.chr 0xff)
      else
        (* Attribute found, we add its true value *)
        if compare (char_array_to_bool check_value) Pkcs11.cK_TRUE = 0 then
          (Char.chr 1)
        else
          (Char.chr 0)
  ) !critical_attributes in
  (out_array)

(* Extract critical attributes from a buffer *)
let char_array_to_template_array buffer =
  let out_template_array = (
  if compare (Array.length buffer) (Array.length !critical_attributes) = 0 then
    Array.mapi (
      fun i in_char ->
      let the_value = (
        if compare in_char (Char.chr 1) = 0 then
          (bool_to_char_array Pkcs11.cK_TRUE)
        else
          if compare in_char (Char.chr 0) = 0 then
            (bool_to_char_array Pkcs11.cK_FALSE)
          else
            ([||])
      ) in
      ({Pkcs11.type_ = !critical_attributes.(i).Pkcs11.type_; 
        Pkcs11.value = the_value})
    ) buffer 
  else
    ([||])
  ) in
  (* Expurge the template from empty attributes *)
  (expurge_template_from_irrelevant_attributes out_template_array)

(* We define a fixed key in the code *)
(* WARNING: this is here for demo purpose, do NOT use this key    *)
(* as is in production code!                                      *)
(* You probably want to use a key secured in a token, or at least *)
(* a random key protected in a file                               *)
(************************************************************************************************************)
(**)let wrapping_format_key = Pkcs11.string_to_byte_array (Pkcs11.pack "00000000000000000000000000000000")(**)
(************************************************************************************************************)

let wrapping_format_patch fun_name arg =
  match fun_name with
  (* WrapKey *)
  ("C_WrapKey")  ->
      let (sessionh, mechanism, wrappingh, wrappedh) = deserialize arg in
      (* Call Wrap in the backend to get binary blob *)
      let (ret, wrapped_key_buffer) = Backend.c_WrapKey sessionh mechanism wrappingh wrappedh in
      (* If we have an error here, return it as is *)
      if compare ret Pkcs11.cKR_OK <> 0 then
        (serialize (true, (ret, [||])))
      else
        (* Get the attributes of the object we want to wrap *)
        let (ret, templates) = filter_getAttributeValue (Backend.c_GetAttributeValue sessionh wrappedh !critical_attributes) in
        if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
          if (compare ret Pkcs11.cKR_OK <> 0) then
            (serialize (true, (Pkcs11.cKR_KEY_NOT_WRAPPABLE, [||])))
          else
            let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...\n" in netplex_log_critical s; failwith s;
        else
          let (ret, templates_values) = Backend.c_GetAttributeValue sessionh wrappedh templates in
          if compare ret Pkcs11.cKR_OK <> 0 then
            (serialize (true, (Pkcs11.cKR_KEY_NOT_WRAPPABLE, [||])))
          else
            (* Compute the buffer *)
            let buffer = Array.append wrapped_key_buffer (template_array_to_char_array templates_values) in
            (* Compute the CMAC *)
            let buffer_cmac = cmac_compute buffer wrapping_format_key in
            (* Append the CMAC to the buffer *)
            let wrapping_format_buffer = Array.append buffer buffer_cmac in
            (serialize (true, (Pkcs11.cKR_OK, wrapping_format_buffer)))
  (* UnwrapKey *)
  | ("C_UnwrapKey")  ->
      let (sessionh, mechanism, unwrappingh, buffer, asked_attributes) = deserialize arg in
      (****)
      let extraction_error_ = false in
      let extraction_error = ref extraction_error_ in
      let buffer_attributes = (try Array.sub buffer ((Array.length buffer) - (Array.length !critical_attributes) - 16) (Array.length !critical_attributes)
        with _ -> extraction_error := true; ([||])
      ) in
      let real_wrapped_key_buffer =  (try Array.sub buffer 0 ((Array.length buffer) - (Array.length !critical_attributes) - 16)
        with _ -> extraction_error := true; ([||])
      ) in
      if compare !extraction_error true = 0 then
        (* In case of an extraction error ... *)
        let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected bad CMAC" fun_name in
        let _ = print_debug info_string 1 in
        (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
      else
        (* Compute the CMAC *)
        let check_cmac = cmac_verify buffer wrapping_format_key in
        if compare check_cmac false = 0 then
          (* CMAC is not OK: return an error *)
          let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected bad CMAC" fun_name in
          let _ = print_debug info_string 1 in
          (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
        else
          (* CMAC is OK, check the templates consistency *)
          let saved_attributes = char_array_to_template_array buffer_attributes in
          let check_templates_nok = check_are_templates_nonconforming fun_name saved_attributes asked_attributes in
          if compare check_templates_nok true = 0 then
            let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected templates inconsistency" fun_name in
            let _ = print_debug info_string 1 in
            (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
          else
            (* Sanitize the merged template *)
            let object_class = get_object_class asked_attributes in
            let sanitized_attributes_ = sanitize_creation_templates fun_name asked_attributes object_class in
            (* NB: we cannot use the generic patch because of our user extension system limitation *)
            (* since the wrapping_format must be an "end point"                                    *)
            if compare sanitized_attributes_ None = 0 then
              let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s error, NO CKA_CLASS in template" fun_name in
              let _ = print_debug info_string 1 in
              (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
            else
              let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s has CMAC and templates OK" fun_name in
              let _ = print_debug info_string 1 in
              (* All is OK, call the real Unwrap function from the backend *)
              (serialize (true, (Backend.c_UnwrapKey sessionh mechanism unwrappingh real_wrapped_key_buffer (get sanitized_attributes_))))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
