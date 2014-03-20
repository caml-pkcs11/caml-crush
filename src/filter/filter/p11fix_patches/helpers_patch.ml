(* Global value to tell if we want to segregate usage *)
let segregate_usage = ref false

let do_segregate_usage _ _ = (let info_string = Printf.sprintf "[User defined extensions]: Activating KEY USAGE SEGREGATION (encrypt/decrypt versus sign/verify)" in  print_debug info_string 1; segregate_usage := true; serialize (false, ()))

(* The critical attributes we focus on in all the patches *)
let critical_attributes key_segregation = if compare key_segregation true = 0 then
                           (* If we segregate key usage, we add the sign-verify in the critical attributes *)
                           [| 
                             {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = [||]} ;
                             (** Add the sign/verify attributes for key segregation patch **)
                             {Pkcs11.type_ = Pkcs11.cKA_SIGN; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_VERIFY; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_SIGN_RECOVER; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_VERIFY_RECOVER; Pkcs11.value = [||]} ;
                           |]
                           else
                           [|
                             {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = [||]} ;
                           |]

(* The following function removes values from a template array *)
(* It is useful when we do not want sensitive values to go to  *)
(* the frontend                                                *)
let expurge_template_from_values templates_array =
  (Array.map (fun templ -> {Pkcs11.type_ = templ.Pkcs11.type_; Pkcs11.value = Array.make (Array.length templ.Pkcs11.value) (Char.chr 0)}) templates_array)

let remove_asked_value_type_from_template templates_array = 
  let (new_templates_array, positions, current_position) = Array.fold_left (
    fun (curr_array, pos, curr_pos) templ ->
      if compare templ.Pkcs11.type_ Pkcs11.cKA_VALUE = 0 then
        (curr_array, Array.append pos [|curr_pos|], curr_pos+1)
      else
        (Array.append curr_array [|templ|], pos, curr_pos+1)
  ) ([||], [||], 0) templates_array in
  (new_templates_array, positions)

let insert_in_array the_array element position = 
  if compare position 0 = 0 then
    (Array.concat [[| element |]; the_array])
  else
    let sub_array_one = Array.sub the_array 0 position in
    let sub_array_two = Array.sub the_array position (Array.length the_array - position) in
    (Array.concat [sub_array_one; [| element |]; sub_array_two]) 

let insert_purged_value_type_in_template templates_array positions = 
  let new_array = ref templates_array in
  Array.iter (
    fun pos ->
      new_array := insert_in_array !new_array {Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [||]} pos;
  ) positions;
  (!new_array)

let expurge_template_from_irrelevant_attributes templates_array = 
  let new_templates_array = Array.fold_left (
    fun curr_array templ ->
      if compare templ.Pkcs11.value [||] = 0 then
        (curr_array)
      else 
        (Array.append curr_array [|templ|])
  ) [||] templates_array in
  (new_templates_array)

let find_existing_attribute attributes attribute =
  let check = List.filter (fun a -> compare a.Pkcs11.type_ attribute.Pkcs11.type_ = 0) (Array.to_list attributes) in
  if compare (List.length check) 0 = 0 then
    (false)
  else
    (true)

let find_existing_attribute_value attributes attribute =
  let check = List.filter (fun a -> (compare a.Pkcs11.type_ attribute.Pkcs11.type_ = 0) && (compare a.Pkcs11.value attribute.Pkcs11.value = 0)) (Array.to_list attributes) in
  if compare (List.length check) 0 = 0 then
    (false)
  else
    (true)

let get_existing_attribute_value attributes attribute =
  let check = List.filter (fun a -> (compare a.Pkcs11.type_ attribute.Pkcs11.type_ = 0)) (Array.to_list attributes) in
  if compare (List.length check) 0 = 0 then
    ([||])
  else
    ((List.hd check).Pkcs11.value)


(* The following function appends to new_attributes the attributes in old_attributes that are not defined in new_attributes *)
let merge_templates old_attributes new_attributes =
  (* Remove current object attributes from the new attributes *)
  let purged_attributes = Array.fold_left (
    fun new_array a ->
      if find_existing_attribute new_attributes a = false then
        (Array.append new_array [|a|])
      else
        (new_array)
  ) [||] old_attributes in
  (* Merge the two arrays *)
  let full_list_attributes = Array.append purged_attributes new_attributes in
  (full_list_attributes)


(* All the critical attributes might no be extracted depending on the object type   *)
(* Hence, we remove all the empty attributes that have not been extracted           *)
let filter_getAttributeValue (ret, attributes) =
  if (compare ret Pkcs11.cKR_OK = 0) || (compare ret Pkcs11.cKR_ATTRIBUTE_TYPE_INVALID = 0) then
    (* Expurge template from the non extracted attributes *)
    (Pkcs11.cKR_OK, expurge_template_from_irrelevant_attributes attributes) 
  else
    (* Return the error with purged values *)
    (ret, expurge_template_from_values attributes)

(* Errors for GetAttributeValue that we want to keep to remain P11 conforming *)
let conforming_errors_ = [ Pkcs11.cKR_GENERAL_ERROR; Pkcs11.cKR_SLOT_ID_INVALID; Pkcs11.cKR_KEY_HANDLE_INVALID; 
       Pkcs11.cKR_SESSION_CLOSED; Pkcs11.cKR_SESSION_HANDLE_INVALID; Pkcs11.cKR_TOKEN_NOT_PRESENT;
       Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED; Pkcs11.cKR_OBJECT_HANDLE_INVALID ]
let conforming_errors = ref conforming_errors_

let getAttributeValueErrors ret =
  let check = List.filter (fun a -> compare a ret = 0) !conforming_errors in
  if compare (List.length check) 0 <> 0 then
    (ret)
  else
    (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)


(* Get the class of an object from an attributes array *)
let get_object_class attributes = 
  let object_class_ = [||] in
  let object_class = ref object_class_ in
  Array.iter (
    fun templ -> 
      if compare templ.Pkcs11.type_ Pkcs11.cKA_CLASS = 0 then
        object_class := templ.Pkcs11.value;
  ) attributes;
  if compare !object_class [||] = 0 then
    (None)
  else
    (Some (Pkcs11.char_array_to_ulong !object_class))

let is_object_class_key attributes = 
  let object_class_ = get_object_class attributes in
  match object_class_ with 
    None -> (false)
   |Some object_class -> 
      begin
      match Pkcs11.match_cKO_value object_class with
        ("cKO_SECRET_KEY" | "cKO_PRIVATE_KEY" | "cKO_PUBLIC_KEY") -> (true)
        | _ -> (false)
      end

(* Check if two templates are compatible regarding their defined attributes *)
let check_are_templates_nonconforming fun_name attributes new_attributes =
  let check = Array.fold_left (
    fun curr_check curr_attr ->
      let tmp_check = Array.fold_left (
        fun tmp_check curr_new_attr ->
          if (compare curr_new_attr.Pkcs11.type_ curr_attr.Pkcs11.type_ = 0) &&
             (compare curr_new_attr.Pkcs11.value curr_attr.Pkcs11.value <> 0) then
            (tmp_check || true)
          else
            (tmp_check || false)
      ) false new_attributes in
      (curr_check || tmp_check)
  ) false attributes in
  (check)
  
