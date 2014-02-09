(* Helpers *)
let sprint_hex_array myarray = 
  let s = Array.fold_left (
    fun a elem -> Printf.sprintf "%s%02x" a (int_of_char elem);
  ) "'" myarray in
  (Printf.sprintf "%s'" s)

let bool_to_char_array boolean_attribute = 
  if compare boolean_attribute Pkcs11.cK_FALSE = 0 then
    ([| (Char.chr 0) |])
  else
    ([| (Char.chr 1) |])

let char_array_to_bool char_array = 
  let check = Array.fold_left (
    fun curr_check elem -> 
      if compare elem (Char.chr 0) = 0 then 
        (curr_check || false) 
      else 
        (curr_check || true)
    ) false char_array in
  if compare check false = 0 then
    (Pkcs11.cK_FALSE)
  else
    (Pkcs11.cK_TRUE)

let sprint_attribute_value attribute_value =
  if compare attribute_value  Pkcs11.cK_TRUE = 0 then
    ("TRUE")
  else
    if compare attribute_value  Pkcs11.cK_FALSE = 0 then
      ("FALSE")
    else
      ("UNKNOWN!")

let sprint_template_array template_array = 
  let string_ = Array.fold_left 
    (fun curr_string templ -> 
       let s1 = Printf.sprintf "(%s, " (Pkcs11.match_cKA_value templ.Pkcs11.type_) in
       let s2 = Printf.sprintf "%s) " (sprint_hex_array templ.Pkcs11.value) in
       (String.concat "" [curr_string; s1; s2])
  ) "" template_array in
  (string_)

(* The critical attributes we focus on in all the patches *)
let critical_attributes_ = [| 
                             {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_PRIVATE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_DERIVE; Pkcs11.value = [||]} ;
                           |]
let critical_attributes = ref critical_attributes_

(* The following function removes values from a template array *)
(* It is useful when we do not want sensitive values to go to  *)
(* the frontend                                                *)
let expurge_template_from_values templates_array =
  (Array.map (fun templ -> {Pkcs11.type_ = templ.Pkcs11.type_; Pkcs11.value = Array.make (Array.length templ.Pkcs11.value) (Char.chr 0)}) templates_array)

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
    (Some (Pkcs11.byte_array_to_ulong !object_class))

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
  
