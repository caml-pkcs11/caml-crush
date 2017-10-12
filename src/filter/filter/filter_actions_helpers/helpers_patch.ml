(************************* MIT License HEADER ************************************
    Copyright ANSSI (2013-2015)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr],
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]
    Marion DAUBIGNARD [marion.daubignard@ssi.gouv.fr]

    This software is a computer program whose purpose is to implement
    a PKCS#11 proxy as well as a PKCS#11 filter with security features
    in mind. The project source tree is subdivided in six parts.
    There are five main parts:
      1] OCaml/C PKCS#11 bindings (using OCaml IDL).
      2] XDR RPC generators (to be used with ocamlrpcgen and/or rpcgen).
      3] A PKCS#11 RPC server (daemon) in OCaml using a Netplex RPC basis.
      4] A PKCS#11 filtering module used as a backend to the RPC server.
      5] A PKCS#11 client module that comes as a dynamic library offering
         the PKCS#11 API to the software.
    There is one "optional" part:
      6] Tests in C and OCaml to be used with client module 5] or with the
         bindings 1]

    Here is a big picture of how the PKCS#11 proxy works:

 ----------------------   --------  socket (TCP or Unix)  --------------------
| 3] PKCS#11 RPC server|-|2] RPC  |<+++++++++++++++++++> | 5] Client library  |
 ----------------------  |  Layer | [SSL/TLS optional]   |  --------          |
           |              --------                       | |2] RPC  | PKCS#11 |
 ----------------------                                  | |  Layer |functions|
| 4] PKCS#11 filter    |                                 |  --------          |
 ----------------------                                   --------------------
           |                                                        |
 ----------------------                                             |
| 1] PKCS#11 OCaml     |                                  { PKCS#11 INTERFACE }
|       bindings       |                                            |
 ----------------------                                       APPLICATION
           |
           |
 { PKCS#11 INTERFACE }
           |
 REAL PKCS#11 MIDDLEWARE
    (shared library)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright holders
    shall not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization.

    The current source code is part of the PKCS#11 filter 4] source tree:

           |
 ----------------------
| 4] PKCS#11 filter    |
 ----------------------
           |

    Project: PKCS#11 Filtering Proxy
    File:    src/filter/filter/filter_actions_helpers/helpers_patch.ml

************************** MIT License HEADER ***********************************)
(* Global value to tell if we want to segregate usage *)
let segregate_usage = ref false

let do_segregate_usage _ _ = (let info_string = Printf.sprintf "[User defined extensions]: Activating KEY USAGE SEGREGATION (encrypt/decrypt versus sign/verify)" in  print_debug info_string 1; segregate_usage := true; serialize (false, ()))

(* The critical attributes we focus on in all the patches *)
let critical_attributes key_segregation = if compare key_segregation true = 0 then
                           (* If we segregate key usage, we add the sign-verify in the critical attributes *)
                           [| 
                             {Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = [||]} ;
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
                             {Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_EXTRACTABLE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = [||]} ;
                             {Pkcs11.type_ = Pkcs11.cKA_NEVER_EXTRACTABLE; Pkcs11.value = [||]} ;
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
(************************************************************************************)
(* Get the critical attributes in one C_GetAttributeValue call *)
let filter_getAttributeValue_raw sessionh objecth the_critical_attributes =
  let (ret, attributes) = Backend.c_GetAttributeValue sessionh objecth the_critical_attributes in
  if (compare ret Pkcs11.cKR_OK = 0) || (compare ret Pkcs11.cKR_ATTRIBUTE_TYPE_INVALID = 0) then
    (* Expurge template from the non extracted attributes *)
    (Pkcs11.cKR_OK, expurge_template_from_irrelevant_attributes attributes) 
  else
    (* Return the error with purged values *)
    (ret, expurge_template_from_values attributes)

(* Get the critical attributes in multiple C_GetAttributeValue calls *)
let filter_getAttributeValue_multi_call sessionh objecth the_critical_attributes =
  let (ret, attributes) = Array.fold_left (
    fun (curr_ret, curr_attributes) attr ->
      (* If the last GetAttributeValue returned an error, skip the rest with empty values *)
      if compare curr_ret Pkcs11.cKR_OK <> 0 then
            (curr_ret, Array.append curr_attributes [| attr |])
      else
        let (the_ret, attr_array) =  Backend.c_GetAttributeValue sessionh objecth [| attr |] in
        if compare the_ret Pkcs11.cKR_OK = 0 then
          (* It is ok, we have the value, push the result in the array *)
          (Pkcs11.cKR_OK, Array.append curr_attributes attr_array)
        else
          if compare the_ret Pkcs11.cKR_ATTRIBUTE_TYPE_INVALID = 0 then
            (* We cannot extract the attribute, just add it empty to the attribute list *)
            (Pkcs11.cKR_OK, Array.append curr_attributes [| attr |])
          else
            (* We have another error, report it and add the attribute empty *)
            (the_ret, Array.append curr_attributes [| attr |])
  ) (Pkcs11.cKR_OK, [||]) the_critical_attributes in
  if compare ret Pkcs11.cKR_OK = 0 then
    (Pkcs11.cKR_OK, attributes)
  else
    (* Return the error with purged values *)
    (ret, expurge_template_from_values attributes)

let filter_getAttributeValue sessionh objecth the_critical_attributes = 
  (filter_getAttributeValue_multi_call sessionh objecth the_critical_attributes)



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

let is_existing_object_class_key sessionh objecth =
  (* Get the CKA_CLASS attributes *)
  let cka_class_template = [| {Pkcs11.type_ = Pkcs11.cKA_CLASS; Pkcs11.value = [||]} |] in
  let (ret, attributes) = Backend.c_GetAttributeValue sessionh objecth cka_class_template in
  if compare ret Pkcs11.cKR_OK = 0 then
    let (ret, attributes) = Backend.c_GetAttributeValue sessionh objecth attributes in    
    if compare ret Pkcs11.cKR_OK = 0 then
      (* We have got the class, now check it *)
      (is_object_class_key attributes)
    else
      (* GetAttributeValue returned an error, fail with an exception *)
      let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_CLASS (this should not happen ...)\n" in netplex_log_critical s; failwith s
  else
    (* GetAttributeValue returned an error, fail with an exception *)
    let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_CLASS (this should not happen ...)\n" in netplex_log_critical s; failwith s

(* Check if two templates are compatible regarding their defined attributes *)
let check_are_templates_nonconforming fun_name attributes new_attributes =
  let check = Array.fold_left (
    fun curr_check curr_attr ->
      let tmp_check = Array.fold_left (
        fun tmp_check curr_new_attr ->
          if (compare curr_new_attr.Pkcs11.type_ curr_attr.Pkcs11.type_ = 0) &&
             (compare curr_new_attr.Pkcs11.value curr_attr.Pkcs11.value <> 0) then
            let s = Printf.sprintf "%s" (Pkcs11.sprint_template_array [| curr_new_attr; curr_attr|]) in
            let _ = print_debug s 1 in
            (tmp_check || true)
          else
            (tmp_check || false)
      ) false new_attributes in
      (curr_check || tmp_check)
  ) false attributes in
  (check)

(* Check if attribute is set to TRUE in an attributes array *)
let check_is_attribute_set fun_name the_attr attributes =
  let check = Array.fold_left (
    fun check_tmp attr ->
      if (compare attr.Pkcs11.type_ the_attr = 0) &&                  
         (compare attr.Pkcs11.value (Pkcs11.bool_to_char_array Pkcs11.cK_TRUE) = 0) then
        (check_tmp || true)
      else
        (check_tmp || false)
  ) false attributes in
  (check)

(* Check if a given attribute is asked in the given template *)
let check_is_attribute_asked fun_name the_attr attributes =
  let check = Array.fold_left (
    fun check_tmp attr ->
      if (compare attr.Pkcs11.type_ the_attr = 0) then
        (check_tmp || true)
      else
        (check_tmp || false)
  ) false attributes in
  (check)

(* Stricky attributes checks *)
let check_for_sticky_attribute fun_name old_attribute new_attribute the_sticky_attributes =
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
    ) false the_sticky_attributes in
    (check)
  else
    (false)

(*** Sticky attributes helper ***)
let detect_sticky_attributes fun_name attributes new_attributes the_sticky_attributes =
  let check = Array.fold_left (
    fun curr_check curr_attr ->
      let tmp_check = Array.fold_left (
        fun tmp_check curr_new_attr ->
          (tmp_check || (check_for_sticky_attribute fun_name curr_attr curr_new_attr the_sticky_attributes))
      ) false new_attributes in
      (curr_check || tmp_check)
  ) false attributes in
  (check)

(*** Conflicting attributes helper ***)
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

let detect_conflicting_attributes function_name attributes new_attributes the_conflicting_attribute =
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
          (Pkcs11.match_cKA_value first_a_type) (Pkcs11.sprint_bool_attribute_value (Pkcs11.char_array_to_bool first_a_value)) (Pkcs11.match_cKA_value second_a_type) (Pkcs11.sprint_bool_attribute_value (Pkcs11.char_array_to_bool second_a_value)) in
          let _ = print_debug info_string 1 in
          (curr_check || block_it)
        else
          (curr_check || block_it)
  ) false the_conflicting_attribute in
  (check)

(* Function to check for conflicting attributes on existing objects *)
let detect_conflicting_attributes_on_existing_object function_name sessionh objecth the_conflicting_attribute =
  let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
  if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
    if (compare ret Pkcs11.cKR_OK <> 0) then
      (true)
    else
      let s = Printf.sprintf "[User defined extensions] %s CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): in CONFLICTING_ATTRIBUTES\n" function_name in netplex_log_critical s; failwith s;
  else
    let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
    if compare ret Pkcs11.cKR_OK <> 0 then
      (true)
    else
      let check = detect_conflicting_attributes function_name templates_values [||] the_conflicting_attribute in
      (check)


let execute_external_command command data argvs env =
  let buffer_size = 2048 in
  let buffer_stdout = Buffer.create buffer_size in
  let buffer_stderr = Buffer.create buffer_size in
  (* Append the argvs to the command *)
  let command = String.concat " " (List.concat [ [command]; Array.to_list argvs ]) in
  let string = Bytes.create buffer_size in
  let (in_channel_stdout, out_channel, in_channel_stderr) = Unix.open_process_full command [||] in
  (* Write data to out_channel *)
  output out_channel data 0 (String.length data);
  (* Close out_channel to tell it's over *)
  flush out_channel;
  close_out out_channel;
  (* Read result data on the in_channel stdout *)
  let chars_read_stdout = ref 1 in
  while !chars_read_stdout <> 0 do
    chars_read_stdout := input in_channel_stdout string 0 buffer_size;
    Buffer.add_substring buffer_stdout string 0 !chars_read_stdout
  done;
  (* Command done, read stderr *)
  let chars_read_stderr = ref 1 in
  while !chars_read_stderr <> 0 do
    chars_read_stderr := input in_channel_stderr string 0 buffer_size;
    Buffer.add_substring buffer_stderr string 0 !chars_read_stderr
  done;
  let ret_status = Unix.close_process_full (in_channel_stdout, out_channel, in_channel_stderr) in
  match ret_status with
    Unix.WEXITED(0) -> (true, Buffer.contents buffer_stdout, Buffer.contents buffer_stderr)
   | _ -> (false, "", Buffer.contents buffer_stderr)
