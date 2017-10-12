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
    File:    src/filter/filter/filter.ml

************************** MIT License HEADER ***********************************)
(******************* Filter main functions *******************)
open Filter_common
open Filter_actions
open Filter_configuration

(* Exceptions *)
exception Pkcs11_inconsistency
exception Loop_overflow

let print_hex_array_to_string = fun a ->  String.concat "" (Array.to_list (Array.map (fun b -> let s = Printf.sprintf "%02x" (int_of_char b) in (s)) a))

(*** High level helper functions *****)
let apply_blacklist original_list forbidden_list =
  (* We have two lists: we want to return a list with the original *)
  (* list without the elements in the forbidden list               *)
  (* For each element in the original list, check if it is in the forbidden one *)
  let filtered_list = List.filter (fun a -> check_element_in_list forbidden_list a = false) original_list in
  (filtered_list)

let apply_blacklist_all_lists original_list forbidden_list = 
 print_mechanisms original_list "Filtering mechanisms, got:" 1;
 let filtered_list = List.fold_left (fun curr_filtered_list (alias_regexp, curr_list) -> if check_regexp alias_regexp (get !current_module) = true then apply_blacklist curr_filtered_list curr_list else curr_filtered_list) original_list forbidden_list in
 let _ = print_mechanisms filtered_list "Filtered mechanisms:" 1 in
 (filtered_list)

let check_forbidden_mechanism_in_list mechanism forbidden_list_alias =
  let associated_list = try Some (get_associated_list (get !current_module) forbidden_list_alias)
    with Find_list_except -> (* If no association was found, skip it by returning that there is no match *) None in
  if compare associated_list None = 0 then
    (false)
  else
    (check_element_in_list (get associated_list) mechanism)

(* Go through all the sub lists and check if the element fits by applying logical and *)
let check_forbidden_mechanism_in_all_lists mechanism forbidden_list_alias =
  let check = List.fold_left (fun curr_bool b -> let check = check_forbidden_mechanism_in_list mechanism [b] in (curr_bool || check)) false forbidden_list_alias in
  if compare check true = 0 then
  begin
    let info_string = Printf.sprintf "mechanism '%s' has been found in the forbidden list for alias '%s' (it is FILTERED)" (Pkcs11.match_cKM_value mechanism) (get !current_module) in
    let _ = print_debug info_string 1 in
    (check)
  end
  else
  begin
    let info_string = Printf.sprintf "mechanism '%s' has not been found in the forbidden list for alias '%s' (it is *not* filtered)" (Pkcs11.match_cKM_value mechanism) (get !current_module) in
    let _ = print_debug info_string 2 in
    (check)
  end


(* Check in *all* lists if a regexp element is indeed satisfied *)
let check_regexp_element_in_all_lists the_module allowed_list the_label search_type = 
  let (cnt, bool_res) = List.fold_left (fun (found_count, curr_bool) (alias_regexp, curr_list) -> if check_regexp alias_regexp the_module = true then (found_count+1, curr_bool || (check_regexp_element_in_list curr_list the_label)) else (found_count, curr_bool)) (0, false) allowed_list in
  (* This is the case where no rule has matched our alias: we return true *)
  if compare cnt 0 = 0 then
  begin
    (* For a forbidden search, we fallback on 'false' when there is no match *)
    if compare search_type "forbidden" = 0 then
      (false)
    (* For an allowed seatch, we fallback on 'true' when there is no match *)
    else
      (true)
  end
  else
    (bool_res)
  

(* Check for a given object if its label is in the allowed list *)
let check_object_label session object_handle allowed_list_alias function_name =
  (* If we don't filter labels, no need to proceed *)
  if compare !allowed_labels [] = 0 then
    (true)
  else
  begin
    (* Get the label of the object *)
    let label_template = [| { Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = [||] } |]  in 
    let (_, label_template) = Backend.c_GetAttributeValue session object_handle label_template in
    let (ret_value, label_template) = Backend.c_GetAttributeValue session object_handle label_template in
    if compare ret_value Pkcs11.cKR_OK = 0 then
    begin
      (* We got the label, check it against the regexp *)
      let check_bool = check_regexp_element_in_all_lists (get !current_module) allowed_list_alias (Pkcs11.char_array_to_string label_template.(0).Pkcs11.value) "allowed" in
      if check_bool = true then
        begin
        (* true = we don't filter the label            *)
        let info_string = Printf.sprintf "%s: label '%s' is not filtered for alias '%s'" function_name (Pkcs11.char_array_to_string label_template.(0).Pkcs11.value) (get !current_module) in
        let _ = print_debug info_string 1 in
        (check_bool)
        end
      else
        begin
        (* false = we filter the label *)
        let info_string = Printf.sprintf "%s: label '%s' is FILTERED for alias '%s'" function_name (Pkcs11.char_array_to_string label_template.(0).Pkcs11.value) (get !current_module) in
        let _ = print_debug info_string 1 in
        (check_bool)
        end
    end
    else
      (* We couldn't extract the label of the object, we don't return it *)
      (false)
  end
   
let apply_allowed_label_filter session object_handles_array allowed_list_alias = 
  let filtered_list = List.filter (fun a -> check_object_label session a allowed_list_alias "C_FindObjects" = true) (Array.to_list object_handles_array) in
  (Array.of_list filtered_list)

let check_label_on_object_creation ckattributearray_ allowed_list_alias function_name =
  (* If we don't filter labels, no need to proceed *)
  if compare !allowed_labels [] = 0 then
    (false)
  else
    (* For each template, check if it is a label *)
    let (check_it, counter) = Array.fold_left (fun (previous_bool, previous_counter) a -> 
                if compare a.Pkcs11.type_ Pkcs11.cKA_LABEL = 0 then
                begin
                  (* If we have a label, check if it is in the allowed list *)
                  let check_bool = check_regexp_element_in_all_lists (get !current_module) allowed_list_alias (Pkcs11.char_array_to_string a.Pkcs11.value) "allowed" in
                  if check_bool = true then
                  begin
                    let info_string = Printf.sprintf "%s: label '%s' is not filtered on creation for alias '%s'" function_name (Pkcs11.char_array_to_string a.Pkcs11.value) (get !current_module) in
                    let _ = print_debug info_string 1 in
                    (false || previous_bool, previous_counter+1)
                  end
                  else
                  begin
                    let info_string = Printf.sprintf "%s: label '%s' is FILTERED on creation for alias '%s'" function_name (Pkcs11.char_array_to_string a.Pkcs11.value) (get !current_module) in
                    let _ = print_debug info_string 1 in
                    (true || previous_bool, previous_counter+1)
                  end
                end
                else
                  (previous_bool, previous_counter)
             ) (false, 0) ckattributearray_ in
    if compare counter 0 = 0 then
      (* If no label has been provided, do not block the creation *)
      (false)
    else
      (check_it)

(* Check for a given object if its id is in the allowed list *)
let check_object_id session object_handle allowed_list_alias function_name =
  (* If we don't filter ids, no need to proceed *)
  if compare !allowed_ids [] = 0 then
    (true)
  else
  begin
    (* Get the id of the object *)
    let id_template = [| { Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = [||]} |]  in 
    let (_, id_template) = Backend.c_GetAttributeValue session object_handle id_template in
    let (ret_value, id_template) = Backend.c_GetAttributeValue session object_handle id_template in
    if compare ret_value Pkcs11.cKR_OK = 0 then
    begin
      (* We got the id, check it against the regexp *)
      let check_bool = check_regexp_element_in_all_lists (get !current_module) allowed_list_alias (print_hex_array_to_string id_template.(0).Pkcs11.value) "allowed" in
      if check_bool = true then
      begin
        (* true = we don't filter the id *)
        let info_string = Printf.sprintf "%s: id '%s' is *not* filtered for alias '%s'" function_name (print_hex_array_to_string id_template.(0).Pkcs11.value) (get !current_module) in
        let _ = print_debug info_string 2 in
        (check_bool)
        end
      else
        begin
        (* false = we filter the id *)
        let info_string = Printf.sprintf "%s: id '%s' is FILTERED for alias '%s'" function_name (print_hex_array_to_string id_template.(0).Pkcs11.value) (get !current_module) in
        let _ = print_debug info_string 1 in
        (check_bool)
        end
    end
    else
      (* We couldn't extract the id of the object, we don't return it *)
      (false)
  end

let apply_allowed_id_filter session object_handles_array allowed_list_alias = 
  let filtered_list = List.filter (fun a -> check_object_id session a allowed_list_alias "C_FindObjects" = true) (Array.to_list object_handles_array) in
  (Array.of_list filtered_list)

let check_id_on_object_creation ckattributearray_ allowed_list_alias function_name =
  (* If we don't filter ids, no need to proceed *)
  if compare !allowed_ids [] = 0 then
    (false)
  else
    (* For each template, check if it is an ID *)
    let (check_it, counter) = Array.fold_left (fun (previous_bool, previous_counter) a -> 
                if compare a.Pkcs11.type_ Pkcs11.cKA_ID = 0 then
                begin
                  (* If we have a label, check if it is in the allowed list *)
                  let check_bool = check_regexp_element_in_all_lists (get !current_module) allowed_list_alias (print_hex_array_to_string a.Pkcs11.value) "allowed" in
                  if check_bool = true then
                  begin
                    let info_string = Printf.sprintf "%s: id '%s' is *not* filtered on creation for alias '%s'" function_name (print_hex_array_to_string a.Pkcs11.value) (get !current_module) in
                    let _ = print_debug info_string 2 in
                    (false || previous_bool, previous_counter+1)
                  end
                  else
                  begin
                    let info_string = Printf.sprintf "%s: id '%s' is FILTERED on creation for alias '%s'" function_name (print_hex_array_to_string a.Pkcs11.value) (get !current_module) in
                    let _ = print_debug info_string 1 in
                    (true || previous_bool, previous_counter+1)
                  end
                end
                else
                  (previous_bool, previous_counter)
             ) (false, 0) ckattributearray_ in
    if compare counter 0 = 0 then
      (* Do not block the creation if no id has been provided *)
      (false)
    else
      (check_it)

let remove_elements_from_array array_ref to_remove = 
  let ref_list = Array.to_list !array_ref in
  let to_remove_list = Array.to_list to_remove in
  let filtered_list = List.filter (fun a -> check_element_in_list to_remove_list a = false) ref_list in
  array_ref := Array.of_list filtered_list;
  ()

let pickup_elements_in_array array_ref count = 
  (* Exract count elements from the array *)
  let extracted = (try Array.sub !array_ref 0 (Nativeint.to_int count)
    (* If count is larger than the size, we return the whole *)
    with Invalid_argument _ -> (Array.copy !array_ref))  in
  let _ = remove_elements_from_array array_ref extracted in
  (extracted)


(* Check if a PKCS#11 function is filtered *)
(* return true if yes, false if no         *)
let check_function_in_forbidden_functions_list function_name forbidden_functions_list = 
  if compare !current_module None = 0 then
    (* Out from here if there is no module already loaded *)
    (false)
  else
    (check_regexp_element_in_all_lists (get !current_module) forbidden_functions_list function_name "forbidden")

(* Check if we are enforcing RO sessions *)
let check_enforce_ro_sessions_for_alias the_list =
  (* We only check for ONE associated list since there is no reason to apply multiple rules here! *)
  (* (we have booleans) *)
  let check = try get_associated_list (get !current_module) the_list 
  (* By default, if the alias has not been found, we don't enforce RO sessions *)
  with Find_list_except -> 
    let info_string = Printf.sprintf "Alias '%s' not found in enforce RO list: not applying any enforcement!" (get !current_module) in
    print_debug info_string 2; (false)
  in
  if check = true then
  begin
    let info_string = Printf.sprintf "Enforcing RO session in OpenSession for alias '%s'" (get !current_module) in
    print_debug info_string 1;
    (check) 
  end
  else
    let info_string = Printf.sprintf "*NOT* enforcing RO session in OpenSession for alias '%s'" (get !current_module) in
    print_debug info_string 2;
    (check)

(* Check if we are forbiding admin operations *)
let check_forbid_admin_for_alias the_list =
  (* We only check for ONE associated list since there is no reason to apply multiple rules here! *)
  (* (we have booleans) *)
  let check = try get_associated_list (get !current_module) the_list 
  (* By default, if the alias has not been found, we don't enforce RO sessions *)
  with Find_list_except -> 
    let info_string = Printf.sprintf "Alias '%s' not found in forbid admin list: not applying the rule!" (get !current_module) in
    print_debug info_string 2; (false)
  in
  if check = true then
  begin
    let info_string = Printf.sprintf "Forbidding SO login for alias '%s'" (get !current_module) in
    print_debug info_string 1;
    (check) 
  end
  else
    let info_string = Printf.sprintf "*NOT* forbidding SO login for alias '%s'" (get !current_module) in
    print_debug info_string 2;
    (check)

(* Check if we are removing padding oracles  *)
let check_remove_padding_oracles the_list the_type =
  let check = check_regexp_element_in_all_lists (get !current_module) the_list the_type "forbidden" in
   if check = true then
  begin
    let info_string = Printf.sprintf "Removing padding oracles for alias '%s' and operation '%s'" (get !current_module) the_type in
    print_debug info_string 1;
    (check)
  end
  else
    let info_string = Printf.sprintf "*NOT* removing padding oracles for alias '%s' and operation '%s'" (get !current_module) the_type in
    print_debug info_string 2;
    (check)
 
(**** Checking the actions given a trigger ****)
let check_trigger_and_action function_trigger the_actions_list argument = 
  (* For all the aliases, get the actions for the given functio_trigger *)
  let current_actions = List.fold_left 
    (fun constructing_list (a, b) -> 
      (* check if the current module is concerned by the alias *)
      if check_regexp a (get !current_module) = true then
        (* Iterate through the list of couples (function, action) *)
        (List.fold_left (fun constructing_list (c, d) -> if check_regexp function_trigger c = true then 
        (List.concat [constructing_list; [d]]) else (constructing_list)) constructing_list b)
    else
      (constructing_list)
    ) [] the_actions_list in
  if List.length current_actions = 0 then
    (* If we have no action, return a fake ret value         *)
    (serialize (false, ()))
  else
    (* Now apply all the actions serially                    *)
    (* If an action returns a value along the way, we return *)
    (* it and stop the execution flow of other actions       *)
    let final_ret = List.fold_left 
    (fun last_action_ret action -> 
      let (stop, _) = deserialize last_action_ret in
        if stop = true then
          (* The last action returned something: return its value without *)
          (* executing the other actions                                  *)
          (last_action_ret)
        else
          let info_string = Printf.sprintf "Executing user defined action '%s' on trigger '%s' for alias '%s'" action function_trigger (get !current_module) in
          print_debug info_string 1; 
          (execute_action function_trigger action (serialize argument))
    ) (serialize (false, ())) current_actions in
    (final_ret)

(** Apply pre actions **)
let apply_pre_filter_actions function_name  args =
  deserialize (check_trigger_and_action function_name !filter_actions_pre args)

(** Apply post actions **)
let apply_post_filter_actions function_name  args =
  deserialize (check_trigger_and_action function_name !filter_actions_post args)

  
(***** Our filterfing functions ******)
(* Filter the mechanisms list returned by C_GetMechanismList *)
(* with respect to our blacklist                             *)
let filter_c_GetMechanismList ret mechanism_list count =
  flush stdout;
  if !current_module = None then
  begin
    (* The module has not been initialized yet: passthrough  *)
    (ret, mechanism_list, count)
  end
  else
  begin
    let filtered_mechanism_list = Array.of_list (apply_blacklist_all_lists (Array.to_list mechanism_list) !forbidden_mechanisms) in
    (* If the resulting mechanism list is bigger thant the count, return the real count if count was 0 or CKR_BUFFER_TOO_SMALL *)
    if Array.length filtered_mechanism_list > (Nativeint.to_int count) then
    begin
      if compare count 0n = 0 then
        (Pkcs11.cKR_OK, [| |], Nativeint.of_int (Array.length filtered_mechanism_list))
      else
        (Pkcs11.cKR_BUFFER_TOO_SMALL, [| |], Nativeint.of_int (Array.length filtered_mechanism_list))
    end
    else
      (ret, filtered_mechanism_list, Nativeint.of_int (Array.length filtered_mechanism_list))
  end




(***** PKCS#11 functions *****)
(*************************************************************************)
(* We don't block SetupArch *)
let c_LoadModule path =
  (* NB: the check function in forbidden list is superfluous since *)
  (* no module is already loaded at this point!                    *)
  (* Check the function *)
  (* Check the alias *)
  let found_alias = try Filter_configuration.get_module_alias (Pkcs11.char_array_to_string path) 
    with Modules_except -> raise Modules_except in
  let ret = Backend.c_LoadModule (Pkcs11.string_to_char_array found_alias) in
  let _ = if compare ret Pkcs11.cKR_OK = 0 then current_module := Some (Pkcs11.char_array_to_string path) else () in
  (ret)

(*************************************************************************)
(* We don't block SetupArch *)
let c_SetupArch arch =
  Backend.c_SetupArch arch

(*************************************************************************)
let c_Initialize () =
  (* If no module is defined, return CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_GENERAL_ERROR)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Initialize" (()) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Initialize" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Initialize" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Initialize" (()) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Initialize ()
 
(*************************************************************************)
let c_GetInfo () =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, {Pkcs11.ck_info_cryptoki_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_info_manufacturer_id = [| |]; Pkcs11.ck_info_flags = 0n; Pkcs11.ck_info_library_description = [| |]; Pkcs11.ck_info_library_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}})
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetInfo" (()) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetInfo" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetInfo" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, {Pkcs11.ck_info_cryptoki_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_info_manufacturer_id = [| |]; Pkcs11.ck_info_flags = 0n; Pkcs11.ck_info_library_description = [| |]; Pkcs11.ck_info_library_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}})
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetInfo" (()) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GetInfo ()
 
(*************************************************************************)
let c_GetSlotList token_present count =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |], 0n) 
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetSlotList" (token_present, count) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetSlotList" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetSlotList" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |], 0n)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetSlotList" (token_present, count) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GetSlotList token_present count
 
(*************************************************************************)
let c_GetSlotInfo ckslotidt_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, {Pkcs11.ck_slot_info_slot_description = [| |]; Pkcs11.ck_slot_info_manufacturer_id = [| |]; Pkcs11.ck_slot_info_flags = 0n; Pkcs11.ck_slot_info_hardware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_slot_info_firmware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}})
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetSlotInfo" (ckslotidt_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetSlotInfo" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetSlotInfo" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, {Pkcs11.ck_slot_info_slot_description = [| |]; Pkcs11.ck_slot_info_manufacturer_id = [| |]; Pkcs11.ck_slot_info_flags = 0n; Pkcs11.ck_slot_info_hardware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_slot_info_firmware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}})
    else
      Backend.c_GetSlotInfo ckslotidt_
 
(*************************************************************************)
let c_GetTokenInfo ckslotidt_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, {Pkcs11.ck_token_info_label = [| |]; Pkcs11.ck_token_info_manufacturer_id = [| |]; Pkcs11.ck_token_info_model = [| |]; Pkcs11.ck_token_info_serial_number = [| |]; Pkcs11.ck_token_info_flags = 0n; Pkcs11.ck_token_info_max_session_count = 0n; Pkcs11.ck_token_info_session_count = 0n; Pkcs11.ck_token_info_max_rw_session_count = 0n; Pkcs11.ck_token_info_rw_session_count = 0n; Pkcs11.ck_token_info_max_pin_len = 0n; Pkcs11.ck_token_info_min_pin_len = 0n; Pkcs11.ck_token_info_total_public_memory = 0n; Pkcs11.ck_token_info_free_public_memory = 0n; Pkcs11.ck_token_info_total_private_memory = 0n; Pkcs11.ck_token_info_free_private_memory = 0n; Pkcs11.ck_token_info_hardware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_token_info_firmware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_token_info_utc_time = [| |]})
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetTokenInfo" (ckslotidt_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetTokenInfo" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetTokenInfo" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, {Pkcs11.ck_token_info_label = [| |]; Pkcs11.ck_token_info_manufacturer_id = [| |]; Pkcs11.ck_token_info_model = [| |]; Pkcs11.ck_token_info_serial_number = [| |]; Pkcs11.ck_token_info_flags = 0n; Pkcs11.ck_token_info_max_session_count = 0n; Pkcs11.ck_token_info_session_count = 0n; Pkcs11.ck_token_info_max_rw_session_count = 0n; Pkcs11.ck_token_info_rw_session_count = 0n; Pkcs11.ck_token_info_max_pin_len = 0n; Pkcs11.ck_token_info_min_pin_len = 0n; Pkcs11.ck_token_info_total_public_memory = 0n; Pkcs11.ck_token_info_free_public_memory = 0n; Pkcs11.ck_token_info_total_private_memory = 0n; Pkcs11.ck_token_info_free_private_memory = 0n; Pkcs11.ck_token_info_hardware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_token_info_firmware_version = {Pkcs11.major = '0'; Pkcs11.minor = '0'}; Pkcs11.ck_token_info_utc_time = [| |]})
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetTokenInfo" (ckslotidt_) in
      if take_ret = true then
        (ret)
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_GetTokenInfo" (ckslotidt_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_GetTokenInfo ckslotidt_

(*************************************************************************)
let c_WaitForSlotEvent ckflagst_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, -1n)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_WaitForSlotEvent" (ckflagst_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_WaitForSlotEvent" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_WaitForSlotEvent" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, -1n)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_WaitForSlotEvent" (ckflagst_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_WaitForSlotEvent ckflagst_
 
(*************************************************************************)
let c_GetMechanismList ckslotidt_ count =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |], 0n)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetMechanismList" (ckslotidt_, count) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetMechanismList" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetMechanismList" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |], 0n)
    else
      (* Do we filter mechanisms? *)
      if List.length !forbidden_mechanisms > 0 then
        begin
        (* We always want to ask for the real number of mechanisms *)
        let mycount = 
	  let (ret, _, newcount) = Backend.c_GetMechanismList ckslotidt_ 0n in 
	  if compare ret Pkcs11.cKR_OK = 0 then newcount else count
        in
        let (ret, mechanism_list, _) = Backend.c_GetMechanismList ckslotidt_ mycount in
        (* We filter the list if everything went OK *)
        if compare ret Pkcs11.cKR_OK = 0 then
          (* Late actions after other checks *)
          let (take_ret, return) =  apply_post_filter_actions "C_GetMechanismList" (ckslotidt_, count) in
          if take_ret = true then
            (return)
          else
	    let (filtered_ret, filtered_list, filtered_count) = filter_c_GetMechanismList ret mechanism_list count in
	    (filtered_ret, filtered_list, filtered_count)
        else
          (* Late actions after other checks *)
          let (take_ret, return) =  apply_post_filter_actions "C_GetMechanismList" (ckslotidt_, count) in
          if take_ret = true then
            (return)
          else
 	    (ret, mechanism_list, count)
        end
      else
        (* If we don't filter mechanisms, passthrough to the backend *)
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_GetMechanismList" (ckslotidt_, count) in
        if take_ret = true then
          (ret)
        else
          Backend.c_GetMechanismList ckslotidt_ count

(*************************************************************************)
let c_GetMechanismInfo ckslotidt_ ckmechanismtypet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, {Pkcs11.ck_mechanism_info_min_key_size = 0n; Pkcs11.ck_mechanism_info_max_key_size = 0n; Pkcs11.ck_mechanism_info_flags = 0n})
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetMechanismInfo" (ckslotidt_, ckmechanismtypet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetMechanismInfo" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetMechanismList" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, {Pkcs11.ck_mechanism_info_min_key_size = 0n; Pkcs11.ck_mechanism_info_max_key_size = 0n; Pkcs11.ck_mechanism_info_flags = 0n})
    else
      (* Check if the asked mechanism is in the forbidden list *)
      if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
	begin
	let s = Printf.sprintf "Mechanism %s has been filtered in C_GetMechanismInfo" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	print_debug s 1;
	(Pkcs11.cKR_MECHANISM_INVALID, {Pkcs11.ck_mechanism_info_min_key_size = 0n; Pkcs11.ck_mechanism_info_max_key_size = 0n; Pkcs11.ck_mechanism_info_flags = 0n})
	end
      else
	(* Late actions after other checks *)
	let (take_ret, ret) =  apply_post_filter_actions "C_GetMechanismInfo" (ckslotidt_, ckmechanismtypet_) in
	if take_ret = true then
	  (ret)
	else
	  Backend.c_GetMechanismInfo ckslotidt_ ckmechanismtypet_

(*************************************************************************)
let c_InitToken ckslotidt_  so_pin label =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED) 
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_InitToken" (ckslotidt_, so_pin, label) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_InitToken" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_InitToken" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_InitToken" (ckslotidt_, so_pin, label) in
      if take_ret = true then
        (ret)
      else
        Backend.c_InitToken ckslotidt_  so_pin label
 
(*************************************************************************)
let c_InitPIN cksessionhandlet_ pin =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_InitPIN" (cksessionhandlet_, pin) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_InitPIN" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_InitPIN" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_InitPIN" (cksessionhandlet_, pin) in
      if take_ret = true then
        (ret)
      else
        Backend.c_InitPIN cksessionhandlet_ pin
 
(*************************************************************************)
let c_SetPIN cksessionhandlet_ old_pin  new_pin =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SetPIN" (cksessionhandlet_, old_pin, new_pin) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SetPIN" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SetPIN" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SetPIN" (cksessionhandlet_, old_pin, new_pin) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SetPIN cksessionhandlet_ old_pin  new_pin
 
(*************************************************************************)
let c_OpenSession ckslotid_ ckflagst_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE) 
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_OpenSession" (ckslotid_, ckflagst_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_OpenSession" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_OpenSession" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check if we are enforcing the RO session *)
      let new_flags = if check_enforce_ro_sessions_for_alias !enforce_ro_sessions = true then
      Nativeint.logand ckflagst_ (Nativeint.lognot Pkcs11.cKF_RW_SESSION)
      else  ckflagst_ in
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_OpenSession" (ckslotid_, new_flags) in
      if take_ret = true then
        (ret)
      else
        Backend.c_OpenSession ckslotid_ new_flags
 
(*************************************************************************)
let c_CloseSession cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_CloseSession" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_CloseSession" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_CloseSession" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_CloseSession" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_CloseSession cksessionhandlet_
 
(*************************************************************************)
let c_CloseAllSessions ckslotidt_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_CloseAllSessions" (ckslotidt_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_CloseAllSessions" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_CloseAllSessions" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_CloseAllSessions" (ckslotidt_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_CloseAllSessions ckslotidt_
 
(*************************************************************************)
let c_GetSessionInfo cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, {Pkcs11.ck_session_info_slot_id = -1n; Pkcs11.ck_session_info_state = 0n; ck_session_info_flags = 0n; ck_session_info_device_error = 0n})
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetSessionInfo" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetSessionInfo" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetSessionInfo" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, {Pkcs11.ck_session_info_slot_id = -1n; Pkcs11.ck_session_info_state = 0n; ck_session_info_flags = 0n; ck_session_info_device_error = 0n})
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetSessionInfo" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GetSessionInfo cksessionhandlet_

(*************************************************************************)
let c_GetOperationState cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetOperationState" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetOperationState" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetOperationState" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetOperationState" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GetOperationState cksessionhandlet_
 
(*************************************************************************)
let c_SetOperationState cksessionhandlet_ state encryption_handle authentication_handle  =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SetOperationState" (cksessionhandlet_, state, encryption_handle, authentication_handle) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SetOperationState" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SetOperationState" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SetOperationState" (cksessionhandlet_, state, encryption_handle, authentication_handle) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SetOperationState cksessionhandlet_ state encryption_handle authentication_handle 

(*************************************************************************)
let c_Login cksessionhandlet_ ckusertypet_ pin =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Login" (cksessionhandlet_, ckusertypet_, pin) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Login" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Login" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
    begin
      (* If we forbid admin operations, we won't let any SO login *)
      if check_forbid_admin_for_alias !forbid_admin_operations = true then
      begin
        (* If we forbid admin operations, we can't allow logins other than regular user ... *)
        if (compare ckusertypet_ Pkcs11.cKU_SO = 0) || (compare ckusertypet_ Pkcs11.cKU_CONTEXT_SPECIFIC = 0) then
          (Pkcs11.cKR_USER_TYPE_INVALID)
        else
          (* Late actions after other checks *)
          let (take_ret, ret) =  apply_post_filter_actions "C_Login" (cksessionhandlet_, ckusertypet_, pin) in
          if take_ret = true then
            (ret)
          else
            Backend.c_Login cksessionhandlet_ ckusertypet_ pin
      end
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_Login" (cksessionhandlet_, ckusertypet_, pin) in
        if take_ret = true then
          (ret)
        else
          Backend.c_Login cksessionhandlet_ ckusertypet_ pin
    end
 
(*************************************************************************)
let c_Logout cksessionhandlet =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Logout" (cksessionhandlet) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Logout" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Logout" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Logout" (cksessionhandlet) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Logout cksessionhandlet

(*************************************************************************)
let c_Finalize () =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Finalize" (()) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Finalize" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Finalize" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Finalize" (()) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Finalize ()
 
(*************************************************************************)
let c_CreateObject cksessionhandlet_ ckattributearray_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_CreateObject" (cksessionhandlet_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_CreateObject" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_CreateObject" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for the possible label or id blocking *)
      let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_CreateObject" in
      let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_CreateObject") in
      if check_label_id = true then
	(Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)
      else
	(* Late actions after other checks *)
	let (take_ret, ret) =  apply_post_filter_actions "C_CreateObject" (cksessionhandlet_, ckattributearray_) in
	if take_ret = true then
	  (ret)
	else
	  Backend.c_CreateObject cksessionhandlet_ ckattributearray_
  
(*************************************************************************)
let c_CopyObject cksessionhandlet_ ckobjecthandlet_ ckattributearray_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_CopyObject" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_CopyObject" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_CopyObject" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_CopyObject" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_CopyObject" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)
      else
        (* Check for the possible label or id blocking *)
        let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_CopyObject" in
        let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_CopyObject") in
        if check_label_id = true then
	  (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)
        else
  	  (* Late actions after other checks *)
  	  let (take_ret, ret) =  apply_post_filter_actions "C_CopyObject" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
  	  if take_ret = true then
  	    (ret)
  	  else
  	    Backend.c_CopyObject cksessionhandlet_ ckobjecthandlet_ ckattributearray_
 
(*************************************************************************)
let c_DestroyObject cksessionhandlet_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DestroyObject" (cksessionhandlet_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
  (* Check the function *)
  let check = check_function_in_forbidden_functions_list "C_DestroyObject" !forbidden_functions in
  if check = true then
    let _ = print_debug "Blocking function C_DestroyObject" 1 in
    (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
  else
    (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_DestroyObject" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_DestroyObject" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_DestroyObject" (cksessionhandlet_, ckobjecthandlet_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_DestroyObject cksessionhandlet_ ckobjecthandlet_

(*************************************************************************)
let c_GetObjectSize cksessionhandlet_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, -1n)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetObjectSize" (cksessionhandlet_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetObjectSize" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetObjectSize" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, -1n)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_GetObjectSize" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_GetObjectSize" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID, -1n)
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_GetObjectSize" (cksessionhandlet_, ckobjecthandlet_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_GetObjectSize cksessionhandlet_ ckobjecthandlet_
 
(*************************************************************************)
let c_GetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetAttributeValue" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetAttributeValue" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetAttributeValue" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_GetAttributeValue" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_GetAttributeValue" = false) then
	(* Here, we call c_GetAttributeValue, we might want to return what the middleware has returned if there has been an error *)
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_GetAttributeValue" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
        let (return, template) =
          if take_ret = true then
            (ret)
          else
            Backend.c_GetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_
        in
        if return <> Pkcs11.cKR_OK then
          (return, [| |])
        else
          (Pkcs11.cKR_OBJECT_HANDLE_INVALID, [| |])
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_GetAttributeValue" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_GetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_
 
(*************************************************************************)
let c_SetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_  =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SetAttributeValue" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SetAttributeValue" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SetAttributeValue" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_SetAttributeValue" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_SetAttributeValue" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Check for the possible label or id blocking *)
        let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_SetAttributeValue" in
        let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_SetAttributeValue") in
        if check_label_id = true then
	  (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID)
        else
  	  (* Late actions after other checks *)
  	  let (take_ret, ret) =  apply_post_filter_actions "C_SetAttributeValue" (cksessionhandlet_, ckobjecthandlet_, ckattributearray_ ) in
  	  if take_ret = true then
  	    (ret)
  	  else
  	    Backend.c_SetAttributeValue cksessionhandlet_ ckobjecthandlet_ ckattributearray_ 

(*************************************************************************)
(* Variable used for the filtered handles     *)
let last_ret_on_error : Pkcs11.ck_rv_t ref = ref Pkcs11.cKR_OK
let find_objects_loop_num : int ref = ref 0
(* Maximum number of loop iterations allowed *)
let max_objects_loop : int ref = ref 100000

let c_FindObjectsInit cksessionhandlet_ ckattributearray_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_FindObjectsInit" (cksessionhandlet_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_FindObjectsInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_FindObjectsInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      let ret = Backend.c_FindObjectsInit cksessionhandlet_ ckattributearray_ in
      if compare ret Pkcs11.cKR_OK = 0 then
	begin
	  (* Reinitialize the found objects array *)
	  current_find_objects_filtered_handles := [| |];
	  last_ret_on_error := Pkcs11.cKR_OK;
          (* Late actions after other checks *)
          let (take_ret, return) =  apply_post_filter_actions "C_FindObjectsInit" (cksessionhandlet_, ckattributearray_) in
          if take_ret = true then
            (return)
          else
            (ret)
	end
	else
          (* Late actions after other checks *)
          let (take_ret, return) =  apply_post_filter_actions "C_FindObjectsInit" (cksessionhandlet_, ckattributearray_) in
          if take_ret = true then
            (return)
          else
            (ret)
 
(*************************************************************************)
let c_FindObjects cksessionhandlet_ count =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |], 0n)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_FindObjects" (cksessionhandlet_, count) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_FindObjects" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_FindObjects" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |], 0n)
    else
    begin
      if Array.length !current_find_objects_filtered_handles = 0 then
      begin
	(* This is the first time FindObjetcs is called              *) 
	(* We find all the objects and store them in our local array *)
	let total_count = ref 1n in
	try
	while compare !total_count 0n <> 0 do
	  let (ret, objects_handles_array, curr_total_count) = Backend.c_FindObjects cksessionhandlet_ 1n in
	  total_count := curr_total_count;
	  if compare ret Pkcs11.cKR_OK <> 0 then
	  begin last_ret_on_error := ret; raise Exit; end
	  else
	    (* Check that we don't overflow and raise an exception if this is the case *)
	    find_objects_loop_num := !find_objects_loop_num + 1;
	    if !find_objects_loop_num > !max_objects_loop then
	    begin
	      print_error "loop overflow when filtering FindObjetcs!";
	      raise Loop_overflow;
	    end
	    else
	    begin
	      (* Apply the label and id filtering                                        *)
	      let label_filtered_array = apply_allowed_label_filter cksessionhandlet_ objects_handles_array !allowed_labels in
	      let label_id_filtered_array = apply_allowed_id_filter cksessionhandlet_ label_filtered_array !allowed_ids in 
	      current_find_objects_filtered_handles := Array.append !current_find_objects_filtered_handles label_id_filtered_array;
	      ();
	    end
	done
	with Exit -> ();
      end;
      (* Late actions after other checks *)
      let (take_ret, return) =  apply_post_filter_actions "C_FindObjects" (cksessionhandlet_, 1n) in
      if take_ret = true then
        (return)
      else
        if compare !last_ret_on_error Pkcs11.cKR_OK <> 0 then
        begin
  	  (* We got an error, reinitialize the global variable last_ret_on_error *)
	  let ret = !last_ret_on_error in
	  last_ret_on_error := Pkcs11.cKR_OK;
          (* We return the real error that we got from the Backend               *)
	  (ret, [| |], 0n)
        end
        else
	  (* FindObjects has already been called          *)
	  (* Pick up objects from local cache array       *)
	  let returned_objects_handles = pickup_elements_in_array current_find_objects_filtered_handles count in
	  (Pkcs11.cKR_OK, returned_objects_handles, Nativeint.of_int (Array.length returned_objects_handles))
        end

(*************************************************************************)
let c_FindObjectsFinal cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_FindObjectsFinal" (cksessionhandlet_) in
  if take_ret = true then
  (ret)
    else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_FindObjectsFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_FindObjectsFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_FindObjectsFinal" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_FindObjectsFinal cksessionhandlet_
 
(*************************************************************************)
let c_EncryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_EncryptInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_EncryptInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_EncryptInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_EncryptInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_EncryptInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
      begin
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
  	  begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_EncryptInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID)
	  end
        else
	  (* Check if we forbid padding oracles *)
	  if (check_remove_padding_oracles !remove_padding_oracles "encrypt" = true || check_remove_padding_oracles !remove_padding_oracles "all" = true) then
	    (* If we indeed want to remove the padding oracles   *)
	    (* we check the mechanism against the dangerous ones *)
	    if check_element_in_list !padding_oracle_mechanisms ckmechanism_.Pkcs11.mechanism = true then
	      (Pkcs11.cKR_MECHANISM_INVALID)
	    else
	      (* Late actions after other checks *)
	      let (take_ret, ret) =  apply_post_filter_actions "C_EncryptInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	      if take_ret = true then
	        (ret)
	      else
	        Backend.c_EncryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
	  else
	    (* Late actions after other checks *)
	    let (take_ret, ret) =  apply_post_filter_actions "C_EncryptInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	    if take_ret = true then
	      (ret)
	    else
	      Backend.c_EncryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
      end

(*************************************************************************)
let c_Encrypt cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Encrypt" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Encrypt" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Encrypt" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Encrypt" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Encrypt cksessionhandlet_ data
 
(*************************************************************************)
let c_EncryptUpdate cksessionhandlet_ data =
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_EncryptUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_EncryptUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_EncryptUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_EncryptUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_EncryptUpdate cksessionhandlet_ data
 
(*************************************************************************)
let c_EncryptFinal cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_EncryptFinal" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_EncryptFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_EncryptFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_EncryptFinal" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_EncryptFinal cksessionhandlet_

(*************************************************************************)
let c_DecryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DecryptInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DecryptInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DecryptInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_DecryptInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_DecryptInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
      (* Check for the asked mechanism against the forbidden list *)
      let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
      if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
        begin
        let s = Printf.sprintf "Mechanism %s has been filtered in C_DecryptInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
        print_debug s 1;
        (Pkcs11.cKR_MECHANISM_INVALID)
        end
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_DecryptInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_DecryptInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
 
(*************************************************************************)
let c_Decrypt cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Decrypt" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Decrypt" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Decrypt" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Decrypt" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Decrypt cksessionhandlet_ data
 
(*************************************************************************)
let c_DecryptUpdate cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DecryptUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DecryptUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DecryptUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DecryptUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DecryptUpdate cksessionhandlet_ data
 
(*************************************************************************)
let c_DecryptFinal cksessionhandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DecryptFinal" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DecryptFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DecryptFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DecryptFinal" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DecryptFinal cksessionhandlet_

(*************************************************************************)
let c_DigestInit cksessionhandlet_ ckmechanism_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DigestInit" (cksessionhandlet_, ckmechanism_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DigestInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DigestInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for the asked mechanism against the forbidden list *)
      let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
      if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
      begin
	let s = Printf.sprintf "Mechanism %s has been filtered in C_DigestInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	print_debug s 1;
	(Pkcs11.cKR_MECHANISM_INVALID)
      end
      else
	(* Late actions after other checks *)
	let (take_ret, ret) =  apply_post_filter_actions "C_DigestInit" (cksessionhandlet_, ckmechanism_) in
	if take_ret = true then
	  (ret)
	else
	  Backend.c_DigestInit cksessionhandlet_ ckmechanism_

(*************************************************************************)
let c_Digest cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Digest" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Digest" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Digest" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Digest" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Digest cksessionhandlet_ data

(*************************************************************************)
let c_DigestUpdate cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DigestUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DigestUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DigestUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DigestUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DigestUpdate cksessionhandlet_ data

(*************************************************************************)
let c_DigestKey cksessionhandlet_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DigestKey" (cksessionhandlet_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DigestKey" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DigestKey" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_DigestKey" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_DigestKey" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Late actions after other checks *)
        let (take_ret, ret) =  apply_post_filter_actions "C_DigestKey" (cksessionhandlet_, ckobjecthandlet_) in
        if take_ret = true then
          (ret)
        else
          Backend.c_DigestKey cksessionhandlet_ ckobjecthandlet_
 
(*************************************************************************)
let c_DigestFinal cksessionhandlet =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DigestFinal" (cksessionhandlet) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DigestFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DigestFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DigestFinal" (cksessionhandlet) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DigestFinal cksessionhandlet
 
(*************************************************************************)
let c_SignInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_SignInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_SignInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
	  begin
    	  let s = Printf.sprintf "Mechanism %s has been filtered in C_SignInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
  	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID)
	  end
        else
	  (* Check if we forbid padding oracles *)
	  if (check_remove_padding_oracles !remove_padding_oracles "sign" = true || check_remove_padding_oracles !remove_padding_oracles "all" = true) then
	    (* If we indeed want to remove the padding oracles   *)
	    (* we check the mechanism against the dangerous ones *)
	    if check_element_in_list !padding_oracle_mechanisms ckmechanism_.Pkcs11.mechanism = true then
	      (Pkcs11.cKR_MECHANISM_INVALID)
	    else
	      (* Late actions after other checks *)
	      let (take_ret, ret) =  apply_post_filter_actions "C_SignInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	      if take_ret = true then
	        (ret)
	      else
	        Backend.c_SignInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
	  else
	    (* Late actions after other checks *)
	    let (take_ret, ret) =  apply_post_filter_actions "C_SignInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	    if take_ret = true then
	      (ret)
	    else
	      Backend.c_SignInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
 
(*************************************************************************)
let c_SignRecoverInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignRecoverInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignRecoverInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignRecoverInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_SignRecoverInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_SignRecoverInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
  	  begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_SignRecoverInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID)
	  end
        else
	  (* Late actions after other checks *)
	  let (take_ret, ret) =  apply_post_filter_actions "C_SignRecoverInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	  if take_ret = true then
	    (ret)
	  else
	    Backend.c_SignRecoverInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_

(*************************************************************************)
let c_Sign cksessionhandlet_ data =
  (* If no module is defined, return CKR_CRYPTOKI_NOT_INITIALIZED *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Sign" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Sign" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Sign" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Sign" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Sign cksessionhandlet_ data

(*************************************************************************)
let c_SignRecover cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignRecover" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignRecover" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignRecover" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SignRecover" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SignRecover cksessionhandlet_ data
 
(*************************************************************************)
let c_SignUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SignUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SignUpdate cksessionhandlet_ data

(*************************************************************************)
let c_SignFinal cksessionhandlet_ =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignFinal" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SignFinal" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SignFinal cksessionhandlet_

(*************************************************************************)
let c_VerifyInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_ =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_VerifyInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_VerifyInit" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_VerifyInit" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_VerifyInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_VerifyInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
        begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_VerifyInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID)
        end
        else
	  (* Late actions after other checks *)
	  let (take_ret, ret) =  apply_post_filter_actions "C_VerifyInit" (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
	  if take_ret = true then
	    (ret)
	  else
	    Backend.c_VerifyInit cksessionhandlet_ ckmechanism_ ckobjecthandlet_
 
(*************************************************************************)
let c_VerifyRecoverInit  cksessionhandlet_ ckmechanism_ ckobjecthandlet_  =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_VerifyRecoverInit " (cksessionhandlet_, ckmechanism_, ckobjecthandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_FindObjects" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_FindObjects" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ ckobjecthandlet_ !allowed_labels "C_VerifyRecoverInit" = false) || (check_object_id cksessionhandlet_ ckobjecthandlet_ !allowed_ids "C_VerifyRecoverInit" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
  	  begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_VerifyRecoverInit" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID)
	  end
        else
	  (* Late actions after other checks *)
	  let (take_ret, ret) =  apply_post_filter_actions "C_VerifyRecoverInit" ( cksessionhandlet_, ckmechanism_, ckobjecthandlet_ ) in
	  if take_ret = true then
	    (ret)
	  else
	    Backend.c_VerifyRecoverInit  cksessionhandlet_ ckmechanism_ ckobjecthandlet_ 

(*************************************************************************)
let c_Verify cksessionhandlet_ data signed_data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_Verify" (cksessionhandlet_, data, signed_data) in
  if take_ret = true then
  (ret)
    else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_Verify" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_Verify" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_Verify" (cksessionhandlet_, data, signed_data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_Verify cksessionhandlet_ data signed_data
 
(*************************************************************************)
let c_VerifyRecover cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_VerifyRecover" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_VerifyRecover" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_VerifyRevover" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_VerifyRecover" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_VerifyRecover cksessionhandlet_ data
 
(*************************************************************************)
let c_VerifyUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_VerifyUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_VerifyUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_VerifyUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_VerifyUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_VerifyUpdate cksessionhandlet_ data

(*************************************************************************)
let c_VerifyFinal cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_VerifyFinal" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_VerifyFinal" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_VerifyFinal" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_VerifyFinal" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_VerifyFinal cksessionhandlet_ data

(*************************************************************************)
let c_DigestEncryptUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DigestEncryptUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DigestEncryptUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DigestEncryptUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DigestEncryptUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DigestEncryptUpdate cksessionhandlet_ data

(*************************************************************************)
let c_DecryptDigestUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DecryptDigestUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DecryptDigestUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DecryptDigestUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DecryptDigestUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DecryptDigestUpdate cksessionhandlet_ data
 
(*************************************************************************)
let c_SignEncryptUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SignEncryptUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SignEncryptUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SignEncryptUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SignEncryptUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SignEncryptUpdate cksessionhandlet_ data
 
(*************************************************************************)
let c_DecryptVerifyUpdate cksessionhandlet_ data =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DecryptVerifyUpdate" (cksessionhandlet_, data) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DecryptVerifyUpdate" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DecryptVerifyUpdate" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_DecryptVerifyUpdate" (cksessionhandlet_, data) in
      if take_ret = true then
        (ret)
      else
        Backend.c_DecryptVerifyUpdate cksessionhandlet_ data
 
(*************************************************************************)
let c_GenerateKey cksessionhandlet_ ckmechanism_ ckattributearray_ =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GenerateKey" (cksessionhandlet_, ckmechanism_, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GenerateKey" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GenerateKey" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for the asked mechanism against the forbidden list *)
      let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
      if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
	begin
	let s = Printf.sprintf "Mechanism %s has been filtered in C_GenerateKey" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	print_debug s 1;
	(Pkcs11.cKR_MECHANISM_INVALID, Pkcs11.cK_INVALID_HANDLE)
	end
      else
	(* Check for the possible label or id blocking *)
	let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_GenerateKey" in
	let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_GenerateKey") in
	if check_label_id = true then
	  (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)
	else
	  (* Late actions after other checks *)
	  let (take_ret, ret) =  apply_post_filter_actions "C_GenerateKey" (cksessionhandlet_, ckmechanism_, ckattributearray_) in
	  if take_ret = true then
	    (ret)
	  else
	    Backend.c_GenerateKey cksessionhandlet_ ckmechanism_ ckattributearray_

(*************************************************************************)
let c_GenerateKeyPair cksessionhandlet_ ckmechanism_ pub_attributes priv_attributes =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GenerateKeyPair" (cksessionhandlet_, ckmechanism_, pub_attributes, priv_attributes) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GenerateKeyPair" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GenerateKeyPair" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for the asked mechanism against the forbidden list *)
      let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
      if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
	begin
	let s = Printf.sprintf "Mechanism %s has been filtered in C_GenerateKeyPair" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	print_debug s 1;
	(Pkcs11.cKR_MECHANISM_INVALID, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)
	end
      else
	(* Check for the possible label or id blocking *)
	let check_label_pub = check_label_on_object_creation pub_attributes !allowed_labels "C_GenerateKeyPair" in
	let check_label_id_pub = check_label_pub || (check_id_on_object_creation pub_attributes !allowed_ids "C_GenerateKeyPair") in
	let check_all = check_label_id_pub || (check_label_on_object_creation priv_attributes !allowed_labels "C_GenerateKeyPair") in
	let check_all = check_all || (check_id_on_object_creation priv_attributes !allowed_ids "C_GenerateKeyPair") in
	if check_all = true then
	  (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE, Pkcs11.cK_INVALID_HANDLE)
	else
	  (* Late actions after other checks *)
	  let (take_ret, ret) =  apply_post_filter_actions "C_GenerateKeyPair" (cksessionhandlet_, ckmechanism_, pub_attributes, priv_attributes) in
	  if take_ret = true then
	    (ret)
	  else
	    Backend.c_GenerateKeyPair cksessionhandlet_ ckmechanism_ pub_attributes priv_attributes

(*************************************************************************)
let c_WrapKey cksessionhandlet_ ckmechanism_ wrapping_handle wrapped_handle =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_WrapKey" (cksessionhandlet_, ckmechanism_, wrapping_handle, wrapped_handle) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_WrapKey" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_WrapKey" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [||])
    else
      (* Check for label or id blocking on the input wrapping key *)
      if (check_object_label cksessionhandlet_ wrapping_handle !allowed_labels "C_WrapKey" = false) || (check_object_id cksessionhandlet_ wrapping_handle !allowed_ids "C_WrapKey" = false) then
        (Pkcs11.cKR_WRAPPING_KEY_HANDLE_INVALID, [||])
      else
        (* Check for label or id blocking on the input wrapped key *)
        if  (check_object_label cksessionhandlet_ wrapped_handle !allowed_labels "C_WrapKey" = false) || (check_object_id cksessionhandlet_ wrapped_handle !allowed_ids "C_WrapKey" = false) then
          (Pkcs11.cKR_OBJECT_HANDLE_INVALID, [||])
        else
          (* Check for the asked mechanism against the forbidden list *)
          let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
          if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
    	    begin
	    let s = Printf.sprintf "Mechanism %s has been filtered in C_WrapKey" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	    print_debug s 1;
	    (Pkcs11.cKR_MECHANISM_INVALID, [||])
	    end
          else
	    (* Check if we forbid padding oracles *)
	    if (check_remove_padding_oracles !remove_padding_oracles "wrap" = true || check_remove_padding_oracles !remove_padding_oracles "all" = true) then
	    begin
	      (* If we indeed want to remove the padding oracles   *)
	      (* we check the mechanism against the dangerous ones *)
	      if check_element_in_list !padding_oracle_mechanisms ckmechanism_.Pkcs11.mechanism = true then
	        (Pkcs11.cKR_MECHANISM_INVALID, [||])
	      else
	        (* Late actions after other checks *)
	        let (take_ret, ret) =  apply_post_filter_actions "C_WrapKey" (cksessionhandlet_, ckmechanism_, wrapping_handle, wrapped_handle) in
	        if take_ret = true then
	          (ret)
	        else
	          Backend.c_WrapKey cksessionhandlet_ ckmechanism_ wrapping_handle wrapped_handle
	    end
	    else
	      (* Late actions after other checks *)
	      let (take_ret, ret) =  apply_post_filter_actions "C_WrapKey" (cksessionhandlet_, ckmechanism_, wrapping_handle, wrapped_handle) in
	      if take_ret = true then
	        (ret)
	      else
	        Backend.c_WrapKey cksessionhandlet_ ckmechanism_ wrapping_handle wrapped_handle

(*************************************************************************)
let c_UnwrapKey cksessionhandlet_ ckmechanism_ unwrapping_handle wrapped_key ckattributearray_   =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_UnwrapKey" (cksessionhandlet_, ckmechanism_, unwrapping_handle, wrapped_key, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_UnwrapKey" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_UnwrapKey" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ unwrapping_handle !allowed_labels "C_UnwrapKey" = false) || (check_object_id cksessionhandlet_ unwrapping_handle !allowed_ids "C_UnwrapKey" = false) then
        (Pkcs11.cKR_UNWRAPPING_KEY_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
  	  begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_UnwrapKey" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID, Pkcs11.cK_INVALID_HANDLE)
	  end
        else
	  (* Check if we forbid padding oracles *)
	  if (check_remove_padding_oracles !remove_padding_oracles "unwrap" = true || check_remove_padding_oracles !remove_padding_oracles "all" = true) then
	  begin
	    (* If we indeed want to remove the padding oracles   *)
	    (* we check the mechanism against the dangerous ones *)
	    if check_element_in_list !padding_oracle_mechanisms ckmechanism_.Pkcs11.mechanism = true then
	      (Pkcs11.cKR_MECHANISM_INVALID, Pkcs11.cK_INVALID_HANDLE)
	    else
	      Backend.c_UnwrapKey cksessionhandlet_ ckmechanism_ unwrapping_handle wrapped_key ckattributearray_  
	  end
	  else
	    (* Check for the possible label or id blocking *)
	    let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_UnwrapKey" in
	    let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_UnwrapKey") in
	    if check_label_id = true then
	      (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)
	    else
	      (* Late actions after other checks *)
	      let (take_ret, ret) =  apply_post_filter_actions "C_UnwrapKey" (cksessionhandlet_, ckmechanism_, unwrapping_handle, wrapped_key, ckattributearray_  ) in
	      if take_ret = true then
	        (ret)
	      else
	        Backend.c_UnwrapKey cksessionhandlet_ ckmechanism_ unwrapping_handle wrapped_key ckattributearray_  

(*************************************************************************)
let c_DeriveKey cksessionhandlet_ ckmechanism_ initial_key_handle ckattributearray_   =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, Pkcs11.cK_INVALID_HANDLE)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_DeriveKey" (cksessionhandlet_, ckmechanism_, initial_key_handle, ckattributearray_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_DeriveKey" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_DeriveKey" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, Pkcs11.cK_INVALID_HANDLE)
    else
      (* Check for label or id blocking on the input objects handles *)
      if (check_object_label cksessionhandlet_ initial_key_handle !allowed_labels "C_DeriveKey" = false) || (check_object_id cksessionhandlet_ initial_key_handle !allowed_ids "C_DeriveKey" = false) then
        (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)
      else
        (* Check for the asked mechanism against the forbidden list *)
        let ckmechanismtypet_ = ckmechanism_.Pkcs11.mechanism in
        if check_forbidden_mechanism_in_all_lists ckmechanismtypet_ !forbidden_mechanisms = true then
  	  begin
	  let s = Printf.sprintf "Mechanism %s has been filtered in C_DeriveKey" (Pkcs11.match_cKM_value ckmechanismtypet_) in
	  print_debug s 1;
	  (Pkcs11.cKR_MECHANISM_INVALID, Pkcs11.cK_INVALID_HANDLE)
	  end
        else
	  (* Check for the possible label or id blocking *)
	  let check_label = check_label_on_object_creation ckattributearray_ !allowed_labels "C_DeriveKey" in
	  let check_label_id = check_label || (check_id_on_object_creation ckattributearray_ !allowed_ids "C_DeriveKey") in
	  if check_label_id = true then
	    (Pkcs11.cKR_ATTRIBUTE_VALUE_INVALID, Pkcs11.cK_INVALID_HANDLE)
	  else
	    (* Late actions after other checks *)
	    let (take_ret, ret) =  apply_post_filter_actions "C_DeriveKey" (cksessionhandlet_, ckmechanism_, initial_key_handle, ckattributearray_  ) in
	    if take_ret = true then
	      (ret)
	    else
	      Backend.c_DeriveKey cksessionhandlet_ ckmechanism_ initial_key_handle ckattributearray_  

(*************************************************************************)
let c_SeedRandom cksessionhandlet_ seed =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_SeedRandom" (cksessionhandlet_, seed) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_SeedRandom" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_SeedRandom" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_SeedRandom" (cksessionhandlet_, seed) in
      if take_ret = true then
        (ret)
      else
        Backend.c_SeedRandom cksessionhandlet_ seed

(*************************************************************************)
let c_GenerateRandom cksessionhandlet_ count =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED, [| |])
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GenerateRandom" (cksessionhandlet_, count) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GenerateRandom" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GenerateRandom" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED, [| |])
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GenerateRandom" (cksessionhandlet_, count) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GenerateRandom cksessionhandlet_ count

(*************************************************************************)
let c_GetFunctionStatus cksessionhandlet_ =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_GetFunctionStatus" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_GetFunctionStatus" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_GetFunctionStatus" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_GetFunctionStatus" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_GetFunctionStatus cksessionhandlet_

(*************************************************************************)
let c_CancelFunction cksessionhandlet_ =
  (* If no module is defined, return a CKR_GENERAL_ERROR *)
  match !current_module with
    None -> 
      (Pkcs11.cKR_CRYPTOKI_NOT_INITIALIZED)
  | _ ->
  (*************************************)
  (* Early actions before other checks *)
  let (take_ret, ret) =  apply_pre_filter_actions "C_CancelFunction" (cksessionhandlet_) in
  if take_ret = true then
    (ret)
  else
    (* Check the function *)
    let check = check_function_in_forbidden_functions_list "C_CancelFunction" !forbidden_functions in
    if check = true then
      let _ = print_debug "Blocking function C_CancelFunction" 1 in
      (Pkcs11.cKR_FUNCTION_NOT_SUPPORTED)
    else
      (* Late actions after other checks *)
      let (take_ret, ret) =  apply_post_filter_actions "C_CancelFunction" (cksessionhandlet_) in
      if take_ret = true then
        (ret)
      else
        Backend.c_CancelFunction cksessionhandlet_

