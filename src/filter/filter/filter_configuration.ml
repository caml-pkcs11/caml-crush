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
    File:    src/filter/filter/filter_configuration.ml

************************** MIT License HEADER ***********************************)
(* Filter configuration handling *)
open Config_file
open Filter_common
open Filter_actions

let string_check_function a = match a with
  "C_LoadModule" -> a
| "C_Initialize" -> a
| "C_Finalize" -> a
| "C_GetSlotList" -> a
| "C_GetInfo" -> a
| "C_WaitForSlotEvent" -> a
| "C_GetSlotInfo" -> a
| "C_GetTokenInfo" -> a
| "C_InitToken" -> a
| "C_OpenSession" -> a
| "C_CloseSession" -> a
| "C_CloseAllSessions" -> a
| "C_GetSessionInfo" -> a
| "C_Login" -> a
| "C_Logout" -> a
| "C_GetMechanismList" -> a
| "C_GetMechanismInfo" -> a
| "C_InitPIN" -> a
| "C_SetPIN" -> a
| "C_SeedRandom" -> a
| "C_GenerateRandom" -> a
| "C_FindObjectsInit" -> a
| "C_FindObjects" -> a
| "C_FindObjectsFinal" -> a
| "C_GenerateKey" -> a
| "C_GenerateKeyPair" -> a
| "C_CreateObject" -> a
| "C_CopyObject" -> a
| "C_DestroyObject" -> a
| "C_GetAttributeValue" -> a
| "C_SetAttributeValue" -> a
| "C_GetObjectSize" -> a
| "C_WrapKey" -> a
| "C_UnwrapKey" -> a
| "C_DeriveKey" -> a
| "C_DigestInit" -> a
| "C_Digest" -> a
| "C_DigestUpdate" -> a
| "C_DigestKey" -> a
| "C_DigestFinal" -> a
| "C_SignInit" -> a
| "C_SignRecoverInit" -> a
| "C_Sign" -> a
| "C_SignRecover" -> a
| "C_SignUpdate" -> a
| "C_SignFinal" -> a
| "C_VerifyInit" -> a
| "C_VerifyRecoverInit" -> a
| "C_Verify" -> a
| "C_VerifyRecover" -> a
| "C_VerifyUpdate" -> a
| "C_VerifyFinal" -> a
| "C_EncryptInit" -> a
| "C_Encrypt" -> a
| "C_EncryptUpdate" -> a
| "C_EncryptFinal" -> a
| "C_DigestEncryptUpdate" -> a
| "C_SignEncryptUpdate" -> a
| "C_DecryptInit" -> a
| "C_Decrypt" -> a
| "C_DecryptUpdate" -> a
| "C_DecryptFinal" -> a
| "C_DecryptDigestUpdate" -> a
| "C_DecryptVerifyUpdate" -> a
| "C_GetOperationState" -> a
| "C_SetOperationState" -> a
| "C_GetFunctionStatus" -> a
| "C_CancelFunction" -> a
| _ -> let error_string = Printf.sprintf "Error: unknown PKCS#11 function '%s'!" a in netplex_log_critical error_string; raise Config_file_wrong_type

let string_check_padding a = match a with
  "wrap" -> a
| "unwrap" -> a
| "encrypt" -> a
| "sign" -> a
| "all" -> a
| _ -> let error_string = Printf.sprintf "Error: unknown padding option '%s'!" a in netplex_log_critical error_string; raise Config_file_wrong_type


(*************************)
(** Our custom wrappers **)
(* Wrapper for mechanisms *)
let ck_mechanism_type_t_wrappers = {
  to_raw = (fun input -> Config_file.Raw.String (Pkcs11.match_cKM_value input));
  of_raw = function 
    | Config_file.Raw.String input -> 
        (try Pkcs11.string_to_cKM_value input 
        with Pkcs11.Mechanism_unknown a -> let error_string = Printf.sprintf "Error: unknown mechanism '%s'!" a in netplex_log_critical error_string; raise Config_file_wrong_type;)
    | _ -> netplex_log_critical "Error: got wrong mechanism type!"; raise Config_file_wrong_type 
}

(* Wrapper for forbidden functions *)
let functions_wrappers = {
  to_raw = (fun input -> Config_file.Raw.String input);
  of_raw = function 
    | Config_file.Raw.String input -> string_check_function input
    | _ -> netplex_log_critical "Error: got wrong function type!"; raise Config_file_wrong_type
}

(* Wrapper for dangerous PKCS#11 paddings *)
let padding_wrappers = {
  to_raw = (fun input -> Config_file.Raw.String input);
  of_raw = function
    | Config_file.Raw.String input -> string_check_padding input
    | _ -> netplex_log_critical "Error: got wrong padding option type!"; raise Config_file_wrong_type
}


(*******************************)
(**** Configuration entries ****)
let group = new group

let modules_ = new list_cp (tuple2_wrappers string_wrappers string_wrappers) ~group ["modules"] [] "Modules aliases."
let modules = ref []

(* For debug and log subchannel, the references are in the filter_common file *)
let debug_ = new int_cp ~group ["debug"] 0 "Debug verbosity"
let log_subch_ = new string_cp ~group ["log_subchannel"] "" "Subchannel to log to"

(* The following entries can be module dependent *)
(* Forbidden mechanisms *)
let forbidden_mechanisms_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers ck_mechanism_type_t_wrappers)) ~group ["forbidden_mechanisms"] [] "Forbidden mechanisms"
let forbidden_mechanisms = ref []

(* Allowed labels for objects *)
let allowed_labels_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers string_wrappers)) ~group ["allowed_labels"] [] "Allowed labels for objects"
let allowed_labels = ref []

(* Allowed ids for objects *)
let allowed_ids_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers string_wrappers)) ~group ["allowed_ids"] [] "Allowed IDs for objects"
let allowed_ids = ref []


(* Forbidden PKCS#11 functions *)
let forbidden_functions_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers functions_wrappers)) ~group ["forbidden_functions"] [] "Forbidden PKCS#11 functions"
let forbidden_functions = ref []

(* Enforce RO sessions *)
let enforce_ro_sessions_ = new list_cp (tuple2_wrappers string_wrappers bool_wrappers) ~group ["enforce_ro_sessions"] [] "Enforce RO sessions"
let enforce_ro_sessions = ref []

(* Prevent admin operations *)
let forbid_admin_operations_ = new list_cp (tuple2_wrappers string_wrappers bool_wrappers) ~group ["forbid_admin_operations"] [] "Forbid admin (SO) login"
let forbid_admin_operations = ref []

(* Remove padding oracles in UnWrap *)
(* List of dangerous paddings with regard to padding oracle attacks - PKCS#11 v1.5 and CBC_PAD - *)
let padding_oracle_mechanisms_ = [Pkcs11.cKM_RSA_PKCS; Pkcs11.cKM_MD2_RSA_PKCS; Pkcs11.cKM_MD5_RSA_PKCS; Pkcs11.cKM_SHA1_RSA_PKCS; Pkcs11.cKM_RIPEMD128_RSA_PKCS; Pkcs11.cKM_RIPEMD160_RSA_PKCS; Pkcs11.cKM_SHA256_RSA_PKCS; Pkcs11.cKM_SHA384_RSA_PKCS; Pkcs11.cKM_SHA512_RSA_PKCS; Pkcs11.cKM_RC2_CBC_PAD; Pkcs11.cKM_DES_CBC_PAD; Pkcs11.cKM_DES3_CBC_PAD; Pkcs11.cKM_CDMF_CBC_PAD; Pkcs11.cKM_CAST_CBC_PAD; Pkcs11.cKM_CAST3_CBC_PAD; Pkcs11.cKM_CAST5_CBC_PAD; Pkcs11.cKM_CAST128_CBC_PAD; Pkcs11.cKM_RC5_CBC_PAD; Pkcs11.cKM_IDEA_CBC_PAD; Pkcs11.cKM_AES_CBC_PAD; Pkcs11.cKM_RSA_X_509]
let padding_oracle_mechanisms = ref padding_oracle_mechanisms_
let remove_padding_oracles_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers padding_wrappers)) ~group ["remove_padding_oracles"] [] "Remove dangerous paddings at Wrap/UnWrap (that could result in padding oracle attacks)"
let remove_padding_oracles = ref []

(* Filter actions *)
let filter_actions_pre_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers (tuple2_wrappers functions_wrappers actions_wrappers))) ~group ["filter_actions_pre"] [] "Define actions to be taken on some PKCS#11 function call trigger (pre actions)"
let filter_actions_pre = ref []
let filter_actions_post_ = new list_cp (tuple2_wrappers string_wrappers (list_wrappers (tuple2_wrappers functions_wrappers actions_wrappers))) ~group ["filter_actions_post"] [] "Define actions to be taken on some PKCS#11 function call trigger (post actions)"
let filter_actions_post = ref []

(* Wrapping key format *)
let wrapping_format_key_ = new string_cp ~group ["wrapping_format_key"] "" "Wrapping key format"

 
(********************************************)
(*********** Printer helpers ****************)
(********************************************)
let print_aliases message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) -> let s = Printf.sprintf "'%s' -> '%s'" a b in print_debug s level) !modules;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_debug_level message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    let s = Printf.sprintf "%d" !debug in print_debug s level;
  end;
  ()

let print_log_subchannel message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    if String.length !log_subch = 0 then
      let s = Printf.sprintf "Netplex log output" in print_debug s level;
    else
      let s = Printf.sprintf "%s"!log_subch in print_debug s level;
  end;
  ()

let print_mechanisms mechanisms_list message level = 
  if level <= !debug
  then
  begin
    if String.length message <> 0 then 
    begin
        let print_string = Printf.sprintf "%s" message in
        print_debug print_string level
    end;
    List.iter (fun mech -> let s = Printf.sprintf " -> %s" (Pkcs11.match_cKM_value mech) in print_debug s level;) mechanisms_list;
  end;
  ()

let print_aliased_mechanisms alias_mechanisms_list message level = 
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) -> 
       let s = Printf.sprintf "Forbidden mechanisms for module '%s' (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in
       print_debug s level; print_mechanisms b "" level;) alias_mechanisms_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()


let print_labels labels_list message level = 
  if level <= !debug
  then
  begin
    if String.length message <> 0 then 
    begin
      let print_string = Printf.sprintf "%s" message in
        print_debug print_string level
    end;
    List.iter (fun label -> let s = Printf.sprintf " -> %s" label in print_debug s level;) labels_list;
  end;
  ()

let print_aliased_labels alias_labels_list message level = 
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) -> 
       let s = Printf.sprintf "Allowed labels for module '%s'  (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in
       print_debug s level; print_labels b "" level;) alias_labels_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_ids ids_list message level = 
  if level <= !debug
  then
  begin
    if String.length message <> 0 then 
    begin
      let print_string = Printf.sprintf "%s" message in
        print_debug print_string level
    end;
    List.iter (fun id -> let s = Printf.sprintf " -> %s" id in print_debug s level;) ids_list;
  end;
  ()

let print_aliased_ids alias_ids_list message level = 
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) -> 
       let s = Printf.sprintf "Allowed ids for module '%s'  (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in
       print_debug s level; print_ids b "" level;) alias_ids_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()


let print_functions functions_list message level = 
  if level <= !debug
  then
  begin
    if String.length message <> 0 then 
    begin
      let print_string = Printf.sprintf "%s" message in
        print_debug print_string level
    end;
    List.iter (fun func -> let s = Printf.sprintf " -> %s" func in print_debug s level;) functions_list;
  end;
  ()

let print_aliased_functions alias_functions_list message level = 
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) -> 
       let s = Printf.sprintf "Forbidden PKCS#11 functions for module '%s' (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in
       print_debug s level; print_labels b "" level;) alias_functions_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_aliased_ro_enforcement ro_enfoce_list message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) ->
      let status = if compare b true = 0 then "true" else "false" in
      let s = Printf.sprintf "RO session enforcement for modules '%s' (corresponding to aliases %s) is: %s" a (get_aliases_from_regexp !modules a) status in
      print_debug s level;) ro_enfoce_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_aliased_forbid_admin_operations admin_forbid_list message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) ->
      let status = if compare b true = 0 then "true" else "false" in
      let s = Printf.sprintf "Admin operations forbidden for modules '%s' (corresponding to aliases %s) is: %s" a (get_aliases_from_regexp !modules a) status in
      print_debug s level;) admin_forbid_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_remove_padding_oracles remove_padding_oracles_list message level =
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) ->
      let s = Printf.sprintf "Removing PKCS#11 dangerous paddings for modules '%s' (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in print_debug s level;
      List.iter (fun c -> let s = Printf.sprintf " -> %s " c in print_debug s level;) b) remove_padding_oracles_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()

let print_filter_actions filter_actions_list message level = 
  if level <= !debug
  then
  begin
    print_debug message level;
    List.iter (fun (a, b) ->
      let s = Printf.sprintf "Actions for modules '%s' (corresponding to aliases %s) are:" a (get_aliases_from_regexp !modules a) in print_debug s level;
      List.iter (fun (c, d) -> let s = Printf.sprintf " %s -> %s " c d in print_debug s level;) b) filter_actions_list;
    let s = Printf.sprintf "--------------------------" in print_debug s level;
  end;
  ()


(*****************************)
(******** Sanity checks ******)
(* Check for each mechanism list if the associated alias is legitimate *)
let check_mechanisms modules mechanisms_config_list = 
  (* We iterate through the mechanisms lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in mechanisms list is not a valid alias!" a in
        print_error error_string; raise Mechanisms_except;) mechanisms_config_list;
   ()

(* Check for each label list if the associated alias is legitimate *)
let check_labels modules labels_config_list = 
  (* We iterate through the labels lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in labels list is not a valid alias!" a in
        print_error error_string; raise Labels_except;) labels_config_list;
   ()

(* Check for each id list if the associated alias is legitimate *)
let check_ids modules ids_config_list = 
  (* We iterate through the ids lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in ids list is not a valid alias!" a in
        print_error error_string; raise Ids_except;) ids_config_list;
   ()


(* Check for each PKCS#11 function list if the associated alias is legitimate *)
let check_functions modules functions_config_list = 
  (* We iterate through the labels lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in forbidden functions list is not a valid alias!" a in
        print_error error_string; raise P11_functions_except;) functions_config_list;
   ()

(* Check for each associated alias the RO session enforcement *)
let check_enforce_ro_sessions modules ro_session_list = 
  (* We iterate through the labels lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in RO session enforcement option is not a valid alias!" a in
        print_error error_string; raise Enforce_RO_except;) ro_session_list;
   ()

(* Check for each associated alias if the admin operations are allowed *)
let check_forbid_admin_operations modules admin_forbid_list = 
  (* We iterate through the lists and check each alias *)
  List.iter (fun (a, _) -> 
    let found = check_alias modules a in 
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in the forbid admin operations option is not a valid alias!" a in
        print_error error_string; raise Forbid_admin;) admin_forbid_list;
   ()

(* Check for each associated alias if we block the dangerous PKCS#11 paddings *)
let check_remove_padding_oracles modules remove_padding_oracles_list = 
  (* We iterate through the lists and check each alias *)
  List.iter (fun (a, _) ->
    let found = check_alias modules a in
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in the remove padding oracles option is not a valid alias!" a in
        print_error error_string; raise Forbid_admin;) remove_padding_oracles_list;
   ()
  

(* Check for each associated alias the actions *)
let check_actions modules actions_list =
  (* We iterate through the list and check each alias *)
  List.iter (fun (a, _) ->
    let found = check_alias modules a in
      if found = false
      then
        let error_string = Printf.sprintf "alias '%s' provided in the actions list a valid alias!" a in
        print_error error_string; raise Actions_except;) actions_list;
   ()

(* Get the wrapping format key from an hexadecimal string *)
(* and set it in the global variable                      *)
let set_wrapping_key wrapping_format_key_string =
  if String.length wrapping_format_key_string <> 32 then
    let error_string = Printf.sprintf "Provided wrapping format key is of size %d instead of 32, or no wrapping key defined at all => please define a proper hexadecimal key for the wrapping format key (i.e. wrapping_format_key = \"00010203...\")" (String.length wrapping_format_key_string) in
    print_error error_string;
    raise Wrapping_key_except;
  else
    let wrapping_format_key_bin = try (Pkcs11.string_to_char_array (Pkcs11.pack wrapping_format_key_string))
      with _ -> (let error_string = Printf.sprintf "Provided wrapping format key is not in proper hexadecimal" in
      print_error error_string; raise Wrapping_key_except;) in
    (wrapping_format_key_bin)

(* Check if the wrapping or unwrapping action are called  *)
(* during pre or post actions                             *)
(* FIXME: this is not a clean way to check for this since *)
(* we are mixing the filter core with specific actions    *)
let check_for_wraping_post_pre actions = 
  let found = ref false in
  List.iter (fun (_, embedded_list) -> 
    List.iter (fun (_, the_action) ->
      if compare the_action "wrapping_format_patch" = 0 then
        found := !found || true
      else
        found := !found || false
    ) embedded_list;
  ) actions;
  (!found)


(******** External interfaces ***************)
(******** Modules aliases     ***************)
(* Generic function to get lists associated to an alias *)
let get_associated_list alias config_list =
  let found =
    try Some (snd (List.find (fun (a, _) -> check_regexp a alias = true) config_list)) with
    (* If not found, retur None *)
    Not_found -> None in
  if found = None
  then
    let info_string = Printf.sprintf "Info: asked list for alias '%s' has not been found!" alias in
      print_debug info_string 2; raise Find_list_except
  else
    (get found)

let get_module_alias alias =
  (* Find the element *)
  let found =
	try Some (snd (List.find (fun (a, _) -> check_regexp a alias = true) !modules)) with
  (* If not found, return the empty string *)
    Not_found -> None in
  if found = None
  then
    let error_string = Printf.sprintf "asked alias '%s' has not been found!" alias in
        print_error error_string; raise Modules_except;
  else
    let debug_string = Printf.sprintf "Aliasing requested '%s' -> '%s'" alias (get found) in
    begin 
      print_debug debug_string 1;
    end;
  (get found)




(************************************************************************)
(***************** Main configuration function **************************)
let print_some_help groupable_cp _ _ filename _ = 
   let error_string = Printf.sprintf "Error when parsing configuration file '%s': erroneous field for '%s'" filename (String.concat "." groupable_cp#get_name) in print_error error_string;
   if compare (String.concat "." groupable_cp#get_name) "forbidden_functions" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [PKCS11_FUNCTION1, PKCS11_FUNCTION2 ...]) where alias_regexp is a module alias regular expression and PKCS11_FUNCTIONi are valid PKCS#11 function names to be blocked for this module alias" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "forbidden_mechanisms" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [MECHANISM1, MECHANISM2 ...]) where alias_regexp is a module alias regular expression and MECHANISMi are valid PKCS#11 mechanisms names to be blocked for this module alias" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "allowed_labels" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [LABEL1, LABEL2 ...]) where alias_regexp is a module alias regular expression and LABELi are regular expressions for the labels to be filtered for this module alias" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "allowed_ids" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [ID1, ID2 ...]) where alias_regexp is a module alias regular expression and IDi are regular expressions for the IDs to be filtered for this module alias" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "modules" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias, PATH) where alias is a module alias and PATH for the real module (aka .so file) to be loaded" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "debug" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain an integer representing the debug level" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "log_subchannel" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain an string representing the log channel where logging should be operated: this channel name is the one used inside the pkcs11proxyd configuration file" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "enforce_ro_sessions" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, BOOL) where alias_regexp is a module alias regular expression and BOOL is a boolean ('true', 'false', 'yes' or 'no') telling for each alias if the RO sessions are enforced or not" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "forbid_admin_operations" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, BOOL) where alias_regexp is a module alias regular expression and BOOL is a boolean ('true', 'false', 'yes' or 'no') telling for each alias if the admin operations are forbidden or not" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "remove_padding_oracles" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [OPERATION_TYPE1, OPERATION_TYPE2 ...]) where alias_regexp is a module alias regular expression and OPERATION_TYPEi are operation types ('wrap', 'unwrap', 'encrypt', 'sign' or 'all') telling for each alias and each operation type if the possible padding oracles are to be removed or not" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "filter_actions_pre" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [(PKCS11_FUNCTION1, ACTION1), (PKCS11_FUNCTION2, ACTION2) ...]) where alias_regexp is a module alias regular expression and PKCS11_FUNCTION are PKCS#11 function names, and ACTION are actions defined and implemented in the filter_actions plugin file" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "filter_actions_post" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain a list of couples (alias_regexp, [(PKCS11_FUNCTION1, ACTION1), (PKCS11_FUNCTION2, ACTION2) ...]) where alias_regexp is a module alias regular expression and PKCS11_FUNCTION are PKCS#11 function names, and ACTION are actions defined and implemented in the filter_actions plugin file" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   if compare (String.concat "." groupable_cp#get_name) "wrapping_format_key" = 0 then
   begin
     let error_string = Printf.sprintf "Field '%s' should contain an string representing wrapping key used for the PKCS#11 patchset 1" (String.concat "." groupable_cp#get_name) in print_error error_string;
     raise Config_file_wrong_type;
   end;
   () 

let load_file f =
  let ic = open_in f in
  let n = in_channel_length ic in
  let s = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
  (s)

let check_occurences big_string to_match conf_file message = 
  let regexp = Str.regexp to_match in
  let matchings = Str.string_match regexp big_string 0 in
  if matchings = true then
    let warning_string = Printf.sprintf "Warning: found multiple occurrences of entry '%s' in the configuration file '%s', only using the first one!" message conf_file in netplex_log_warning warning_string;
  () 

let get_config configuration_file =
  (* Check if the config file exists *)
  let check_conf_file = Sys.file_exists configuration_file in
  if check_conf_file = true
  then
  begin
    (* First, we check for multiple entries for the same field *)
    let options_list = ["debug"; "modules"; "forbidden_mechanisms"; "allowed_labels"; "allowed_ids"; "forbidden_functions"; "log_subchannel"; "wrapping_format_key"] in
    let file_content = load_file configuration_file in
    let file_content = Str.global_replace (Str.regexp "\n") "\b" file_content in
    let file_content = Str.global_replace (Str.regexp "^") "\b" file_content in
    let regexp_list = List.map (fun a -> (Printf.sprintf ".*\b%s[ ]*=.*\b%s[ ]*=.*" a a, a)) options_list in
    List.iter (fun (a, b) -> check_occurences file_content a configuration_file b) regexp_list;
    (* Then, we try to get all the fields *)
    group#read ~no_default:false ~on_type_error:print_some_help configuration_file;
    (* Get the log subchannel *)
    log_subch := log_subch_#get;
    print_log_subchannel "Log subchannel is: " 0;
    (* get the debug verbosity *)
    debug := debug_#get;
    print_debug_level "Debug level is: " 0;
    (* Get modules aliases *)
    modules := modules_#get;
    if !modules = [] then
    begin
      let error_string = Printf.sprintf "no modules found in the configuration file '%s'" configuration_file in
      print_error error_string; raise Modules_except;
    end;
    print_aliases "Modules are:" 3;
    (* Get forbidden mechanims *)
    forbidden_mechanisms := forbidden_mechanisms_#get;
    (* Sanity check to see if mechanisms are indeed associated to existing aliases *)
    let _ = try check_mechanisms !modules !forbidden_mechanisms with Mechanisms_except -> raise Mechanisms_except in
    print_aliased_mechanisms !forbidden_mechanisms "Forbidden mechanisms are:" 3;
    (* Labelshandling *)
    allowed_labels := allowed_labels_#get;
    (* Sanity check to see if lablels are indeed associated to existing aliases *)
    let _ = try check_labels !modules !allowed_labels with Labels_except -> raise Labels_except in
    print_aliased_labels !allowed_labels "Allowed labels are:" 3;
    (* Labelshandling *)
    allowed_ids := allowed_ids_#get;
    (* Sanity check to see if lablels are indeed associated to existing aliases *)
    let _ = try check_ids !modules !allowed_ids with Ids_except -> raise Ids_except in
    print_aliased_ids !allowed_ids "Allowed ids are:" 3;
    (* Forbidden functions *)
    forbidden_functions := forbidden_functions_#get;
    let _ = try check_functions !modules !forbidden_functions with P11_functions_except -> raise P11_functions_except in
    print_aliased_functions !forbidden_functions "Forbidden PKCS#11 functions are:" 3;
    (* Enforce RO sessions? *)
    enforce_ro_sessions := enforce_ro_sessions_#get;
    let _ = try check_enforce_ro_sessions !modules !enforce_ro_sessions with Enforce_RO_except -> raise Enforce_RO_except in
    print_aliased_ro_enforcement !enforce_ro_sessions "RO session enforcement are:" 3;
    (* Enforce admin operations forbid? *)
    forbid_admin_operations := forbid_admin_operations_#get;
    let _ = try check_forbid_admin_operations !modules !forbid_admin_operations with Forbid_admin -> raise Forbid_admin in
    print_aliased_forbid_admin_operations !forbid_admin_operations "Admin operations forbid are:" 3;
    (* Enforce admin operations forbid? *)
    remove_padding_oracles := remove_padding_oracles_#get;
    let _ = try check_remove_padding_oracles !modules !remove_padding_oracles with Remove_padding_oracles -> raise Remove_padding_oracles in
    print_remove_padding_oracles !remove_padding_oracles "Remove padding oracles:" 3;
    (* Get the specific actions for each PKCS#11 trigger *)
    filter_actions_pre := filter_actions_pre_#get;
    let _ = try check_actions !modules !filter_actions_pre with Actions_except -> raise Actions_except in
    filter_actions_post := filter_actions_post_#get;
    let _ = try check_actions !modules !filter_actions_pre with Actions_except -> raise Actions_except in
    print_filter_actions !filter_actions_pre "Specific pre actions are:" 3;
    print_filter_actions !filter_actions_post "Specific post actions are:" 3;
    (* Check if we have a post or pre actions matching the wrapping key format patch *)
    if (check_for_wraping_post_pre !filter_actions_post = true) || (check_for_wraping_post_pre !filter_actions_pre = true) then
      (* Get the wrapping format key *)
      let wrapping_format_key_string = wrapping_format_key_#get in
      (* Parse the hexadecimal key and set the global variable *)
      let the_wrapping_format_key = try (set_wrapping_key wrapping_format_key_string) with _ -> raise Wrapping_key_except in
      wrapping_format_key := the_wrapping_format_key;
    else
      (* Try to get the wrapping format key *)
      let wrapping_format_key_check_existing = try Some wrapping_format_key_#get with _ -> None in
      if compare wrapping_format_key_check_existing None <> 0 then
        if compare (get wrapping_format_key_check_existing) "" <> 0 then
          let warning_string = Printf.sprintf "Warning: found a wrapping_format_key in the configuration file '%s' without any post or pre action using it!" configuration_file in netplex_log_warning warning_string;
        else
          ()
      else
        ();
    ()
  end
  else
  begin
    let error_string = Printf.sprintf "no filter config file '%s'" configuration_file in
    print_error error_string;
    raise Config_file_none;
  end;
