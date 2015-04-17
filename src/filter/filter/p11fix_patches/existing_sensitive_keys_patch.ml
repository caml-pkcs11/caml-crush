(************************************************************************)
(* The following patch deals with possible issues regarding keys that   *)
(* have been generated without Caml Crush.                              *)
(* These keys can be dangerous because their values are known and they  *)
(* might be used to leak other keys.                                    *)
(* This patch works as follows:                                         *)
(*   - Paranoid mode: if CKA_SENSITIVE is TRUE and CKA_ALWAYS_SENSITIVE *)
(*     is FALSE, we do not trust the key and do not allow it to be used.*)
(*   - Relaxed mode for key escrow: when used, this mode allows the     *)
(*     usage of keys with CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=  *)
(*     FALSE ONLY if these are encryption/decryption keys and NON LOCAL *)
(*     keys.                                                            *)

type dangerous_sensitive_keys_filtering =
  | PARANOID
  | ESCROW_ENCRYPT_ONLY_KEYS
  | ESCROW_ALL_KEYS

(* Conflicting attributes on sensitive keys *)
let dangerous_sensitive_keys_conflicting_attributes = [|
                                ({Pkcs11.type_ = Pkcs11.cKA_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE}, {Pkcs11.type_ = Pkcs11.cKA_ALWAYS_SENSITIVE; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_FALSE});
                                |]

let detect_dangerous_existing_sensitive_keys function_name sessionh objecth allow_key_escrow =
  (* Detect the conflicting attribute *)
  let check = detect_conflicting_attributes_on_existing_object function_name sessionh objecth dangerous_sensitive_keys_conflicting_attributes in
  if compare check true = 0 then
    (* We have detected a conflicting attribute regerding sensitive keys *)
    if compare allow_key_escrow 0 = 0 then
      (* We are in paranoid mode, return true *)
      let info_string = Printf.sprintf "[User defined extensions] CONFLICTING_ATTRIBUTES_SENSITIVE_KEYS: conflicting CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=FALSE detected. We are in paranoid mode => %s is blocked!\n" function_name in
      let _ = print_debug info_string 1 in
      (true)
    else
      (* For relaxed modes, we only focus on local keys *)
      (* Check if CKA_LOCAL is set                      *)
      let (ret, templates) = filter_getAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_LOCAL; Pkcs11.value = [||]}|] in
      let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
      if compare ret Pkcs11.cKR_OK <> 0 then
        let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_LOCAL (this should not happen ...)\n" in netplex_log_critical s; failwith s
      else
        if compare (Pkcs11.char_array_to_bool templates_values.(0).Pkcs11.value) Pkcs11.cK_FALSE = 0 then
          if compare allow_key_escrow 1 = 0 then
            (* We are in the relaxed mode where we allow ONLY keys with CKA_LOCAL=FALSE and *)
            (* the keys are only for encryption/decryption                                  *)
            let (ret, templates) = filter_getAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_ENCRYPT; Pkcs11.value = [||]}; {Pkcs11.type_ = Pkcs11.cKA_DECRYPT; Pkcs11.value = [||]}|] in
            let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
            if compare ret Pkcs11.cKR_OK <> 0 then
              let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_ENCRYPT/CKA_DECRYPT (this should not happen ...)\n" in netplex_log_critical s; failwith s
            else
              if (compare (Pkcs11.char_array_to_bool templates_values.(0).Pkcs11.value) Pkcs11.cK_TRUE = 0) ||
                 (compare (Pkcs11.char_array_to_bool templates_values.(1).Pkcs11.value) Pkcs11.cK_TRUE = 0) then
                (* => CKA_ENCRYPT=TRUE or CKA_DECRYPT=TRUE *)
                let info_string = Printf.sprintf "[User defined extensions] CONFLICTING_ATTRIBUTES_SENSITIVE_KEYS: conflicting CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=FALSE detected. We are in relaxed key escrow mode (for ENCRYPT/DECRYPT only non local keys) => %s is NOT blocked!\n" function_name in
                let _ = print_debug info_string 2 in
                (false)
              else
                let info_string = Printf.sprintf "[User defined extensions] CONFLICTING_ATTRIBUTES_SENSITIVE_KEYS: conflicting CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=FALSE detected. We are in relaxed key escrow mode (for ENCRYPT/DECRYPT only non local keys) => %s is blocked!\n" function_name in
                let _ = print_debug info_string 1 in
               (true)
          else
            (* We are in the full relaxed mode where we allow all keys with CKA_LOCAL=FALSE *)
            (* to be escrowed                                                               *)
            let info_string = Printf.sprintf "[User defined extensions] CONFLICTING_ATTRIBUTES_SENSITIVE_KEYS: conflicting CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=FALSE detected. We are in relaxed key escrow mode (for all non local keys) => %s is NOT blocked!\n" function_name in
            let _ = print_debug info_string 2 in
            (false)
        else
          (* This is not a non local key, we block its usage since there is no reason for such local keys *)
          (* to exist! (i.e. with CKA_SENSITIVE=TRUE and CKA_ALWAYS_SENSITIVE=FALSE).                     *)
          (true)
  else
    (* No conflicting attribute, all is OK *)
    (false)

(*** This patch is an addendum to the original CryptokiX patch  ***)
let dangerous_sensitive_keys function_name arg allow_key_escrow =
  let allow_key_escrow_integer = (
    match allow_key_escrow with
      | PARANOID -> 0
      | ESCROW_ENCRYPT_ONLY_KEYS -> 1
      | ESCROW_ALL_KEYS -> 2
  ) in
  match function_name with
  (* Crypto operations *)
    ("C_EncryptInit" | "C_DecryptInit" | "C_SignInit" | "C_SignRecoverInit" | "C_VerifyInit" | "C_VerifyRecoverInit") ->
     let (sessionh, _, ckobjecthandlet_) = deserialize arg in
     let check = detect_dangerous_existing_sensitive_keys function_name sessionh ckobjecthandlet_ allow_key_escrow_integer in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID)))
     else
       (serialize (false, ()))
  | "C_DeriveKey" ->
     let (sessionh, _, initial_key_handle, _) = deserialize arg in
     let check = detect_dangerous_existing_sensitive_keys function_name sessionh initial_key_handle allow_key_escrow_integer in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
     else
       (serialize (false, ()))
  | "C_DigestKey" ->
     let (sessionh, ckobjecthandlet_) = deserialize arg in
     let check = detect_dangerous_existing_sensitive_keys function_name sessionh ckobjecthandlet_ allow_key_escrow_integer in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID)))
     else
       (serialize (false, ()))
  | "C_WrapKey" ->
     let (sessionh, _, wrapping_handle, wrapped_handle) = deserialize arg in
     let check_one = detect_dangerous_existing_sensitive_keys function_name sessionh wrapping_handle allow_key_escrow_integer in
     let check_two = detect_dangerous_existing_sensitive_keys function_name sessionh wrapped_handle allow_key_escrow_integer in
     if (compare check_one true = 0) || (compare check_two true = 0) then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, [||])))
     else
       (serialize (false, ()))
  | "C_UnwrapKey" ->
     let (sessionh, _, unwrapping_handle, _, _) = deserialize arg in
     let check = detect_dangerous_existing_sensitive_keys function_name sessionh unwrapping_handle allow_key_escrow_integer in
     if compare check true = 0 then
       (serialize (true, (Pkcs11.cKR_OBJECT_HANDLE_INVALID, Pkcs11.cK_INVALID_HANDLE)))
     else
       (serialize (false, ()))
  | "C_FindObjects" ->
    let (sessionh, _) = deserialize arg in
    (* We filter the global object list and remove objects that don't fit our policy *)
    let new_current_find_objects_filtered_handles = !current_find_objects_filtered_handles in
    Array.iter (
      fun handle ->
        let check = detect_dangerous_existing_sensitive_keys function_name sessionh handle allow_key_escrow_integer in
        if compare check true = 0 then
          current_find_objects_filtered_handles := Array.of_list (
             (* Remove the handle from the array since it is a 'bad' object *)
              List.filter (
                  fun curr_handle -> if compare handle curr_handle = 0 then false else true
                ) (Array.to_list !current_find_objects_filtered_handles)
            )
        else
          ()
    ) new_current_find_objects_filtered_handles;
    (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))

(***********************************************************************)
let dangerous_sensitive_keys_paranoid function_name arg = dangerous_sensitive_keys function_name arg PARANOID

let dangerous_sensitive_keys_escrow_encrypt function_name arg = dangerous_sensitive_keys function_name arg ESCROW_ENCRYPT_ONLY_KEYS 

let dangerous_sensitive_keys_escrow_all function_name arg = dangerous_sensitive_keys function_name arg ESCROW_ALL_KEYS
