(************************* CeCILL-B HEADER ************************************
    Copyright ANSSI (2013)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]

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

    This software is governed by the CeCILL-B license under French law and
    abiding by the rules of distribution of free software.  You can  use,
    modify and/ or redistribute the software under the terms of the CeCILL-B
    license as circulated by CEA, CNRS and INRIA at the following URL
    "http://www.cecill.info".

    As a counterpart to the access to the source code and  rights to copy,
    modify and redistribute granted by the license, users are provided only
    with a limited warranty  and the software's author,  the holder of the
    economic rights,  and the successive licensors  have only  limited
    liability.

    In this respect, the user's attention is drawn to the risks associated
    with loading,  using,  modifying and/or developing or reproducing the
    software by the user in light of its specific status of free software,
    that may mean  that it is complicated to manipulate,  and  that  also
    therefore means  that it is reserved for developers  and  experienced
    professionals having in-depth computer knowledge. Users are therefore
    encouraged to load and test the software's suitability as regards their
    requirements in conditions enabling the security of their systems and/or
    data to be ensured and,  more generally, to use and operate it in the
    same conditions as regards security.

    The fact that you are presently reading this means that you have had
    knowledge of the CeCILL-B license and that you accept its terms.

    The current source code is part of the PKCS#11 filter 4] source tree:

           |                                             
 ----------------------                                  
| 4] PKCS#11 filter    |                                 
 ----------------------                                  
           |                                             

    Project: PKCS#11 Filtering Proxy
    File:    src/filter/filter/filter_common.ml

************************** CeCILL-B HEADER ***********************************)
(** Defining the configure exceptions **)
exception Config_file_none
exception Config_file_wrong_type
exception Config_file_double_entry
exception Mechanisms_except
exception Modules_except
exception Mechanism_forbidden
exception Find_list_except
exception Labels_except
exception Ids_except
exception P11_functions_except
exception Enforce_RO_except
exception Forbid_admin
exception Remove_padding_oracles
exception Actions_except

(** Generic function to get the value of an option **)
let get = function
  | Some x -> x
  | None   -> raise (Invalid_argument "Option.get")

(************************************)
(* Global variables and structures  *)
(* of the filter core engine        *)
(************************************)
let current_find_objects_filtered_handles : Pkcs11.ck_object_handle_t array ref = ref [| |]
(* Current module if it is loaded *)
let current_module : string option ref = ref None


(****************************)
(* Basic logging primitives *)
(****************************)
(* Channel variable needed for logging *)
let log_subch = ref ""
let debug = ref 0

let netplex_log_info s =
  if String.length !log_subch <> 0 then
  begin
    (Netplex_cenv.self_cont()) # log_subch !log_subch `Info s;
    ()
  end
  else
  begin
    Netplex_cenv.log `Info s;
    ()
  end

let netplex_log_warning s =
  if String.length !log_subch <> 0 then
  begin
    (Netplex_cenv.self_cont()) # log_subch !log_subch `Warning s;
    ()
  end
  else
  begin
    Netplex_cenv.log `Warning s;
    ()
  end

let netplex_log_error s =
  if String.length !log_subch <> 0 then
  begin
    (Netplex_cenv.self_cont()) # log_subch !log_subch `Err s;
    ()
  end
  else
  begin
    Netplex_cenv.log `Err s;
    ()
  end

let netplex_log_critical s =
  if String.length !log_subch <> 0 then
  begin
    (Netplex_cenv.self_cont()) # log_subch !log_subch `Crit s;
    ()
  end
  else
  begin
    Netplex_cenv.log `Crit s;
    ()
  end

let print_debug message level =
  (* We only print the message if the debug level is sufficient *)
  if level <= !debug
  then
  begin
    let s = Printf.sprintf "[PKCS#11 FILTER pid %d] [DEBUG_LEVEL %d/%d] %s" (Unix.getpid()) level !debug message in
    netplex_log_info s;
  end;
  ()

let print_error message =
  let s = Printf.sprintf "[PKCS#11 FILTER pid %d] ERROR: %s" (Unix.getpid()) message in
  netplex_log_error s;
  ()

(************************************)
(**** Basic checking primitives *****)
(* Check if an element is in a list *)
let check_element_in_list the_list element =
   (* Find the element *)
  let found = try Some (List.find (fun a -> compare a element = 0) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
    (true)

(* The hash table that keeps track of regexp/string matching or unmatching *)
let regexp_hash_tbl = ref (Hashtbl.create 0)

(* Check if b fits the regexp in a *)
let check_regexp a b =
  (* Check if we already have a positive match in our hash table *)
  let found = (try Hashtbl.find !regexp_hash_tbl (a,b) with
    (* If a match is found, return it *)
    Not_found -> 
      (* We have not found a match in the hash table, add it *)
      (* Add an end of line character $ at the end of the string *)
      (* to match to avoid sub strings match                     *)
      let check = Str.string_match (Str.regexp (Printf.sprintf "%s$" a)) b 0 in
      let _ = Hashtbl.add !regexp_hash_tbl (a, b) check in
      (check)) in
   (found)

(* Check if b fits the regexp in a *)
let check_regexp_ a b =
      (Str.string_match (Str.regexp (Printf.sprintf "%s$" a)) b 0)

(* Check if an element is in a regexp string list *)
let check_regexp_element_in_list the_list element =
   (* Find the element *)
  let found = try Some (List.find (fun a -> check_regexp a element = true) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
    (true)

(* Check if an alias is indeed present in the couples list as a first element *)
let check_alias the_list alias =
  (* Find the element *)
  let found = try Some (List.find (fun (a, _) -> check_regexp alias a = true) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
    (true)

let get_aliases_from_regexp the_list regexp =
  (* For each alias in the list, get *)
  let matched_aliases = List.fold_left (fun s (a, _) -> let ret_s = if check_regexp regexp a = true then Printf.sprintf "%s '%s'" s a else s in (ret_s)) "" the_list in
  (matched_aliases)

