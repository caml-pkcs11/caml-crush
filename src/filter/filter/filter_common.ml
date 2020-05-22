(************************* MIT License HEADER ************************************
    Copyright ANSSI (2013-2015)
    Contributors : Ryad BENADJILA [ryadbenadjila@gmail.com],
    Thomas CALDERON [calderon.thomas@gmail.com]
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
    File:    src/filter/filter/filter_common.ml

************************** MIT License HEADER ***********************************)
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
exception Wrapping_key_except

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

(* FIXME: putting the wrapping format key as a global variable here  *)
(* is not very clever, but this is the easiest way to share it among *)
(* our configuration and user actions modules                        *)
(* We should move it in the P11 patchset fix in a future release     *)
let wrapping_format_key : char array ref = ref [||]

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
      (* We have not found a match in the hash table, add it     *)
      (* Add an end of line character $ at the end of the string *)
      (* to match to avoid sub strings match                     *)
      let check = Str.string_match (Str.regexp (Printf.sprintf "%s$" a)) b 0 in
      let _ = Hashtbl.add !regexp_hash_tbl (a, b) check in
      (check)) in
   (found)

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

