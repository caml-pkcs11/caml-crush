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
    File:    src/filter/filter/filter_actions.ml

************************** CeCILL-B HEADER ***********************************)
(* The following file can be seen as a "plugins" extension    *)
(* to the fiter rules. All the actions described here after   *)
(* can be called from within the filter engine BEFORE any     *)
(* filtering rule is applied: in that sense, actions can be   *)
(* seen as a full extension and/or replacement of the genuine *)
(* rules that are already offered by the filter. See the      *)
(* documentation for more details on how to add new actions   *)
(* and how they interact with the filter engine.              *)  

open Config_file
open Filter_common

(* WARNING: marshalling is type unsafe: care must be taken *)
(* when defining custom actions!                           *)
(* In any case, if the serialize or deserialize fail, we   *)
(* force a container exit!                                 *)
let serialize x = try Marshal.to_string x [] with _ -> print_error "MARSHALLING ERROR when serializing! Check your custom functions! KILLING the container ..."; exit 0
let deserialize x = try Marshal.from_string x 0 with _ -> print_error "MARSHALLING ERROR when deserializing! Check your custom functions! KILLING the container ..."; exit 0


(********* CUSTOM actions ******)
let c_Initialize_hook _ = 
  let s = Printf.sprintf " ########## Hooking C_Initialize!" in
  print_debug s 1; 
  let return_value = serialize (false, ()) in
  (return_value)

let c_Login_hook arg = 
  let (cksessionhandlet_, ckusertypet_, pin) = (deserialize arg) in
  if compare (Pkcs11.byte_array_to_string pin) "1234" = 0 then
    (* Passtrhough if pin is 1234 *)
    let s = Printf.sprintf " ######### Passthrough C_Login with pin %s!" (Pkcs11.byte_array_to_string pin) in
    print_debug s 1;
    (serialize (false, ()))
  else
  begin
    (* Hook the call if pin != 1234 *)
    let s = Printf.sprintf " ######### Hooking C_Login with pin %s!" (Pkcs11.byte_array_to_string pin) in
    print_debug s 1;
    let return_value = serialize (true, Pkcs11.cKR_PIN_LOCKED) in
    (return_value)
  end

let identity _ = 
  let s = Printf.sprintf " ######### Identity hook called!" in
  print_debug s 1;
  let return_value = serialize (false, ()) in
  (return_value)


(********* CUSTOM actions wrappers for the cionfiguration file ******)
let execute_action action argument = match action with
  "c_Initialize_hook" -> c_Initialize_hook argument
| "c_Login_hook" -> c_Login_hook argument
| "identity" -> identity argument
| _ -> identity argument

let string_check_action a = match a with
  "c_Initialize_hook" -> a
| "c_Login_hook" -> a
| "identity" -> a
| _ -> let error_string = Printf.sprintf "Error: unknown action option '%s'!" a in netplex_log_critical error_string; raise Config_file_wrong_type


(* Wrapper for actions defined in the plugin *)
let actions_wrappers = {
  to_raw = (fun input -> Config_file.Raw.String input);
  of_raw = function
    | Config_file.Raw.String input -> string_check_action input
    | _ -> netplex_log_critical "Error: got wrong action type!"; raise Config_file_wrong_type
}
