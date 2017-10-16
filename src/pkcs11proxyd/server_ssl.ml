(************************* MIT License HEADER **********************************
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

    The current source code is part of the PKCS#11 daemon 3] source tree:
 ---------------------- 
| 3] PKCS#11 RPC server|
 ---------------------- 

    Project: PKCS#11 Filtering Proxy
    File:    src/pkcs11proxyd/server_ssl.ml

************************** MIT License HEADER *********************************)

(* Use aliases if this is an old version (< 4.02) of OCaml without a Bytes module *)
IFNDEF OCAML_WITH_BYTES_MODULE THEN
module Bytes = String
ENDIF

IFDEF WITH_SSL THEN
(* Reference those two variables here to avoid circulare dependencies *)
let libnames_config_ref = ref ""
let filter_config_file_ref = ref ""
IFNDEF WITH_SSL_LEGACY THEN
Nettls_gnutls.init();
ENDIF
ENDIF

IFDEF WITH_SSL THEN
let fetch_ssl_params use_ssl cf addr =
IFNDEF WITH_SSL_LEGACY THEN
  let tls_config = Netplex_config.read_tls_config cf addr (Netsys_crypto.current_tls_opt()) in
    (use_ssl, tls_config)
ELSE
  match use_ssl with
  | true ->
      let cafile =
        try
          cf # string_param (cf # resolve_parameter addr "cafile")
        with
          | Not_found ->
          failwith "Required parameter cafile is missing!" in
      let certfile =
        try
          cf # string_param (cf # resolve_parameter addr "certfile")
        with
          | Not_found ->
          failwith "Required parameter certfile is missing!" in
      let certkey =
        try
          cf # string_param (cf # resolve_parameter addr "certkey")
        with
          | Not_found ->
          failwith "Required parameter certkey is missing!" in
      let cipher_suite =
        try
          Some (cf # string_param (cf # resolve_parameter addr "cipher_suite"))
        with
          | Not_found -> (None); in
      (* PFS handling *)
      let dh_params =
        try
          Some (cf # string_param (cf # resolve_parameter addr "dh_params"))
        with
          | Not_found -> (None); in
      let ec_curve_name =
        try
          Some (cf # string_param (cf # resolve_parameter addr "ec_curve_name"))
        with
          | Not_found -> (None); in
      if cipher_suite = None
      then
      begin
          let s = Printf.sprintf "CONFIGURATION: you did not set any cipher_suite list, it will use the OpenSSL HIGH suites!" in
          Netplex_cenv.log `Info s;
      end;
      (* Certificate verification depth *)
      let verify_depth =
        try
          Some (cf # int_param (cf # resolve_parameter addr "verify_depth"))
        with
          | Not_found -> (None); in

      (* DHE PFS handling *)
      if dh_params = None
      then
      begin
          let s = Printf.sprintf "CONFIGURATION: you did not set any dh_params list, PFS DHE suites disabled" in
          Netplex_cenv.log `Info s;
      end;
      (* ECDHE PFS handling *)
      if ec_curve_name = None
      then
      begin
          let s = Printf.sprintf "CONFIGURATION: you did not set any ec_curve_name list, PFS ECDHE suites disabled" in
          Netplex_cenv.log `Info s;
      end;
      let allowed_clients_cert_path =
        try
          Some (cf # string_param (cf # resolve_parameter addr "allowed_clients_cert_path"))
        with
          | Not_found -> (None); in
      if allowed_clients_cert_path = None
      then
      begin
          let s = Printf.sprintf "CONFIGURATION: you did not set any allowed_clients_cert_path, any client with a proper certificate will be accepted" in
          Netplex_cenv.log `Info s;
      end
      else
      begin
        let path = (match allowed_clients_cert_path with Some x -> x | _ -> "") in
        let check_dir = (try Sys.is_directory path with
           _ -> false) in
         if check_dir = false then
           let s = Printf.sprintf "Error: forbidden client certificates folder %s does not exist!" path in
           failwith s
      end;
        (use_ssl, cafile, certfile, certkey, cipher_suite, dh_params, ec_curve_name, verify_depth, allowed_clients_cert_path)
  | false -> (use_ssl, "", "", "", None, None, None, None, None)
ENDIF
ENDIF

(* WITH SSL *)
IFDEF WITH_SSL THEN
let configure cf addr =
  (* Handle filter passthrough for the specific C_LoadModule call *)
  let filter_config_file =
    try
      Some (cf # string_param (cf # resolve_parameter addr "filter_config"))
    with
      | Not_found -> (None); in
  let libnames_config =
    try
      Some (cf # string_param (cf # resolve_parameter addr "libnames"))
    with
      | Not_found -> (None); in
  let use_ssl =
    try
      cf # bool_param (cf # resolve_parameter addr "use_ssl")
    with
      | Not_found -> false in
IFDEF WITHOUT_FILTER THEN
  if filter_config_file <> None
  then
  begin
      let s = Printf.sprintf "CONFIGURATION: unused option 'filter_config' found in the server configuration file while the server has been compiled with filter passthrough!" in
      Netplex_cenv.log `Info s;
  end;
  if libnames_config = None
  then
  begin
      failwith "Required parameter libnames is missing! (server compiled with filter passthrough mode)!";
  end;
  libnames_config_ref := (match libnames_config with None -> "" | Some x -> x);
  (fetch_ssl_params use_ssl cf addr)
ELSE
  if libnames_config <> None
  then
  begin
      let s = Printf.sprintf "CONFIGURATION: unused option 'libnames' found in the server configuration file while the server has been compiled to use the filter module!" in
      Netplex_cenv.log `Info s;
  end;
  if filter_config_file = None
  then
  begin
      failwith "Required parameter filter_config is missing! (this is a path to the filter configuration rules)";
  end;
  filter_config_file_ref := (match filter_config_file with
                                          Some value -> (value)
                                          | None -> "");
  (fetch_ssl_params use_ssl cf addr)

ENDIF
ENDIF

IFDEF WITH_SSL_LEGACY THEN
(* Note: since we check for Ocaml-ssl > 0.4.7, we should *)
(* not have issues with unsupported ciphers anymore      *)
let unsupported_suites = ref [""]


(* We do not let OpenSSL fallback to ugly ciphers *)
let exclude_bad_ciphers = ref "!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4"


(* Check if an element is in a list *)
let check_element_in_suites_list the_list element =
  (* Find the element *)
  let found = try Some (List.find (fun a -> compare a element = 0) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
  begin
    (* Notify the user that the suite he specified is unsupported *)
    let s = Printf.sprintf "CONFIGURATION: the '%s' SSL cipher suite is currently *not* supported by OCaml OpenSSL bindings => it is *removed* from the cipher suites that will be used!" element in
    Netplex_cenv.log `Info s;
    (true)
  end

(* Filter the unsupported suites *)
let filter_PFS_ciphers ciphers =
  (* Split the string with : *)
  let the_list = Str.split (Str.regexp ":") ciphers in
  (* For each suite, check if it is unsupported, and don't keep it if this is the case *)
  let new_list = List.filter (fun a -> check_element_in_suites_list !unsupported_suites a = false) the_list in
  let new_ciphers = String.concat ":" new_list in
  (new_ciphers)

(* Filter the empty ciphers suite or the one only containing *)
(* negative expressions                                      *)
let check_negative_only_ciphers ciphers = 
  (* Split the string with : *)
  let the_list = Str.split (Str.regexp ":") ciphers in
  let check = List.fold_left (fun boolean element -> if compare (Str.string_match (Str.regexp "!") element 0) false = 0 then false else boolean) true the_list in
  (check)

let check_empty_negative_only_suites ciphers =
  if compare ciphers "" = 0 then
  begin
    (* Empty ciphers suite case *)
    let ciphers =  String.concat ":" ["HIGH"; ciphers] in
    let s = Printf.sprintf "CONFIGURATION: the cipher_suite list is empty => we will use the OpenSSL HIGH suites!" in
    Netplex_cenv.log `Info s;
    (ciphers)
  end
  else
  begin
    (* Check for the presence of negative only expressions *)
    let check_neg = check_negative_only_ciphers ciphers in
    if compare check_neg true = 0 then
    begin
      let ciphers =  String.concat ":" ["HIGH"; ciphers] in
      let s = Printf.sprintf "CONFIGURATION: the cipher_suite list only contains negative expressions => we will append the OpenSSL HIGH suites!" in
       Netplex_cenv.log `Info s;
      (ciphers)
    end
    else
      (* If there was no problem, just return the input ciphers *)
      (ciphers)
  end

(* This function checks in the allowed_clients_cert_path folder if a given client *)
(* is allowed                                                                     *)
let read_file f =
  let ic = open_in f in
  let n = in_channel_length ic in
  let s = String.create n in
  really_input ic s 0 n;
  close_in ic;
  (s)

let check_is_client_certificate_allowed allowed_clients_cert_path client_cert =
  match allowed_clients_cert_path with
     None -> true
   | Some path ->
     (* Go through all the client certificates in the path *)
     let check_dir = (try Sys.is_directory path with
       _ -> false) in
     if check_dir = true then
       (* List all files in the directory *)
       let cert_files = Sys.readdir path in
       (* Get the client certificate string *)
       let tmp_file = Filename.temp_file "pkcs11proxy_server" "client_cert" in
       let _ = Ssl.write_certificate tmp_file client_cert in
       (* Read the cert file as a string *)
       let client_cert_string = read_file tmp_file in
       let check = ref false in
       Array.iter (
         fun file_name ->
           let to_compare = (try read_file (path ^ Filename.dir_sep ^ file_name) with
             _ ->  ""
           )  in
           if compare to_compare "" = 0 then
             check := !check || false
           else
             if compare to_compare client_cert_string = 0 then
               check := !check || true
             else
               check := !check || false
       ) cert_files;
       (!check)
     else
       let s = Printf.sprintf "Error: forbidden client certificates folder %s does not exist!" path in
       failwith s
(* Ocamlnet is 4.x *)
(*
let check_is_client_certificate_allowed allowed_clients_cert_path client_cert =
  match allowed_clients_cert_path with
     None -> true
   | Some path ->
     (*
     (* Go through all the client certificates in the path *)
     let check_dir = (try Sys.is_directory path with
       _ -> false) in
     if check_dir = true then
       (* List all files in the directory *)
       let cert_files = Sys.readdir path in
       (* Get the client certificate string *)
       let tmp_file = Filename.temp_file "pkcs11proxy_server" "client_cert" in
       let _ = Ssl.write_certificate tmp_file client_cert in
       (* Read the cert file as a string *)
       let client_cert_string = read_file tmp_file in
       let check = ref false in
       Array.iter (
         fun file_name ->
           let to_compare = (try read_file (path ^ Filename.dir_sep ^ file_name) with
             _ ->  ""
           )  in
           if compare to_compare "" = 0 then
             check := !check || false
           else
             if compare to_compare client_cert_string = 0 then
               check := !check || true
             else
               check := !check || false
       ) cert_files;
       (!check)
     else
       let s = Printf.sprintf "Error: forbidden client certificates folder %s does not exist!" path in
       failwith s
    *)
    true
ENDIF
*)

let my_socket_config use_ssl cafile certfile certkey cipher_suite dh_params ec_curve_name verify_depth allowed_clients_cert_path =
  match use_ssl with
  | true ->
    flush stdout;
    Ssl.init();
    let ctx = Ssl.create_context Ssl.TLSv1_2 Ssl.Server_context in
    Ssl.set_verify ctx [ Ssl.Verify_peer; Ssl.Verify_fail_if_no_peer_cert ] None;

    (* Setup given cipher_suite *)
    begin
    match cipher_suite with
        None -> (let new_cipher = String.concat ":" ["HIGH"; !exclude_bad_ciphers] in 
                            try 
                                Ssl.set_cipher_list ctx new_cipher
                            with
                                _ -> let s = Printf.sprintf "Unsupported cipher suite when configuring OpenSSL" in
                                                    failwith s)
       | Some ciphers -> ( let new_ciphers = filter_PFS_ciphers ciphers in
                           let new_ciphers = check_empty_negative_only_suites new_ciphers in
                           let new_cipher = String.concat ":" [new_ciphers; !exclude_bad_ciphers] in 
                            try 
                                Ssl.set_cipher_list ctx new_cipher
                            with
                                _ -> let s = Printf.sprintf "Unsupported cipher list %s" ciphers in
                                                    failwith s)
    end;

    Ssl.set_client_CA_list_from_file ctx cafile;
    begin
    match verify_depth with
     None -> Ssl.set_verify_depth ctx 4;
    | Some params -> Ssl.set_verify_depth ctx params;
    end;

    Ssl.load_verify_locations ctx cafile "" ;
    Ssl.use_certificate ctx certfile certkey;

    begin
    match dh_params with
     None -> ()
    | Some params -> try Ssl.init_dh_from_file ctx params
                        with _ -> let s = Printf.sprintf "Could not set DH params from file %s" params in
                        failwith s
    end;

    begin
    match ec_curve_name with
     None -> ()
    | Some params -> try Ssl.init_ec_from_named_curve ctx params
                        with _ -> let s = Printf.sprintf "Could not set EC curve name %s" params in
                        failwith s
    end;

    Rpc_ssl.ssl_server_socket_config
      ~get_peer_user_name:(fun _ sslsock ->
                   prerr_endline "get_peer_user_name";
                   let cert = Ssl.get_certificate sslsock in
                   let user = Ssl.get_subject cert in
                   (* Check peer client certificate *)
                   let is_client_allowed = check_is_client_certificate_allowed allowed_clients_cert_path cert in
                   if is_client_allowed = false then
                     let s = Printf.sprintf "Unsupported client certificate for user=%s" user in
                     (* Close the socket and quit *)
                     let _ = Ssl.shutdown sslsock in
                     failwith s
                   else
                     prerr_endline ("user=" ^ user);
                     Some user)
        ctx
    | false -> Rpc_server.default_socket_config

ENDIF

IFDEF WITH_SSL THEN
IFDEF WITH_SSL_LEGACY THEN
let socket_config (use_ssl, cafile, certfile, certkey, cipher_suite, dh_params, ec_curve_name, verify_depth, allowed_clients_cert_path) =
  my_socket_config use_ssl cafile certfile certkey cipher_suite dh_params ec_curve_name verify_depth allowed_clients_cert_path
ELSE
let socket_config (use_ssl, tls_config) =
  match use_ssl with
  | false -> Rpc_server.default_socket_config
  | true -> (match tls_config with
     None -> failwith "Failed to read tls configuration"
    |Some config -> Rpc_server.tls_socket_config config)
ENDIF
ENDIF

