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

    The current source code is part of the client library 5] source tree:
                                                          --------------------
                                                         | 5] Client library  |
                                                         |  --------          |
                                                         | |        | PKCS#11 |
                                                         | |        |functions|
                                                         |  --------          |
                                                          --------------------
                                                                    |
                                                                    |
                                                          { PKCS#11 INTERFACE }
                                                                    |
                                                              APPLICATION

    Project: PKCS#11 Filtering Proxy
    File:    src/client-lib/client.ml

************************** MIT License HEADER ***********************************)
open Pkcs11_rpc_aux

open Rpc_helpers


(*IFDEF UNIX_SOCKET THEN
IFDEF TCP_SOCKET THEN*)
(* Send an error: these two can't be defined at the same time *)
(*ENDIF
ENDIF*)

(* Getting the timeout if it is set in an environment variable *)
let rpc_timeout = 
  let check_env = (try Sys.getenv("PKCS11PROXY_RPC_TIMEOUT") 
    (* An RPC timeout of 25 seconds is the default *)
    with _ -> "25") in
  let timeout = (try float_of_string check_env with
    (* An RPC timeout of 25 seconds is the default *)
    _ -> 25.0) in
  (timeout)

(* Getting the socket path from the defined variable or 
from the environment *)
(* Get the path *)
IFDEF SOCKET_PATH THEN
let path = SOCKET_PATH
ELSE
let path = (try Sys.getenv("PKCS11PROXY_SOCKET_PATH") with
  _ -> "")
ENDIF
IFDEF UNIX_SOCKET THEN
let get_socket_path = 
  (* UNIX socket *)
  if path = "" then
  begin
    raise (Failure "Error: unix socket path is empty!")
  end;
  path
ELSE
let get_socket_path = 
  (* TCP socket *)
  let l = Str.split (Str.regexp ":") path in
  if  List.length l != 2 then
  begin
    let error_string = Printf.sprintf "Error: tcp socket path %s is malformed" path in
    raise (Failure error_string)
  end
  else
  begin
    (List.nth l 0, int_of_string (List.nth l 1))
  end
ENDIF

(* WITH SSL *)
IFDEF WITH_SSL THEN
(* Handle the path case *)
IFDEF SSL_FILES_PATH THEN
let ca_file_path = PKCS11PROXY_CA_FILE
let cert_file_path = PKCS11PROXY_CERT_FILE
let private_key_file_path = PKCS11PROXY_PRIVKEY_FILE
ENDIF
(* Handle the env case *)
IFDEF SSL_FILES_ENV THEN
let ca_file_path = (try Sys.getenv("PKCS11PROXY_CA_FILE") with
  _ -> failwith "Error: could not get PKCS11PROXY_CA_FILE from env")
let cert_file_path = (try Sys.getenv("PKCS11PROXY_CERT_FILE") with
  _ -> failwith "Error: could not get PKCS11PROXY_CERT_FILE from env")
let private_key_file_path = (try Sys.getenv("PKCS11PROXY_PRIVKEY_FILE") with
  _ -> failwith "Error: could not get PKCS11PROXY_PRIVKEY_FILE from env")
ENDIF
(* Handle the embed case *)
IFDEF SSL_FILES_EMBED THEN
(* We include the .inc files generated by autoconf *)
INCLUDE "ca_file.inc"
INCLUDE "cert_file.inc"
INCLUDE "private_key_file.inc"
(* Create temp files from these *)
let ca_file_path = Filename.temp_file "pkcs11proxy_client" "ca_file"
let cert_file_path = Filename.temp_file "pkcs11proxy_client" "cert_file"
let private_key_file_path = Filename.temp_file "pkcs11proxy_client" "private_key_file"
(* Open the temp files and write the certificates inside them *)
let write_string_to_file path str = 
   let oc = open_out_gen [Open_wronly; Open_append; Open_text] 0o600 path in
   Printf.fprintf oc "%s" str;
   close_out oc
let ssl_socket_config cafile certfile certkey =
   List.iter (write_string_to_file ca_file_path) ca_file_buff;
   write_string_to_file certfile cert_file_buff;
   write_string_to_file certkey private_key_file_buff;
   Ssl.init();
   let ctx = Ssl.create_context Ssl.TLSv1 Ssl.Client_context in
   Ssl.set_verify ctx [ Ssl.Verify_peer ] None;
   Ssl.set_verify_depth ctx 4;
   Ssl.load_verify_locations ctx cafile "" ;
   Ssl.use_certificate ctx certfile certkey;
   let rpc = Rpc_ssl.ssl_client_socket_config ctx in
   (* Now that the socket has been established, we can 
      safely remove the temp files *)
   Sys.remove ca_file_path;
   Sys.remove cert_file_path;
   Sys.remove private_key_file_path;
   (rpc)
ELSE
let ssl_socket_config cafile certfile certkey =
   Ssl.init();
   let ctx = Ssl.create_context Ssl.TLSv1 Ssl.Client_context in
   Ssl.set_verify ctx [ Ssl.Verify_peer ] None;
   Ssl.set_verify_depth ctx 4;
   Ssl.load_verify_locations ctx cafile "" ;
   Ssl.use_certificate ctx certfile certkey;
   Rpc_ssl.ssl_client_socket_config ctx
ENDIF

let socket_ctx = ssl_socket_config ca_file_path cert_file_path private_key_file_path
  
(* WITHOUT SSL *)
ELSE
let socket_ctx = Rpc_client.default_socket_config
ENDIF


(* create_client2 *)
let rpc_client = ref None

let get_rpc_client ref_to_rpc_client = 
	match !ref_to_rpc_client with
		| None -> raise (Failure "Client is not initialized")
		| Some x -> x

IFDEF UNIX_SOCKET THEN
let rpc_connect () = 
	begin
	Netsys_signal.init();
	(* UNIX SOCKET *)
	let path = get_socket_path in
	rpc_client := Some (Pkcs11_rpc_clnt.P.V.create_client2
		  (`Socket(Rpc.Tcp,
			   Rpc_client.Unix(path),
			   socket_ctx))
  		  );
        match !rpc_client with
            Some client -> Rpc_client.configure client 0 rpc_timeout
          | _ -> ()
	end
ELSE
let rpc_connect () =
	begin
	Netsys_signal.init();
	(* TCP SOCKET *)
	let (host, port) = get_socket_path in
        rpc_client := Some (Pkcs11_rpc_clnt.P.V.create_client2
          (`Socket(Rpc.Tcp,
               Rpc_client.Inet(host, port),
               socket_ctx))
		);
        match !rpc_client with
            Some client -> Rpc_client.configure client 0 rpc_timeout
          | _ -> ()
	end
ENDIF
let _ = Callback.register "RPC_connect" rpc_connect

let shut_down_client () = 
    Rpc_client.shut_down (get_rpc_client rpc_client);
	()
let _ = Callback.register "Shut_Down_Client" shut_down_client


let c_SetupArch client_arch = 
	let ret = Pkcs11_rpc_clnt.P.V.c_setuparch (get_rpc_client rpc_client) client_arch in
	ret
let _ = Callback.register "C_SetupArch" c_SetupArch

(* Client side load module *)
let c_LoadModule libname = 
	(* Get the libname in the config file *)
	let ret = Pkcs11_rpc_clnt.P.V.c_loadmodule (get_rpc_client rpc_client) libname in
	ret

let _ = Callback.register "C_LoadModule" c_LoadModule

let c_Initialize () = 
    let ret = Pkcs11_rpc_clnt.P.V.c_initialize (get_rpc_client rpc_client) () in
    ret

let _ = Callback.register "C_Initialize" c_Initialize


let c_GetSlotList token_present count = 
    let ret = Pkcs11_rpc_clnt.P.V.c_getslotlist (get_rpc_client rpc_client) (token_present, count) in 
    (ret.c_getslotlist_rv , ret.c_getslotlist_slot_list, ret.c_getslotlist_count)
let _ = Callback.register "C_GetSlotList" c_GetSlotList


let c_Finalize () =
    let ret = Pkcs11_rpc_clnt.P.V.c_finalize (get_rpc_client rpc_client) () in 
    ret

let _ = Callback.register "C_Finalize" c_Finalize

let c_GetInfo () =
    let ret = Pkcs11_rpc_clnt.P.V.c_getinfo (get_rpc_client rpc_client) () in
    (ret.c_getinfo_rv , (ck_info_rpc_aux_to_pkcs11 ret.c_getinfo_info))
let _ = Callback.register "C_GetInfo" c_GetInfo

let c_WaitForSlotEvent flags =
    let ret = Pkcs11_rpc_clnt.P.V.c_waitforslotevent (get_rpc_client rpc_client) (flags) in
    (ret.c_waitforslotevent_rv , ret.c_waitforslotevent_count )
let _ = Callback.register "C_WaitForSlotEvent" c_WaitForSlotEvent

let c_GetSlotInfo slot_id = 
    let ret = Pkcs11_rpc_clnt.P.V.c_getslotinfo (get_rpc_client rpc_client) (slot_id) in
    (ret.c_getslotinfo_rv , (ck_slot_info_rpc_aux_to_pkcs11 ret.c_getslotinfo_slot_info) )
let _ = Callback.register "C_GetSlotInfo" c_GetSlotInfo

let c_GetTokenInfo slot_id = 
    let ret = Pkcs11_rpc_clnt.P.V.c_gettokeninfo (get_rpc_client rpc_client) (slot_id) in
    (ret.c_gettokeninfo_rv , (ck_token_info_rpc_aux_to_pkcs11 ret.c_gettokeninfo_token_info))
let _ = Callback.register "C_GetTokenInfo" c_GetTokenInfo

let c_Login handle user_type pin = 
   let real_pin = (Pkcs11.char_array_to_string pin) in
    let ret = Pkcs11_rpc_clnt.P.V.c_login (get_rpc_client rpc_client) (handle, user_type, real_pin) in
    ret
let _ = Callback.register "C_Login" c_Login

let c_Logout handle = 
    let ret = Pkcs11_rpc_clnt.P.V.c_logout (get_rpc_client rpc_client) (handle) in
    ret
let _ = Callback.register "C_Logout" c_Logout

let c_OpenSession slot_id flags = 
    let ret = Pkcs11_rpc_clnt.P.V.c_opensession (get_rpc_client rpc_client) (slot_id, flags) in
    (ret.c_opensession_rv , ret.c_opensession_handle )
let _ = Callback.register "C_OpenSession" c_OpenSession

let c_CloseSession session = 
    let ret = Pkcs11_rpc_clnt.P.V.c_closesession (get_rpc_client rpc_client) (session) in
    ret
let _ = Callback.register "C_CloseSession" c_CloseSession

let c_GetMechanismList slot_id count = 
   let ret = Pkcs11_rpc_clnt.P.V.c_getmechanismlist (get_rpc_client rpc_client) (slot_id, count) in 
    (ret.c_getmechanismlist_rv , ret.c_getmechanismlist_list, ret.c_getmechanismlist_count )
let _ = Callback.register "C_GetMechanismList" c_GetMechanismList


let c_CloseAllSessions slot_id = 
    let ret = Pkcs11_rpc_clnt.P.V.c_closeallsessions (get_rpc_client rpc_client) (slot_id) in
    ret
let _ = Callback.register "C_CloseAllSessions" c_CloseAllSessions

let c_GetSessionInfo session = 
   let ret = Pkcs11_rpc_clnt.P.V.c_getsessioninfo (get_rpc_client rpc_client) (session) in 
    (ret.c_getsessioninfo_rv , (ck_session_info_rpc_aux_to_pkcs11 ret.c_getsessioninfo_info) )
let _ = Callback.register "C_GetSessionInfo" c_GetSessionInfo

let c_GetMechanismInfo slot_id mechanism_type = 
    let ret = Pkcs11_rpc_clnt.P.V.c_getmechanisminfo (get_rpc_client rpc_client) (slot_id, mechanism_type ) in
    (ret.c_getmechanisminfo_rv , (ck_mechanism_info_rpc_aux_to_pkcs11 ret.c_getmechanisminfo_info) )
let _ = Callback.register "C_GetMechanismInfo" c_GetMechanismInfo

let c_InitPIN session_handle pin = 
   let real_pin = (Pkcs11.char_array_to_string pin) in
   let ret = Pkcs11_rpc_clnt.P.V.c_initpin (get_rpc_client rpc_client) (session_handle, real_pin) in 
    ret
let _ = Callback.register "C_InitPINT" c_InitPIN

let c_SetPIN session_handle old_pin new_pin = 
   let real_old_pin = (Pkcs11.char_array_to_string old_pin) in
   let real_new_pin = (Pkcs11.char_array_to_string new_pin) in
   let ret = Pkcs11_rpc_clnt.P.V.c_setpin (get_rpc_client rpc_client) (session_handle, real_old_pin, real_new_pin) in 
    ret
let _ = Callback.register "C_SetPIN" c_SetPIN

let c_SeedRandom session_handle seed = 
   let real_seed = (Pkcs11.char_array_to_string seed) in
   let ret = Pkcs11_rpc_clnt.P.V.c_seedrandom (get_rpc_client rpc_client) (session_handle, real_seed) in 
    ret
let _ = Callback.register "C_SeedRandom" c_SeedRandom

let c_InitToken slot_id so_pin label = 
   let real_so_pin = (Pkcs11.char_array_to_string so_pin) in
   let real_label = (Pkcs11.char_array_to_string label) in
   let ret = Pkcs11_rpc_clnt.P.V.c_inittoken (get_rpc_client rpc_client) (slot_id, real_so_pin, real_label) in 
    ret
let _ = Callback.register "C_InitToken" c_InitToken

let c_GenerateRandom session_handle count = 
   let ret = Pkcs11_rpc_clnt.P.V.c_generaterandom (get_rpc_client rpc_client) (session_handle, count) in
    (ret.c_generaterandom_rv , (Pkcs11.string_to_char_array ret.c_generaterandom_data) )
let _ = Callback.register "C_GenerateRandom" c_GenerateRandom

let c_FindObjectsInit session_handle attributes = 
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_findobjectsinit (get_rpc_client rpc_client) (session_handle, real_attributes) in 
   ret
let _ = Callback.register "C_FindObjectsInit" c_FindObjectsInit

let c_FindObjects session_handle count = 
   let ret = Pkcs11_rpc_clnt.P.V.c_findobjects (get_rpc_client rpc_client) (session_handle, count) in 
    (ret.c_findobjects_rv , ret.c_findobjects_objects, ret.c_findobjects_count )
let _ = Callback.register "C_FindObjects" c_FindObjects

let c_FindObjectsFinal session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_findobjectsfinal (get_rpc_client rpc_client) (session_handle) in 
   ret
let _ = Callback.register "C_FindObjectsFinal" c_FindObjectsFinal

let c_GenerateKey session_handle mechanism attributes = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_generatekey (get_rpc_client rpc_client) (session_handle, real_mechanism, real_attributes) in 
   (ret.c_generatekey_rv , ret.c_generatekey_handle )
let _ = Callback.register "C_GenerateKey" c_GenerateKey

let c_GenerateKeyPair session_handle mechanism pub_attributes priv_attributes = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let real_pub_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux pub_attributes) in
   let real_priv_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux priv_attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_generatekeypair (get_rpc_client rpc_client) (session_handle, real_mechanism, real_pub_attributes, real_priv_attributes) in 
   (ret.c_generatekeypair_rv , ret.c_generatekeypair_pubhandle , ret.c_generatekeypair_privhandle )
let _ = Callback.register "C_GenerateKeyPair" c_GenerateKeyPair

let c_CreateObject session_handle attributes = 
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_createobject (get_rpc_client rpc_client) (session_handle, real_attributes) in 
   (ret.c_createobject_rv , ret.c_createobject_handle )
let _ = Callback.register "C_CreateObject" c_CreateObject

let c_CopyObject session_handle object_handle attributes = 
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_copyobject (get_rpc_client rpc_client) (session_handle, object_handle, real_attributes) in 
   (ret.c_copyobject_rv , ret.c_copyobject_handle )
let _ = Callback.register "C_CopyObject" c_CopyObject

let c_DestroyObject session_handle object_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_destroyobject (get_rpc_client rpc_client) (session_handle, object_handle) in 
   ret
let _ = Callback.register "C_DestroyObject" c_DestroyObject

let c_GetAttributeValue session_handle object_handle attributes = 
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_getattributevalue (get_rpc_client rpc_client) (session_handle, object_handle, real_attributes) in 
   (ret.c_getattributevalue_rv , (Array.map ck_attribute_rpc_aux_to_pkcs11 ret.c_getattributevalue_value))
let _ = Callback.register "C_GetAttributeValue" c_GetAttributeValue

let c_SetAttributeValue session_handle object_handle attributes = 
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_setattributevalue (get_rpc_client rpc_client) (session_handle, object_handle, real_attributes) in 
   ret
let _ = Callback.register "C_SetAttributeValue" c_SetAttributeValue

let c_GetObjectSize session_handle object_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_getobjectsize (get_rpc_client rpc_client) (session_handle, object_handle) in 
   (ret.c_getobjectsize_rv , ret.c_getobjectsize_size )
let _ = Callback.register "C_GetObjectSize" c_GetObjectSize

let c_WrapKey session_handle mechanism wrapping_handle wrapped_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_wrapkey (get_rpc_client rpc_client) (session_handle, real_mechanism, wrapping_handle, wrapped_handle) in 
   (ret.c_wrapkey_rv , (Pkcs11.string_to_char_array ret.c_wrapkey_value) )
let _ = Callback.register "C_WrapKey" c_WrapKey

let c_UnwrapKey session_handle mechanism unwrapping_handle wrapped_key attributes = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let real_wrapped_key = (Pkcs11.char_array_to_string wrapped_key) in 
   let ret = Pkcs11_rpc_clnt.P.V.c_unwrapkey (get_rpc_client rpc_client) (session_handle, real_mechanism, unwrapping_handle, real_wrapped_key, real_attributes) in 
   (ret.c_unwrapkey_rv , ret.c_unwrapkey_handle )
let _ = Callback.register "C_UnwrapKey" c_UnwrapKey

let c_DeriveKey session_handle mechanism initial_key attributes = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let real_attributes = (Array.map ck_attribute_pkcs11_to_rpc_aux attributes) in
   let ret = Pkcs11_rpc_clnt.P.V.c_derivekey (get_rpc_client rpc_client) (session_handle, real_mechanism, initial_key, real_attributes) in 
   (ret.c_derivekey_rv , ret.c_derivekey_handle )
let _ = Callback.register "C_DeriveKey" c_DeriveKey

let c_DigestInit session_handle mechanism = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_digestinit (get_rpc_client rpc_client) (session_handle, real_mechanism ) in
   ret
let _ = Callback.register "C_DigestInit" c_DigestInit

let c_Digest session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_digest (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_digest_rv , (Pkcs11.string_to_char_array ret.c_digest_value) )
let _ = Callback.register "C_Digest" c_Digest

let c_DigestUpdate session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_digestupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   ret
let _ = Callback.register "C_DigestUpdate" c_DigestUpdate
   
let c_DigestFinal session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_digestfinal (get_rpc_client rpc_client) (session_handle) in
   (ret.c_digestfinal_rv , (Pkcs11.string_to_char_array ret.c_digestfinal_value) )
let _ = Callback.register "C_DigestFinal" c_DigestFinal

let c_DigestKey session_handle object_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_digestkey (get_rpc_client rpc_client) (session_handle, object_handle ) in
   ret
let _ = Callback.register "C_DigestKey" c_DigestKey

let c_SignInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_signinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_SignInit" c_SignInit

let c_Sign session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_sign (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_sign_rv , (Pkcs11.string_to_char_array ret.c_sign_value) )
let _ = Callback.register "C_Sign" c_Sign

let c_SignUpdate session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_signupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   ret
let _ = Callback.register "C_SignUpdate" c_SignUpdate
   
let c_SignFinal session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_signfinal (get_rpc_client rpc_client) (session_handle) in
   (ret.c_signfinal_rv , (Pkcs11.string_to_char_array ret.c_signfinal_value) )
let _ = Callback.register "C_SignFinal" c_SignFinal


let c_VerifyInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verifyinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_VerifyInit" c_VerifyInit

let c_Verify session_handle data signed_data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let real_signed_data = (Pkcs11.char_array_to_string signed_data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verify (get_rpc_client rpc_client) (session_handle, real_data, real_signed_data) in
   ret
let _ = Callback.register "C_Verify" c_Verify

let c_VerifyUpdate session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verifyupdate (get_rpc_client rpc_client) (session_handle, real_data) in
   ret
let _ = Callback.register "C_VerifyUpdate" c_VerifyUpdate

let c_VerifyFinal session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verifyfinal (get_rpc_client rpc_client) (session_handle, real_data) in
   ret
let _ = Callback.register "C_VerifyFinal" c_VerifyFinal

let c_EncryptInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_encryptinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_EncryptInit" c_EncryptInit

let c_Encrypt session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_encrypt (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_encrypt_rv , (Pkcs11.string_to_char_array ret.c_encrypt_value) )
let _ = Callback.register "C_Encrypt" c_Encrypt

let c_EncryptUpdate session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_encryptupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_encryptupdate_rv , (Pkcs11.string_to_char_array ret.c_encryptupdate_value) )
let _ = Callback.register "C_EncryptUpdate" c_EncryptUpdate

let c_EncryptFinal session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_encryptfinal (get_rpc_client rpc_client) (session_handle) in
   (ret.c_encryptfinal_rv , (Pkcs11.string_to_char_array ret.c_encryptfinal_value) )
let _ = Callback.register "C_EncryptFinal" c_EncryptFinal

let c_DecryptInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_decryptinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_DecryptInit" c_DecryptInit

let c_Decrypt session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_decrypt (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_decrypt_rv , (Pkcs11.string_to_char_array ret.c_decrypt_value) )
let _ = Callback.register "C_Decrypt" c_Decrypt

let c_DecryptUpdate session_handle data = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_decryptupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_decryptupdate_rv , (Pkcs11.string_to_char_array ret.c_decryptupdate_value) )
let _ = Callback.register "C_DecryptUpdate" c_DecryptUpdate

let c_DecryptFinal session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_decryptfinal (get_rpc_client rpc_client) (session_handle) in
   (ret.c_decryptfinal_rv , (Pkcs11.string_to_char_array ret.c_decryptfinal_value) )
let _ = Callback.register "C_DecryptFinal" c_DecryptFinal

let c_SignRecoverInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_signrecoverinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_SignRecoverInit" c_SignRecoverInit

let c_SignRecover session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_signrecover (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_signrecover_rv , (Pkcs11.string_to_char_array ret.c_signrecover_value) )
let _ = Callback.register "C_SignRecover" c_SignRecover

let c_VerifyRecoverInit session_handle mechanism object_handle = 
   let real_mechanism = (ck_mechanism_pkcs11_to_rpc_aux mechanism) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verifyrecoverinit (get_rpc_client rpc_client) (session_handle, real_mechanism, object_handle) in
   ret
let _ = Callback.register "C_VerifyRecoverInit" c_VerifyRecoverInit

let c_VerifyRecover session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_verifyrecover (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_verifyrecover_rv , (Pkcs11.string_to_char_array ret.c_verifyrecover_value) )
let _ = Callback.register "C_VerifyRecover" c_VerifyRecover

let c_DigestEncryptUpdate session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_digestencryptupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_digestencryptupdate_rv , (Pkcs11.string_to_char_array ret.c_digestencryptupdate_value) )
let _ = Callback.register "C_DigestEncryptUpdate" c_DigestEncryptUpdate

let c_DecryptDigestUpdate session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_decryptdigestupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_decryptdigestupdate_rv , (Pkcs11.string_to_char_array ret.c_decryptdigestupdate_value) )
let _ = Callback.register "C_DecryptDigestUpdate" c_DecryptDigestUpdate

let c_SignEncryptUpdate session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_signencryptupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_signencryptupdate_rv , (Pkcs11.string_to_char_array ret.c_signencryptupdate_value) )
let _ = Callback.register "C_SignEncryptUpdate" c_SignEncryptUpdate

let c_DecryptVerifyUpdate session_handle data  = 
   let real_data = (Pkcs11.char_array_to_string data) in
   let ret = Pkcs11_rpc_clnt.P.V.c_decryptverifyupdate (get_rpc_client rpc_client) (session_handle, real_data ) in
   (ret.c_decryptverifyupdate_rv , (Pkcs11.string_to_char_array ret.c_decryptverifyupdate_value) )
let _ = Callback.register "C_DecryptVerifyUpdate" c_DecryptVerifyUpdate

let c_GetOperationState session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_getoperationstate (get_rpc_client rpc_client) (session_handle) in
   (ret.c_getoperationstate_rv , (Pkcs11.string_to_char_array ret.c_getoperationstate_value) )
let _ = Callback.register "C_GetOperationState" c_GetOperationState


let c_SetOperationState session_handle state encryption_handle authentication_handle = 
   let real_state = (Pkcs11.char_array_to_string state) in
   let ret = Pkcs11_rpc_clnt.P.V.c_setoperationstate (get_rpc_client rpc_client) (session_handle, real_state, encryption_handle, authentication_handle) in
   ret
let _ = Callback.register "C_SetOperationState" c_SetOperationState

let c_GetFunctionStatus session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_getfunctionstatus (get_rpc_client rpc_client) (session_handle) in
   ret
let _ = Callback.register "C_GetFunctionStatus" c_GetFunctionStatus

let c_CancelFunction session_handle = 
   let ret = Pkcs11_rpc_clnt.P.V.c_cancelfunction (get_rpc_client rpc_client) (session_handle) in
   ret
let _ = Callback.register "C_CancelFunction" c_CancelFunction


