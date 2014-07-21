(************************* CeCILL-B HEADER ************************************
    Copyright ANSSI (2014)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr] and Marion
    DAUBIGNARD [marion.daubignard@ssi.gouv.fr]

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

    The current source code is part of the tests 6] source tree.

    Project: PKCS#11 Filtering Proxy
    File:    src/tests/ocaml/generic_scenario.ml

************************** CeCILL-B HEADER ***********************************)
open Printf
open P11_common
open P11_for_generic
open Sys
(* the file P11_for_generic contains all the code
of the functions parsing test scenarios.
These are extensively commented and the ABOUT_TEST_SCENARIOS 
file provides a more global overview of what can be tested and how.*)

let _ = 
   
  if Array.length argv !=2 then
    failwith "usage : ./gen_scenario <name_of_the_test_scenario>
              e.g. if your test scenario is encoded in the file get_sensitive_key.ml
              ./gen_scenario get_sensitive_key";
  let my_scenario= Array.get argv 1 in
  let scenario_test = match my_scenario with 
    | t when t="get_sensitive_key" -> Get_sensitive_key.this_scenario; 
    | t when t="sensitive_is_sticky" -> Sensitive_is_sticky.this_scenario;
    | t when t="extractable_is_sticky" -> Extractable_is_sticky.this_scenario;
    | t when t="encrypt_and_unwrap" -> Encrypt_and_unwrap.this_scenario;
    | t when t="double_unwrap" -> Double_unwrap.this_scenario;  
    | t when t="wrap_and_decrypt_1" -> Wrap_and_decrypt_1.this_scenario;  
    | t when t="wrap_and_decrypt_2" -> Wrap_and_decrypt_2.this_scenario; 
    | t when t="wrap_and_decrypt_3" -> Wrap_and_decrypt_3.this_scenario; 
    | t when t="wrap_and_decrypt_4" -> Wrap_and_decrypt_4.this_scenario; 
    | t when t="create_object_1" -> Create_object_1.this_scenario; 
    | t when t="create_object_2" ->  Create_object_2.this_scenario;
    | t when t="misc_scenario" -> Misc_scenario.this_scenario;  
    | _ -> failwith "It seems that this test scenario is not implemented yet!!!!!"
  in
  
  let _ = init_module in
  let conf_user_pin = fetch_pin in
    (* Initialize module *)
  let ret_value = Pkcs11.mL_CK_C_Initialize () in
  let _ = check_ret ret_value C_InitializeError false in
  printf "C_Initialize ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  
    (* Fetch slot count by passing 0n (present) 0n (count) *)
  let (ret_value, slot_list_, count) = Pkcs11.mL_CK_C_GetSlotList 0n 0n in
  let _ = check_ret ret_value C_GetSlotListError false in
  printf "C_GetSlotList ret: %s, Count = %s, slot_list =" (Nativeint.to_string ret_value) (Nativeint.to_string count);
  
  Pkcs11.print_int_array slot_list_;
  
    (* Fetch slot list by passing 0n count *)
  let (ret_value, slot_list_, count) = Pkcs11.mL_CK_C_GetSlotList 0n count in
  let _ = check_ret ret_value C_GetSlotListError false in
  printf "C_GetSlotList ret: %s, Count = %s, slot_list =" (Nativeint.to_string ret_value) (Nativeint.to_string count);
  Pkcs11.print_int_array slot_list_;
  
  Array.iter print_slots slot_list_;
  
    (* hardcoded take first available slot *)
  let slot_id = slot_list_.(0) in
  
    (* GetMechList and find list of mechanisms we want to test*)
  let mechanism_array_ = get_mechanism_list_for_slot slot_id in
  let mechanism_list_  = Array.to_list mechanism_array_ in
  let mechanisms = Array.map Pkcs11.match_cKM_value mechanism_array_ in
  Pkcs11.print_string_array mechanisms;
  
    (* Try and find a symmetric mechanism available on the device*)
  let symm_mechs_available = intersect symmetric_mechs_tested mechanism_list_ in  
  let symm_keygen_to_test = List.map sym_mech_to_sym_keygen symm_mechs_available in
  
  
  let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
  let _ = check_ret ret_value C_OpenSessionError false in
  printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  let user_pin = Pkcs11.string_to_char_array conf_user_pin in
  let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
  let _ = check_ret ret_value C_LoginError false in
  printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  
  if (symm_keygen_to_test=[]) then 
    failwith "No symmetric mechanism is available !\n";
  
  let mech_tested = sym_keygen_to_sym_mech (List.hd symm_keygen_to_test) in
  printf "Let's generate a SECRET key that should not be revealed\n";	
  
  let the_attr_template = [| attr_extractable ; attr_decrypt ; attr_token ; attr_encrypt ; attr_sensitive |] in
  let key_list= keygen_trial session [("sensitive_key",the_attr_template)] symm_keygen_to_test in
  
  if (key_list=[]) then 
    failwith "I couldn't generate a key to leak!\n";
  
  let (_,key_to_leak,_)  = List.hd key_list in
  
  let template_w = [| attr_wrap |] in
  let template_wf = [| attr_wrapf |] in
  let template_d = [| attr_decrypt |] in
  let template_wd = [| attr_wrap ; attr_decrypt |] in
  let template_wfd = [| attr_wrapf ; attr_decrypt |] in
  let template_token_w = [| attr_wrap; attr_token |] in
  let template_token_d = [| attr_decrypt; attr_token |] in
  let template_token_ue = [| attr_encrypt ; attr_unwrap |] in 
  
  
  
  let _= scenario_parser scenario_test mech_tested session key_to_leak
  in
  
  
  
    (* Logout and finalize *)
  let ret_value = Pkcs11.mL_CK_C_Logout session in
  printf "C_Logout ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  let _ = check_ret ret_value C_LogoutError false in
  let ret_value = Pkcs11.mL_CK_C_CloseSession session in
  let _ = check_ret ret_value C_CloseSessionError false in
  printf "C_CloseSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  
  let ret_value = Pkcs11.mL_CK_C_CloseAllSessions slot_id in
  let _ = check_ret ret_value C_CloseAllSessionsError false in
  printf "C_CloseAllSessions ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  let ret_value = Pkcs11.mL_CK_C_Finalize () in
  let _ = check_ret ret_value C_FinalizeError false in
  printf "C_Finalize ret: %s\n" (Pkcs11.match_cKR_value ret_value)
    
