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

    The current source code is part of the tests 6] source tree.

    Project: PKCS#11 Filtering Proxy
    File:    src/tests/ocaml/p11_for_generic.ml

************************** MIT License HEADER ***********************************)
open Printf
open P11_common

let symmetric_mechs_tested = [Pkcs11.cKM_DES3_CBC; Pkcs11.cKM_AES_CBC ; Pkcs11.cKM_DES_CBC]


let sym_mech_to_sym_keygen mech_type =
  match mech_type with
  | m when m=Pkcs11.cKM_AES_CBC -> Pkcs11.cKM_AES_KEY_GEN
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.cKM_DES_KEY_GEN
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.cKM_DES3_KEY_GEN
  | _ -> failwith "sym_mech_to_sym_keygen : does not belong to symm_mechs_tested !"

let sym_keygen_to_sym_mech mech_type =
  match mech_type with
  |  m when m=Pkcs11.cKM_AES_KEY_GEN ->  Pkcs11.cKM_AES_CBC
  |  m when m=Pkcs11.cKM_DES_KEY_GEN ->  Pkcs11.cKM_DES_CBC
  |  m when m=Pkcs11.cKM_DES3_KEY_GEN ->  Pkcs11.cKM_DES3_CBC
  | _ -> failwith "sym_keygen_to_sym_mech : does not belong to symm_mechs_tested !"    


let mech_type_to_key_type mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC -> Pkcs11.cKK_AES
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.cKK_DES
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.cKK_DES3
  | _ ->  failwith "mech_type_to_key_type : unknown mechanism" 
  

let mech_type_to_mech mech_type = 
  {Pkcs11.mechanism = mech_type ; Pkcs11.parameter = [||]}

let mech_to_mech_type mech = 
  mech.Pkcs11.mechanism

let null_param mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000")
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000")
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000")
  (* | m when m=Pkcs11.cKM_AES_KEY_GEN -> Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000") *)
  (* | m when m=Pkcs11.cKM_DES_KEY_GEN ->  Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000") *)
  (* | m when m=Pkcs11.cKM_DES3_KEY_GEN -> Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000") *)
  | _ ->  failwith "null_param error : unknown mechanism"

let null_vector mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000")
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000")
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.string_to_char_array (Pkcs11.pack  "000000000000000000000000000000000000000000000000")
  (*| m when m=Pkcs11.cKM_AES_KEY_GEN -> Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000")
  | m when m=Pkcs11.cKM_DES_KEY_GEN ->  Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000")
  | m when m=Pkcs11.cKM_DES3_KEY_GEN -> Pkcs11.string_to_char_array (Pkcs11.pack "00000000000000000000000000000000")*)
  (*| m when m=Pkcs11.cKM_RSA_PKCS -> Pkcs11.string_to_char_array  (Pkcs11.pack 
"457c13303730d4aec2c876e83a51905891da44f7cf100fe9b9922fb9f2b91628abb44b8277b42e0a0e557cbf3332a3f4a3c86911aab2e1f7ce182d2bf1aeaf8ed622fb1816241544a08a99d872507a482b26a7e14477360a5800a4df9a6450113392c67450441943292b978fa830ed82cad4fdc65d939665fa7acd963c874e3a")*)
  | _ ->  failwith "null_vector error : unknown mechanism"

let null_string mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC -> Pkcs11.pack "00000000000000000000000000000000"
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.pack "0000000000000000"
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.pack  "000000000000000000000000000000000000000000000000"
  | _ -> failwith "null_string : not needed yet"


let mech_type_to_mech_and_iv mech_type = 
  { Pkcs11.mechanism = mech_type ;  Pkcs11.parameter = null_param mech_type } 

let mech_type_to_key_length mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC ->  Pkcs11.int_to_ulong_char_array 16n 
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_AES_KEY_GEN -> Pkcs11.int_to_ulong_char_array 16n
  | m when m=Pkcs11.cKM_DES_KEY_GEN ->  Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_DES3_KEY_GEN -> Pkcs11.int_to_ulong_char_array 8n 
  | _ ->  failwith "mech_type_to_key_length : unknown mechanism"

 (*  keygen_trial and asym_keygen_trial functions : uses an auxiliary function that 
     goes through an attribute template list and mechanism_type list,
     trying for each bad template and each mechanism to generate a key. In case of success,
     the label and handle to the resulting key are stored in the accu list, which is
     returned by the function. *)
let keygen_trial session template_list mech_list =
  let rec aux_keygen_trial temp_l mech_ll accu =
    match (temp_l, mech_ll) with
    | (_,[]) -> accu 
    | ([], h::t ) -> aux_keygen_trial template_list t accu  (* treat the next mechanism once the attribute
							     template list is emptied *)
    | ((temp_name, attr_template)::t , mech :: tt ) ->
      let key_label = Printf.sprintf "mytest_keygen_sym_%s_%s" temp_name (Pkcs11.match_cKM_value mech) in
      let key_length = mech_type_to_key_length mech in 
      let complete_template = templ_append attr_template Pkcs11.cKA_LABEL (Pkcs11.string_to_char_array key_label) in
      let complete_template = templ_append complete_template Pkcs11.cKA_VALUE_LEN key_length in
      let (ret_value, key_hdl) = Pkcs11.mL_CK_C_GenerateKey session (mech_type_to_mech mech) complete_template in
      let _= printf "For template %s and mechanism %s, C_GenerateKey ret: %s\n" temp_name (Pkcs11.match_cKM_value mech) (Pkcs11.match_cKR_value ret_value) in
      (* in any case, we go on with the attribute template list*)
      (* in case the keygen worked we keep the handle to use the key for a test scenario below *)
      if (check_ret_ok ret_value) then
	aux_keygen_trial t mech_ll ((mech,key_hdl, attr_template)::accu)
      else
	aux_keygen_trial t mech_ll accu
  in
  aux_keygen_trial template_list mech_list []

let asym_keygen_trial session template_list=
  let rec aux_asym_keygen_trial temp_l accu =
    match temp_l with
    | [] -> accu 
    | (temp_name, attr_template)::t  ->    
      let key_label = Some (Printf.sprintf "mytest_keygen_asym_%s" temp_name) in      
      let (pub_template,priv_template) = generate_generic_rsa_template 1024n key_label None in
      let (pub_template, priv_template) = update_generic_rsa_template attr_template (pub_template,priv_template) in
      let (ret_value, pubkey_, privkey_) = Pkcs11.mL_CK_C_GenerateKeyPair session (mech_type_to_mech Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN) pub_template priv_template in
      let _= printf "For template %s and mechanism RSA_PKCS_KEYGEN, C_GenerateKey ret: %s\n" temp_name (Pkcs11.match_cKR_value ret_value) in
      (* in any case, we go on with the attribute template list*)
      (* in case the keygen worked we keep the handle to use the key for a test scenario below *)
      if (check_ret_ok ret_value) then
	aux_asym_keygen_trial t ((pubkey_, privkey_,attr_template)::accu)
      else
	aux_asym_keygen_trial t accu
  in
  aux_asym_keygen_trial template_list []



type opcode =  W | D | G |  E | GKTL | U of (Pkcs11.ck_attribute array) | C of (Pkcs11.ck_attribute array) | DoubleU of (Pkcs11.ck_attribute array * Pkcs11.ck_attribute array) | S | F | WW

type previous_result_needed = Empty | Hdl of Pkcs11.ck_object_handle_t | Bitstring of char array 

 
type scenario_state = previous_result_needed * Pkcs11.ck_object_handle_t * (Pkcs11.ck_attribute list)
(* ck_object_handle containts the key generated at the beginning of the scenario
to perform crypto afterwards *)



(* this function is meant to create and initialize a scenario state to use in the
test scenario. Indeed, it aims at creating a handle to a key with 
the attributes set to values as specified by attr_templates. 
In other words, the first named template in a scenario will result in the creation
of a key conforming to this template, and a handle to this key is stored in
the 'middle' component of the output scenario state. 
The key is meant for the mechanism 'mech' (globally used as a parameter of the scenario_parser
function).
To perform the key generation, two strategies are tried : generating the key 
with the right attributes in one step, or setting them progressively.
*)  
let init_action (temp_name, attr_template) mech session = 
  (* first thing to try : direct generation with the attribute list = symmetric case for now*)
  let key_label = Printf.sprintf "mytest_keygen_sym_%s_%s" temp_name (Pkcs11.match_cKM_value mech) in
  let key_length = mech_type_to_key_length mech in 
  let complete_template = templ_append attr_template Pkcs11.cKA_LABEL (Pkcs11.string_to_char_array key_label) in
  let complete_template = templ_append complete_template Pkcs11.cKA_VALUE_LEN key_length in
  let (ret_value, key_hdl) = Pkcs11.mL_CK_C_GenerateKey session (mech_type_to_mech mech) complete_template in
  let _= printf "For template %s and mechanism %s, C_GenerateKey ret: %s\n" temp_name (Pkcs11.match_cKM_value mech) (Pkcs11.match_cKR_value ret_value) in 
  if check_ret_ok ret_value then
    Some(Empty, key_hdl, [])
  else   
    begin
      (* we try generating a "raw" key and set attributes to the desired values one by one*)
      (* this is "raw" key generation*)
      let key_label = Printf.sprintf "mytest_keygen_sym_%s_%s" temp_name (Pkcs11.match_cKM_value mech) in
      let key_length = mech_type_to_key_length mech in 
      let complete_template = templ_append [||] Pkcs11.cKA_LABEL (Pkcs11.string_to_char_array key_label) in
      let complete_template = templ_append complete_template Pkcs11.cKA_VALUE_LEN key_length in
      let (ret_value, key_hdl) = Pkcs11.mL_CK_C_GenerateKey session (mech_type_to_mech mech) complete_template in 
      let _= printf "For template %s and mechanism %s \'raw\' key generation, C_GenerateKey ret: %s\n" temp_name (Pkcs11.match_cKM_value mech) (Pkcs11.match_cKR_value ret_value) in 
      if  not(check_ret_ok ret_value) then
	failwith "Could not generate the key.\n"
      else      
	let attr_template_length= Array.length attr_template in
	let rec aux_init_action attr_template_index = 
	  if (attr_template_index<attr_template_length) then 
	    begin
	      let target_template = [|Array.get attr_template attr_template_index|] in
	      let ret_value = Pkcs11.mL_CK_C_SetAttributeValue session key_hdl target_template in
    	      let _=printf "C_SetAttributeValue ret : %s\n" (Pkcs11.match_cKR_value ret_value) in
	      if  not(check_ret_ok ret_value) then
		begin
		  printf "init_action failed there, trying to set %s\n" (Pkcs11.match_cKA_value ((Array.get target_template 0).Pkcs11.type_));
		  failwith "Setting attributes progressively stopped there."
		end
	      else aux_init_action (attr_template_index+1)
	    end	    
	  else 
	    begin
	      printf "For template %s and mechanism %s, setting attributes progressively worked.\n" temp_name (Pkcs11.match_cKM_value mech);
	      Some(Empty, key_hdl, [])
	    end
	in
	aux_init_action 0;
    end

(* the set_template function tries to set one by one the attributes in attr_template on the key refered by the hdl
obj_hdl *)
let set_the_template attr_template obj_hdl session = 
  let attr_template_length= Array.length attr_template in
  if attr_template_length=0 then 
    printf "set_the_template : nothing to be set\n"
  else     
    let rec aux_init_action attr_template_index = 
      if (attr_template_index<attr_template_length) then 
	begin
	  let target_template = [|Array.get attr_template attr_template_index|] in
	  let ret_value = Pkcs11.mL_CK_C_SetAttributeValue session obj_hdl target_template in
    	  let _=printf "C_SetAttributeValue ret : %s\n" (Pkcs11.match_cKR_value ret_value) in
	  if  not(check_ret_ok ret_value) then
	    begin
	      printf "set_the_template failed there, trying to set %s\n" (Pkcs11.match_cKA_value ((Array.get target_template 0).Pkcs11.type_));
	      failwith "Setting attributes progressively failed"
	    end
	  else aux_init_action (attr_template_index+1)
	end	    
      else 
	printf "Setting attributes progressively worked.\n"; 
    in
    aux_init_action 0
      

(************* functions implementing opcode operations *************)
(* this function wraps key_to_leak with with the key obj_hdl using tested_mech *)
let apply_wrap obj_hdl tested_mech session key_to_leak = 
  let (ret_value, wrapped_key_) = Pkcs11.mL_CK_C_WrapKey session tested_mech obj_hdl key_to_leak in
  let _ = check_ret ret_value C_WrapKeyError true in
  printf "C_WrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  printf "Wrapped SECRET key:\n";
  Pkcs11.print_hex_array wrapped_key_;
  printf "key_to_leak is %nd and obj_hdl is %nd \n" key_to_leak obj_hdl;
  Some(Bitstring(wrapped_key_), obj_hdl, [])

(* decrypts my_res using obj_hdl and tested_mech and prints it out*)
let apply_decrypt my_res obj_hdl tested_mech session = 
  printf "decrypting with key %nd\n" obj_hdl;
  let dec_data = decrypt_some_data session tested_mech obj_hdl my_res in
  printf "Attack DONE SENSITIVE key value:\n";
  Pkcs11.print_hex_array dec_data; 
  None

(* prints out the value of key_hdl; leaves myscenariostate unchanged *)  
let apply_getattributevalue key_hdl session myscenariostate = 
  printf "We get the value of %nd\n" key_hdl ; 
  let value_template =  [| { Pkcs11.type_ =Pkcs11.cKA_VALUE; Pkcs11.value = [||] }|] in
  let (ret_value,temp_res) = Pkcs11.mL_CK_C_GetAttributeValue session key_hdl value_template in
  if (check_ret_ok ret_value) then   
    let (ret_value,temp_res) = Pkcs11.mL_CK_C_GetAttributeValue session key_hdl temp_res in
    if (check_ret_ok ret_value) then
      begin
	let key_value_attr = Array.get temp_res 0 in
	printf "This is embarrassing, I recovered a sensitive key value, which is :\n";
	Pkcs11.print_hex_array key_value_attr.Pkcs11.value;
      end
    else
      printf "C_GetAttributeValue failed with %s\n" (Pkcs11.match_cKR_value ret_value) ;
  else
    printf "C_GetAttributeValue failed with %s\n" (Pkcs11.match_cKR_value ret_value) ;
  myscenariostate

(* encrypts a string of zeroes of the appropriate length with the key refered to by obj_hdl
using the mechanism mech and a null parameter. 
Stores the resulting bitstring in the "previous result" filed of the state, 
and sets the second component of the state to obj_hdl. *)
let apply_encrypt session mech obj_hdl = 
  printf "encrypting zeroes with key %nd\n" obj_hdl;
  let encrypt_mech = mech_type_to_mech_and_iv mech in
  let zeroes = null_string mech in
  let ciphertext= encrypt_some_data session encrypt_mech obj_hdl zeroes in
  printf "Encryption done\n" ;
  printf "Encrypted zeroes:\n";
  Pkcs11.print_hex_array ciphertext;
  Some(Bitstring(ciphertext), obj_hdl, [])


(* unwraps ciphertext with obj_hdl and attributes attr_template.
In case of success, the resulting handle is stored in the first component of the scenario state,
second component is the obj_hdl used to unwrap.*)       
let apply_unwrap  obj_hdl session mech ciphertext attr_template = 
  printf "unwrapping with key %nd\n" obj_hdl;
  let unwrap_mech = mech_type_to_mech_and_iv mech in
  let key_length = mech_type_to_key_length mech in 
  let key_type =  mech_type_to_key_type mech in
  let complete_template = templ_append attr_template Pkcs11.cKA_VALUE_LEN key_length in
  let complete_template = templ_append complete_template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY) in
  let complete_template = templ_append complete_template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array key_type) in
  let (ret_value, unwrapped_key_hdl)=Pkcs11.mL_CK_C_UnwrapKey session unwrap_mech obj_hdl ciphertext complete_template in
  printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  if (check_ret_ok ret_value) then   
    begin
      printf "unwrapping created key %nd\n" unwrapped_key_hdl;
      Some(Hdl(unwrapped_key_hdl), obj_hdl, [])
    end
  else 
    None 

(* unwraps *twice* ciphertext with obj_hdl, firstly with attributes in attr_template, 
secondly with attributes in attr_template2.
In case of success, the handle resulting from the first (resp.second) unwrap is stored in the first (resp. second) 
component of the resulting scenario state. *)     
let apply_double_unwrap obj_hdl session mech ciphertext attr_template attr_template2 = 
  printf "First unwrapping with key %nd\n" obj_hdl;
  let unwrap_mech = mech_type_to_mech_and_iv mech in
  let key_length = mech_type_to_key_length mech in 
  let key_type =  mech_type_to_key_type mech in
  let complete_template = templ_append attr_template Pkcs11.cKA_VALUE_LEN key_length in
  let complete_template = templ_append complete_template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY) in
  let complete_template = templ_append complete_template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array key_type) in
  let (ret_value, key_hdl1)=Pkcs11.mL_CK_C_UnwrapKey session unwrap_mech obj_hdl ciphertext complete_template in
  printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);  
  if (check_ret_ok ret_value) then 
    begin
      printf "Unwrapping created key %nd\n" key_hdl1;
      let complete_template = templ_append attr_template2 Pkcs11.cKA_VALUE_LEN key_length in
      let complete_template = templ_append complete_template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY) in
      let complete_template = templ_append complete_template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array key_type) in
      let (ret_value, key_hdl2)=Pkcs11.mL_CK_C_UnwrapKey session unwrap_mech obj_hdl ciphertext complete_template in
      printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
      if (check_ret_ok ret_value) then 
	begin
	  printf "Unwrapping created key %nd\n" key_hdl2;
	  Some(Hdl(key_hdl1), key_hdl2, [])
	end
      else
	None
    end
  else
    None

(* Creates a secret key worth (an adequate number of) zeroes, corresponding 
to the mechanism 'mech'. In case of success, the resulting handle is 
is stored in the first component of the scenario state output. Rest
of the state remains unchanged.  
*)
let apply_create session mech attr_template my_scenario_state =
  printf "Creating object\n";
  let key_length = mech_type_to_key_length mech in 
  let key_type =  mech_type_to_key_type mech in
  let zeroes = null_vector mech in
  let complete_template = templ_append attr_template Pkcs11.cKA_VALUE_LEN key_length in
  let complete_template = templ_append complete_template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY) in
  let complete_template = templ_append complete_template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array key_type) in
  let complete_template = templ_append complete_template Pkcs11.cKA_VALUE zeroes in
  let (ret_value, key_hdl) = Pkcs11.mL_CK_C_CreateObject session complete_template in
  printf "C_CreateObject ret: %s\n" (Pkcs11.match_cKR_value ret_value);
  if (check_ret_ok ret_value) then 
    begin
      printf "Createobject created key %nd\n" key_hdl;
      match my_scenario_state with 
      | None -> Some(Hdl(key_hdl),0n,[]) (* the state is 'initialized' if it was 'empty'.*)
      | Some(prev_res,obj_hdl,attr_list) -> Some(Hdl(key_hdl),obj_hdl,attr_list)
    end
  else
    None


(* global parameters : session handle session + secret sensitive key hdl key_to_leak
   input = tested_mechanism tested_mech -> (not a keygen)
   generated outside*)

(* example of valid scenario [(("token_wd", template_token_wd), "W"), (("empty", [||]), "D") ]
*)

let scenario_parser scenario mech session key_to_leak=
  (* this function unfolds the scenario progressively. It starts by initializing
     a new scenario state using init_action, and then proceeds to apply the
     rest of the scenario.
     To do so, it uses to auxiliary functions :
     - action_ttt is an auxiliairy function that applies the appropriate action
     corresponding to the opcode to a scenario state my_scenatio_state. 
     - continue *)

  let action_ttt my_opcode my_scenario_state = 
    (*let (prev_res, obj_hdl, ck_attr_list) = my_scenario_state in*)
    match (my_opcode,my_scenario_state) with 
    | (W,Some(prev_res, obj_hdl, ck_attr_list)) -> 
      let wrap_mech = mech_type_to_mech_and_iv mech in
      begin
	match prev_res with 
	| Hdl(other_hdl) ->  apply_wrap other_hdl wrap_mech session key_to_leak
	| _ -> apply_wrap obj_hdl wrap_mech session key_to_leak						       
      end
    | (WW, Some(prev_res, obj_hdl, ck_attr_list)) ->  
      let wrap_mech = mech_type_to_mech_and_iv mech in
      begin
	match prev_res with 
	| Hdl(other_hdl) ->  apply_wrap obj_hdl wrap_mech session other_hdl
	| _ -> 	failwith "scenario problem : tried to wrap but no wrapping key"      			       
      end
    | (D,Some(prev_res, obj_hdl, ck_attr_list)) -> 
      begin
	match prev_res with 
	| Bitstring(bs) -> let decrypt_mech = mech_type_to_mech_and_iv mech in
			   apply_decrypt bs obj_hdl decrypt_mech session 
	| _ -> failwith "scenario problem : tried to decrypt but no ciphertext"      
      end
    | (GKTL,my_scenario_state) -> apply_getattributevalue key_to_leak session my_scenario_state
    | (G,Some(Hdl(other_hdl),obj_hdl,ck_attr_list)) -> apply_getattributevalue other_hdl session (Some(Hdl(other_hdl),obj_hdl,ck_attr_list))
    | (E,Some(prev_res, obj_hdl, ck_attr_list)) ->
       begin
	match prev_res with 
	| Hdl(other_hdl) -> apply_encrypt session mech other_hdl 
	| _ -> apply_encrypt session mech obj_hdl 						       
      end
    | (U(attr_template), Some(prev_res, obj_hdl, ck_attr_list)) ->
      begin
	match prev_res with 
	| Bitstring(bs) -> apply_unwrap obj_hdl session mech bs attr_template
	| _ -> failwith "scenario problem: tried to unwrap but no ciphertext"      
      end
    | (C(attr_template),my_scenario_state) -> apply_create session mech attr_template my_scenario_state
    | (DoubleU(attr_template, attr_template2),  Some(prev_res, obj_hdl, ck_attr_list)) ->
      begin
	match prev_res with 
	| Bitstring(bs) -> apply_double_unwrap obj_hdl session mech bs attr_template attr_template2
	| _ -> failwith "scenario problem: tried to unwrap but no ciphertext"      
      end  
    | (S,my_scenario_state) -> my_scenario_state   
    | (F,Some(Hdl(hdl), obj_hdl, ck_attr_list)) -> Some(Empty, hdl, ck_attr_list)   
    | _ -> failwith "Not implemented yet"      
      
    in
    
  (* continue recusrsively applies the first 'action' of the scenario scnr to my_scenario_state, 
  using action_ttt to obtain a new scenario_state resulting from the opcode and my_scenario_state *)
  let rec continue scnr my_scenario_state= 
    match (scnr, my_scenario_state) with 
    | ([],_) -> printf "Done here\n"
    | ((_,GKTL)::t,_)->  let my_sc_st = action_ttt GKTL my_scenario_state in continue t my_sc_st 
    (* this is to be able to get the key_to_leak at whatever moment suits us (for verification purposes)
       in a scenario; without impacting anything in the scenario. 
    *)
    | ((h1, h2) :: t, Some(prev_res, obj_hdl, ck_attr_list))-> 
      (* in any other case, we try to set the attributes listed in the named template 
      on the key refered to by the handle currently stored in the scenario state (middle component)
      before carrying out the action encoded by the opcode. *)
      let (_,my_attr_temp) = h1 in
      (* the set_template function tries to set one by one 
	 the attributes in attr_template on the key refered by the hdl
	 obj_hdl *)
      let _= set_the_template my_attr_temp obj_hdl session in
      let my_sc_st = action_ttt h2 my_scenario_state in
      continue t my_sc_st	
    | _ -> failwith "Abrupt end of scenario processing : either the scenario is badly encoded, or the test failed !"
  in
  
  match scenario with 
  | [] -> printf "This is an empty scenario you gave me !\n";
  | (the_named_template, the_opcode) :: t -> 
      (* To initialize the state, either there is a non-empty template to be used to
	 create a key and we apply the init_action function before carrying on, 
	 or we directly proceed to the opcode.*)
      let (_,attr_temp) = the_named_template in
      if Array.length attr_temp = 0 then 	
	continue t (action_ttt the_opcode None) 
      else
	continue t (action_ttt the_opcode (init_action the_named_template (sym_mech_to_sym_keygen mech) session))
 
      
