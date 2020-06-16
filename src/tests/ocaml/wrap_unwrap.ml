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

    The current source code is part of the tests 6] source tree.

    Project: PKCS#11 Filtering Proxy
    File:    src/tests/ocaml/wrap_unwrap.ml

************************** MIT License HEADER ***********************************)
open Printf
open P11_common

let encrypt_decrypt_some_data_with_mech_type session pubkey_ privkey_ data mech_type = 
    let enc_mech = { Pkcs11.mechanism = mech_type ; Pkcs11.parameter = [| |] } in
    printf "--------------\n";
    printf "%s encrypt/decrypt\n" (Pkcs11.match_cKM_value mech_type);
    let enc_data_ = encrypt_some_data session enc_mech pubkey_ data in
    printf "\tthrough Encrypt single call is:\n";
    Pkcs11.print_hex_array enc_data_;
    let dec_data_ = decrypt_some_data session enc_mech privkey_ enc_data_ in
    printf "\tthrough Decrypt single call is:\n";
    Printf.printf "'%s'\n" (Pkcs11.char_array_to_string dec_data_)

let _ = 
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

    (* GetMechList *)
    let mechanism_list_ = get_mechanism_list_for_slot slot_id in

    let mechanisms = Array.map Pkcs11.match_cKM_value mechanism_list_ in
    Pkcs11.print_string_array mechanisms;

    (* OpenSession and Login *)
    let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let _ = check_ret ret_value C_OpenSessionError false in
    printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let user_pin = Pkcs11.string_to_char_array conf_user_pin in
    let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
    let _ = check_ret ret_value C_LoginError false in
    printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    (* Generate a token rsa key pair *)
    let (pub_template_, priv_template_) = generate_rsa_template 1024n (Some "mytest") (Some "1234") in
    let (pubkey_, privkey_) = generate_rsa_key_pair session 1024n pub_template_ priv_template_ in

    (* Let's create a symetric DES3 key that will wrap our RSA private key *)
    let symetric_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES3_KEY_GEN ; Pkcs11.parameter = [| |] } in
    let symetric_template = [||] in

    let symetric_template = templ_append symetric_template Pkcs11.cKA_WRAP Pkcs11.true_ in
    let symetric_template = templ_append symetric_template Pkcs11.cKA_UNWRAP Pkcs11.true_ in
    let symetric_template = templ_append symetric_template Pkcs11.cKA_TOKEN Pkcs11.true_ in

    let keygen_to_test = ["cKM_DES3_KEY_GEN" ] in

    let keygen_to_test = List.map Pkcs11.string_to_cKM_value keygen_to_test in
    let mech_intersect = intersect keygen_to_test (Array.to_list mechanism_list_) in

    let (ret_value, symkey_) = Pkcs11.mL_CK_C_GenerateKey session symetric_mech symetric_template in
    let _ = check_ret ret_value C_GenerateKeyError false in
    printf "C_GenerateKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    while true do

    begin

        (* Now let's wrap the RSA privkey with the 3DES key *)
        let iv = Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000") in
        let wrapping_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES3_CBC_PAD ; Pkcs11.parameter = iv } in
        let (ret_value, wrapped_key_) = Pkcs11.mL_CK_C_WrapKey session wrapping_mech symkey_ privkey_ in
        let _ = check_ret ret_value C_WrapKeyError true in
        printf "C_WrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "--------------\n";
        printf "Wrapped RSA private key with DES3_CBC_PAD:\n";
        Pkcs11.print_hex_array wrapped_key_;

        (* Now we try to Unwrap the key *)
        let label = Pkcs11.string_to_char_array "unwrapped_rsa_pkey" in
        let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
        let priv_template = [||] in
        let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in
        let priv_template = templ_append priv_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_LABEL label in
        let priv_template = templ_append priv_template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_SIGN Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_UNWRAP Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in

        let (ret_value, unwrapped_key_handle_) = Pkcs11.mL_CK_C_UnwrapKey session wrapping_mech symkey_ wrapped_key_ priv_template in
        let _ = check_ret ret_value C_UnwrapKeyError true in
        printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);

        (* Destroy objects *)
        let _ = List.map (destroy_some_object session) [unwrapped_key_handle_] in

        flush stdout;
        Gc.full_major()
    end
    done;

    (* Logout and finalize *)
    let ret_value = Pkcs11.mL_CK_C_Logout session in
    printf "C_Logout ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let _ = check_ret ret_value C_LogoutError false in
    let ret_value = Pkcs11.mL_CK_C_CloseSession session in
    let _ = check_ret ret_value C_CloseSessionError false in
    printf "C_CloseSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let ret_value = Pkcs11.mL_CK_C_Finalize () in
    let _ = check_ret ret_value C_FinalizeError false in
    printf "C_Finalize ret: %s\n" (Pkcs11.match_cKR_value ret_value)

