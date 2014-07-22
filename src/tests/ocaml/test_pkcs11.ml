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
    File:    src/tests/ocaml/test_pkcs11.ml

************************** CeCILL-B HEADER ***********************************)
open Printf
open P11_common

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

    (* GenerateKeyPair *)
    let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let _ = check_ret ret_value C_OpenSessionError false in
    printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let user_pin = Pkcs11.string_to_char_array conf_user_pin in
    let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
    let _ = check_ret ret_value C_LoginError false in
    printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    (* Use higher level function to generate RSA template and create keypair *)
    let (pub_template_, priv_template_) = generate_rsa_template 1024n (Some "mytest") (Some "1234") in
    let (pubkey_, privkey_) = generate_rsa_key_pair session 1024n pub_template_ priv_template_ in

    (* Template utils *)
    (* Sign *)
    let sign_mech = { Pkcs11.mechanism = Pkcs11.cKM_RSA_PKCS ; Pkcs11.parameter = [| |] } in
    let signed_data_ = sign_some_data session sign_mech privkey_ "mysecretdata" in

    printf "--------------\n";
    printf "SIGNED DATA\n";
    Pkcs11.print_hex_array signed_data_;
    printf "--------------\n";

    let ret_value = verify_some_data session sign_mech pubkey_ "mysecretdata" signed_data_ in
    printf "C_Verify should be OK ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let _ = try verify_some_data session sign_mech pubkey_ "mysecretdata2" signed_data_ with
        C_VerifyError -> printf "C_Verify failed as expected\n"; Pkcs11.cKR_OK
        | _ -> raise (Failure "C_Verify call did not fail as expected") in

    (* Encrypt *)
    (* RSA_PKCS Encrypt *)
    let crypt_mech = sign_mech in
    let crypted_data_ = encrypt_some_data session crypt_mech pubkey_ "mysecretdata" in

    printf "--------------\n"; 
    printf "ENCRYPTED DATA\n"; 
    Pkcs11.print_hex_array crypted_data_;
    printf "--------------\n";

    (* Decrypt *)
    let decrypted_data_ = decrypt_some_data session crypt_mech privkey_ crypted_data_ in

    printf "--------------\n";
    printf "DECRYPTED DATA\n";
    Pkcs11.print_char_array decrypted_data_;
    printf "--------------\n";

    (* CreateObject new publickey from previous values pubkey_*)
    (* Prepare empty templates *)
    let x1 = { Pkcs11.type_ = Pkcs11.cKA_MODULUS; Pkcs11.value = [||]} in
    let x2 = { Pkcs11.type_ = Pkcs11.cKA_PUBLIC_EXPONENT; Pkcs11.value = [||]} in
    let modbit_template = [| x1; x2 |] in

    (* First GetAttrValue call fills value fields with zeros, then seconds calls fills with real value *)
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session pubkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError false in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session pubkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError false in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "--------------\n";
    printf "CKA_MODULUS and CKA_PUBLIC_EXPONENT templates\n";
    Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;
    Pkcs11.print_hex_array modbit_template.(1).Pkcs11.value;

    (* Common *)
    let pub_template = [||] in
    (*Append fetched values from x1 and x2 *)
    let pub_template = Array.append modbit_template pub_template in

    let id = Pkcs11.string_to_char_array "789" in
    let pub_template = templ_append pub_template Pkcs11.cKA_ID id in

    let keytype = Pkcs11.int_to_ulong_char_array Pkcs11.cKK_RSA in
    let pub_template = templ_append pub_template Pkcs11.cKA_KEY_TYPE keytype in

    (* PublicTemplate *)
    let pubclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in

    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in
    let label = Pkcs11.string_to_char_array "testlabel" in
    let pub_template = templ_append pub_template Pkcs11.cKA_WRAP Pkcs11.true_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_TOKEN Pkcs11.true_ in

    let (ret_value, _) = Pkcs11.mL_CK_C_CreateObject session pub_template in
    let _ = check_ret ret_value C_CreateObjectError false in
    printf "C_CreateObject ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    printf "--------------\n";
    (* PrivateTemplate *)
    let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in

    let priv_expo = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE_EXPONENT; Pkcs11.value = [||]} in
    let modbit_template = [| priv_expo |] in
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session privkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError true in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session privkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError true in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "CKA_PRIVATE_EXPONENT template *before* destruction\n";
    Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;

    (* DestroyObject *)
    (*
    let ret_value =  Pkcs11.mL_CK_C_DestroyObject session privkey_ in
    let _ = check_ret ret_value C_DestroyObjectError false in
    printf "C_DestroyObject ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let modbit_template = [| priv_expo |] in
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session privkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError true in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, modbit_template) = Pkcs11.mL_CK_C_GetAttributeValue session privkey_ modbit_template in
    let _ = check_ret ret_value C_GetAttributeValueError true in
    printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "CKA_PRIVATE_EXPONENT template *after* destruction\n";
    Pkcs11.print_hex_array modbit_template.(0).Pkcs11.value;
    printf "--------------\n";

    (* Recreate Object from retrieved attribute *)
    let newpriv_template = [||] in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_CLASS privclass in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_KEY_TYPE keytype in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_SENSITIVE Pkcs11.true_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_SIGN Pkcs11.true_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_EXTRACTABLE Pkcs11.false_ in
    let newpriv_template = templ_append newpriv_template Pkcs11.cKA_PRIVATE_EXPONENT [||] in

    (* The call should fail because CKA_PRIVATE_EXPONENT is empty *)
    let (ret_value, newprivkey_) = Pkcs11.mL_CK_C_CreateObject session newpriv_template in
    let _ = check_ret ret_value C_CreateObjectError true in
    printf "C_CreateObject should fail ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let (found_, number_) = find_objects session [||] 10n in
    
    printf "Found %d objects\n" (Nativeint.to_int number_);

    (* 
    let ret_value = Pkcs11.mL_CK_C_Logout session in
    printf "C_Logout ret: %s\n" (Pkcs11.match_cKR_value ret_value); 
    let ret_value = Pkcs11.mL_CK_C_CloseSession session in
    printf "C_CloseSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    *)


    (* Let's open a session for the _Random ops *)
    let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id Pkcs11.cKF_SERIAL_SESSION in
    let _ = check_ret ret_value C_OpenSessionError false in
    printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    (* GetSessionInfo *)
    let (ret_value, session_info_) = Pkcs11.mL_CK_C_GetSessionInfo session in
    let _ = check_ret ret_value C_GetSessionInfoError false in
    printf "GetSessionInfo example below\n";
    printf "CKS_R0_USER_FUNCTIONS: %d\n" (Nativeint.to_int Pkcs11.cKS_RO_USER_FUNCTIONS);
    printf "Session state        : %d\n" (Nativeint.to_int session_info_.Pkcs11.ck_session_info_state);

    (* SeedRandom *)
    let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
    let _ = check_ret ret_value C_LoginError false in
    printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let rand = Pkcs11.string_to_char_array "ThisIsSuperMegaRandom" in
    let ret_value = Pkcs11.mL_CK_C_SeedRandom session rand in
    let _ = check_ret ret_value C_SeedRandomError false in
    printf "C_SeedRandom ret: %s\n" (Pkcs11.match_cKR_value ret_value);

     
    (* GenerateRandom *)
    let rand_len = 32n in
    let (ret_value, rand_array) = Pkcs11.mL_CK_C_GenerateRandom session rand_len in
    let _ = check_ret ret_value C_GenerateRandomError false in
    printf "C_GenerateRandom ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "--------------\n";
    printf "Random string of length %d got from C_GenerateRandom:\n" (Nativeint.to_int rand_len);
    Pkcs11.print_hex_array rand_array;
    *)

    (* Generate a symmetric Key *)
    (* Template *)

    (* GenerateKey DES_KEY *)
    if check_element_in_list (Array.to_list mechanism_list_) Pkcs11.cKM_DES3_KEY_GEN  = true then
        begin
        printf "DES key generation support, let's try Wrap/Unwrap\n";
       
        let my_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES3_KEY_GEN ; Pkcs11.parameter = [| |] } in

        let x1 = { Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.true_}
        in
        let x2 = { Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.true_}
        in
        let (ret_value, deskey_) = Pkcs11.mL_CK_C_GenerateKey session my_mech [|
            x1 ; x2  |] in
        let _ = check_ret ret_value C_GenerateKeyError true in
        printf "C_GenerateKey DES ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "C_GenerateKey DES handle: %s\n" (Nativeint.to_string deskey_);

        (* Dump the key value we have created *)
        let deskey_value = { Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [||]} in
        let deskey_template = [| deskey_value |] in
        let (ret_value, deskey_template) = Pkcs11.mL_CK_C_GetAttributeValue session deskey_ deskey_template in
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        let (ret_value, deskey_template) = Pkcs11.mL_CK_C_GetAttributeValue session deskey_ deskey_template in
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "--------------\n";
        printf "DES key value generated with C_GenerateKey:\n";
        Pkcs11.print_hex_array deskey_template.(0).Pkcs11.value;

        (* Let's wrap the RSA privkey with the DES key *)
        let iv = Pkcs11.string_to_char_array (Pkcs11.pack "0000000000000000") in
        let wrapping_mech = { Pkcs11.mechanism = Pkcs11.cKM_DES3_CBC_PAD ;
        Pkcs11.parameter = iv } in
        let (ret_value, wrapped_key_) = Pkcs11.mL_CK_C_WrapKey session wrapping_mech deskey_ privkey_ in
        let _ = check_ret ret_value C_WrapKeyError true in
        printf "C_WrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "--------------\n";
        printf "Wrapped RSA private key with DES_ECB:\n";
        Pkcs11.print_hex_array wrapped_key_;

        (* Try to Unwrap the key *)
        let priv_template = [||] in
        let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in
        let priv_template = templ_append priv_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_ID id in
        let priv_template = templ_append priv_template Pkcs11.cKA_LABEL label in
        let priv_template = templ_append priv_template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_SIGN Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_UNWRAP Pkcs11.true_ in
        let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in

        (* This call should fail because the session is RO *)
        let (ret_value, _) = Pkcs11.mL_CK_C_UnwrapKey session wrapping_mech deskey_ wrapped_key_ priv_template in
        let _ = check_ret ret_value C_UnwrapKeyError true in
        printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        (* Open a new RW session *)
        let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        (* Login again *)
        let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
        let _ = check_ret ret_value C_LoginError false in
        printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        (* This call should succeed since the session is RW now *)
        let (ret_value, unwrapped_key_handle_) = Pkcs11.mL_CK_C_UnwrapKey session wrapping_mech deskey_ wrapped_key_ priv_template in
        let _ = check_ret ret_value C_UnwrapKeyError true in
        printf "C_UnwrapKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        (* Now extract the key *)
        let priv_expo = { Pkcs11.type_ = Pkcs11.cKA_PRIVATE_EXPONENT; Pkcs11.value = [||]} in
        let unwrappedkey_template = [| priv_expo |] in
        let (ret_value, unwrappedkey_template) = Pkcs11.mL_CK_C_GetAttributeValue session unwrapped_key_handle_ unwrappedkey_template in 
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        let (ret_value, unwrappedkey_template) = Pkcs11.mL_CK_C_GetAttributeValue session unwrapped_key_handle_ unwrappedkey_template in
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "--------------\n";
        printf "CKA_PRIVATE_EXPONENT template after Unwrap with the DES key\n";
        Pkcs11.print_hex_array unwrappedkey_template.(0).Pkcs11.value;
        end

    else
        begin
        printf "Cannot generate DES KEY skipping Wrap/Unwrap\n";
        (* Open a new RW session *)
        let (ret_value, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        printf "C_OpenSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        (* Login again *)
        let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER user_pin in
        let _ = check_ret ret_value C_LoginError false in
        printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        end;

    if check_element_in_list (Array.to_list mechanism_list_) Pkcs11.cKM_DH_PKCS_KEY_PAIR_GEN  = true then
        begin
        printf "DH key generation support, let's try DES KEY derivation\n";
        (* Derive a key (we first generate a DH key pair) *)
        (* MechanismChoice *)
        let dh_mech = { Pkcs11.mechanism = Pkcs11.cKM_DH_PKCS_KEY_PAIR_GEN ; Pkcs11.parameter = [| |] } in
        (* PublicTemplate *)
        let pub_dh_template = [||] in
        let priv_dh_template = [||] in
        let derive_template = [||] in
        let prime = Pkcs11.string_to_char_array (Pkcs11.pack "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF") in
        let base = Pkcs11.int_to_ulong_char_array 2n in
        let pub_dh_template = templ_append pub_dh_template Pkcs11.cKA_PRIME prime in
        let pub_dh_template = templ_append pub_dh_template Pkcs11.cKA_BASE base in
        (* PrivateTemplate *)
        let priv_dh_template = templ_append priv_dh_template Pkcs11.cKA_DERIVE Pkcs11.true_ in
        (* GenerateKeyPair *)
        let (ret_value, _, privkeydh_) = Pkcs11.mL_CK_C_GenerateKeyPair session dh_mech pub_dh_template priv_dh_template in
        let _ = check_ret ret_value C_GenerateKeyPairError true in
        printf "C_GenerateKeyPair ret: %s\n" (Pkcs11.match_cKR_value ret_value);

        (* Derivation *)
        (* Create derive_mech with parameter, array of size 128 filled with '0' *)
        let derive_mech = { Pkcs11.mechanism = Pkcs11.cKM_DH_PKCS_DERIVE ; Pkcs11.parameter = Array.make 128 '0'} in
        (* Create derive_template, derived key will encrypt/decrypt *)
        let derive_template = templ_append derive_template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY) in
        let derive_template = templ_append derive_template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array Pkcs11.cKK_DES) in
        let derive_template = templ_append derive_template Pkcs11.cKA_ENCRYPT Pkcs11.true_ in
        let derive_template = templ_append derive_template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
        let (ret_value, derived_key_handle_) = Pkcs11.mL_CK_C_DeriveKey session derive_mech privkeydh_ derive_template in
        let _ = check_ret ret_value C_DeriveKeyError true in
        printf "C_DeriveKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        let derived_deskey_value = { Pkcs11.type_ = Pkcs11.cKA_VALUE; Pkcs11.value = [||]} in
        let derived_key_template = [| derived_deskey_value |] in
        let (ret_value, derived_key_template) = Pkcs11.mL_CK_C_GetAttributeValue session derived_key_handle_ derived_key_template in
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        let (ret_value, derived_key_template) = Pkcs11.mL_CK_C_GetAttributeValue session derived_key_handle_ derived_key_template in
        let _ = check_ret ret_value C_GetAttributeValueError true in
        printf "C_GetAttributeValue ret: %s\n" (Pkcs11.match_cKR_value ret_value);
        printf "--------------\n";
        printf "DES key value derived from DH key\n";
        Pkcs11.print_hex_array derived_key_template.(0).Pkcs11.value;
        end
    else
        printf "No DH key generation support, skipping key derivation\n";

    (* Digest *)
    let digest_mech = { Pkcs11.mechanism = Pkcs11.cKM_MD5 ; Pkcs11.parameter = [| |] } in

    let string_to_digest = "the brown fox jumps over the lazy dog" in

    let digest_ = digestupdate_some_data session digest_mech string_to_digest in

    printf "--------------\n";
    printf "MD5 digest of '%s'\n" string_to_digest;
    printf "\tthrough Update/Final is:\n";
    Pkcs11.print_hex_array digest_;
    let digest_ = digest_some_data session digest_mech string_to_digest in
    printf "\tthrough Digest single call is:\n";
    Pkcs11.print_hex_array digest_;


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
    (* Logout on BAD Session ID *)
    let ret_value = Pkcs11.mL_CK_C_Logout 20n in
    let _ = check_ret ret_value C_LogoutError true in
    printf "BAD C_Logout ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let ret_value = Pkcs11.mL_CK_C_Finalize () in
    let _ = check_ret ret_value C_FinalizeError false in
    printf "C_Finalize ret: %s\n" (Pkcs11.match_cKR_value ret_value)
