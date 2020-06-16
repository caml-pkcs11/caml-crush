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
    File:    src/filter/filter/p11fix_patches/non_local_objects_patch.ml

************************** MIT License HEADER ***********************************)
(***************************************************************************)
(* The non local objects patch:                                        *****)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *****)

(* When using the CryptokiX patches, we want to avoid keys created through *)
(* C_CreateObject to circumvent the protections                            *)
(* Hence, we filter C_CreateObject and do not allow WRAP/UNWRAP attributes *)
(* set with C_SetAttributeValue/C_CopyObject  for non local                *)
(* objects - i.e. CKA_LOCAL set to FALSE -                                 *)

let non_local_objects_dangerous_attributes = [| 
                                      {Pkcs11.type_ = Pkcs11.cKA_UNWRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                      {Pkcs11.type_ = Pkcs11.cKA_WRAP; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                      (* We should not be able to set CKA_LOCAL according to the standard, we enforce this however *)
                                      (* for C_CreateObject, C_CopyObject and C_SetAttribute                                       *)
                                      {Pkcs11.type_ = Pkcs11.cKA_LOCAL; Pkcs11.value = Pkcs11.bool_to_char_array Pkcs11.cK_TRUE};
                                               |]


let non_local_objects_patch fun_name arg =
  match fun_name with
  ("C_CreateObject")  ->
    let (_, extracted_attributes_array) = deserialize arg in
    (* First, we check if we are dealing with a key *)
    if compare (is_object_class_key extracted_attributes_array) true = 0 then
      let check = Array.fold_left (
        fun curr_check attr -> (curr_check || find_existing_attribute_value extracted_attributes_array attr)
      ) false non_local_objects_dangerous_attributes in
      if compare check true = 0 then
        (* We have found one of our dangerous attributes, this is not good! *)
        let info_string = Printf.sprintf "[User defined extensions]: NON_LOCAL_OBJECTS modification blocked during %s" fun_name in
        let _ = print_debug info_string 1 in
        (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
      else
        (* If all is ok, passthrough *)
        (serialize (false, ()))
    else
        (serialize (false, ()))
  | ("C_CopyObject" | "C_SetAttributeValue") ->
    let (sessionh, objecth, extracted_attributes_array) = deserialize arg in
    (* First, we check if we are dealing with a key *)
    if compare (is_existing_object_class_key sessionh objecth) true = 0 then
      (* Check if one of the dangerous attributes is concerned *)
      let check = Array.fold_left (
        fun curr_check attr -> (curr_check || find_existing_attribute_value extracted_attributes_array attr)
      ) false non_local_objects_dangerous_attributes in
      if compare check true = 0 then
        (* We have found one of our dangerous attributes, let's check if we must filter this call *)
        (* Extract the CKA_LOCAL attribute *)
        let (ret, templates) = Backend.c_GetAttributeValue sessionh objecth [|{Pkcs11.type_ = Pkcs11.cKA_LOCAL; Pkcs11.value = [||]}|] in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (* We cannot extract the CKA_LOCAL, which means that it is not a key *)
          (serialize (false, ()))
        else
          (* Extract the CKA_LOCAL value *)
          let (ret, templates_values) = Backend.c_GetAttributeValue sessionh objecth templates in
          if compare ret Pkcs11.cKR_OK <> 0 then
            (* We should not end up here ... *)
            let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting CKA_LOCAL (it is not possible to get these attributes from the backend ...)\n" in netplex_log_critical s; failwith s;
          else
            (* Check for CKA_LOCAL, if FALSE we give an error *)
            if compare (Pkcs11.char_array_to_bool templates_values.(0).Pkcs11.value) Pkcs11.cK_FALSE = 0 then
              (* The object is not local, block the call *)
              let info_string = Printf.sprintf "[User defined extensions]: NON_LOCAL_OBJECTS modification blocked during %s" fun_name in
              let _ = print_debug info_string 1 in
              if compare fun_name "C_CopyObject" = 0 then
                (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
              else
                (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT)))
            else
              (* No dangerous attribute us concerned ... *)
              (serialize (false, ()))
      else
        (* No dangerous attribute us concerned ... *)
        (serialize (false, ()))
    else
      (* No dangerous attribute us concerned ... *)
      (serialize (false, ()))
  | _ -> (serialize (false, ()))
