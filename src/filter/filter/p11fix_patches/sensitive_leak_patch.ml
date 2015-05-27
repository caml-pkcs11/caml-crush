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

    The current source code is part of the PKCS#11 filter 4] source tree:

           |
 ----------------------
| 4] PKCS#11 filter    |
 ----------------------
           |

    Project: PKCS#11 Filtering Proxy
    File:    src/filter/filter/p11fix_patches/sensitive_leak_patch.ml

************************** MIT License HEADER ***********************************)
(***********************************************************************)
(* The patch preventing directly reading or writhing to sensitive or   *)
(* extractable keys.                                                   *)
(* This patch also prevents directly setting CKA_ALWAYS_SENSITIVE and  *)
(* CKA_NEVER_EXTRACTABLE                                               *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

let prevent_sensitive_leak_patch fun_name arg = 
  match fun_name with
    "C_GetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (getAttributeValueErrors ret, attributes)))
        else
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in let _ = netplex_log_critical s in netplex_log_critical s; failwith s;
        else
          (* If the object is sensitive or non-extractable, and we ask for a value, we return an error *)
          if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_VALUE attributes) true = 0) && 
             ((compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) 
              || (compare (check_is_attribute_set fun_name Pkcs11.cKA_EXTRACTABLE templates_values) true = 0)) then
            let error_type = 
              if (compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) then "SENSITIVE" else "NON EXTRACTABLE" in
            let info_string = Printf.sprintf "[User defined extensions]: SENSITIVE_LEAK asked during %s for a %s key" fun_name error_type in
            let _ = print_debug info_string 1 in
            (* We expurge the template from the value type and call the backend *)
            let (new_attributes, positions) = remove_asked_value_type_from_template attributes in
            let (ret, returned_attributes) = Backend.c_GetAttributeValue sessionh objecth new_attributes in
            (* Now, we reinsert the value type in the template with zeroes *)
            let filtered_attributes = insert_purged_value_type_in_template returned_attributes positions in
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_SENSITIVE, filtered_attributes)))
          else
            (* If we are here, we passthrough the call *)
            (serialize (false, ()))
  | "C_SetAttributeValue" ->
      let (sessionh, objecth, attributes) = deserialize arg in
      let (ret, templates) = filter_getAttributeValue sessionh objecth (critical_attributes !segregate_usage) in
      if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
        if (compare ret Pkcs11.cKR_OK <> 0) then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
        else
          let s = "[User defined extensions] C_SettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): inside SENSITIVE_LEAK\n" in netplex_log_critical s; failwith s;
      else
        let (ret, templates_values) = filter_getAttributeValue sessionh objecth templates in
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
        else
          (* If the object is sensitive or non-extractable, and we ask for a value to be set, we return an error *)
          if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_VALUE attributes) true = 0) && 
             ((compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) 
              || (compare (check_is_attribute_set fun_name Pkcs11.cKA_EXTRACTABLE templates_values) true = 0)) then
            let error_type = 
              if (compare (check_is_attribute_set fun_name Pkcs11.cKA_SENSITIVE templates_values) true = 0) then "SENSITIVE" else "NON EXTRACTABLE" in
            let info_string = Printf.sprintf "[User defined extensions]: SENSITIVE_LEAK asked during %s for a %s key" fun_name error_type in
            let _ = print_debug info_string 1 in
            (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
          else
            (* If we ask for a modification of CKA_NEVER_EXTRACTABLE or CKA_ALWAYS_SENSITIVE, return an error *)
            if (compare (check_is_attribute_asked fun_name Pkcs11.cKA_ALWAYS_SENSITIVE attributes) true = 0) ||
               (compare (check_is_attribute_asked fun_name Pkcs11.cKA_NEVER_EXTRACTABLE attributes) true = 0) then
              (serialize (true, (Pkcs11.cKR_ATTRIBUTE_READ_ONLY)))
            (* If we end up here, passthrough *)
            else           
              (serialize (false, ()))
  (* Default if we are in a non concerned function is to passthrough *)
  | _ -> (serialize (false, ()))
