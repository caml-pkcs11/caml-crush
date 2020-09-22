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
    File:    src/filter/filter/p11fix_patches/wrapping_format_patch.ml

************************** MIT License HEADER ***********************************)
(***********************************************************************)
(* The wrapping format patch:                                          *)
(* see http://secgroup.dais.unive.it/projects/security-apis/cryptokix/ *)

(* Include the CMAC helpers here *)
INCLUDE "p11fix_patches/cmac.ml"

(* Create a buffer from critical attributes *)
let template_array_to_char_array templates =
  let out_array = Array.map (
    fun temp ->
      let check_value = get_existing_attribute_value templates temp in 
      (* Attribute found, we add its true value *)
      (* Do we have a CKA_CLASS attribute?      *)
      (* If yes, keep the 32-bit value          *)
      if compare temp.Pkcs11.type_ Pkcs11.cKA_CLASS = 0 then
        if compare check_value [||] = 0 then
          (* Attribute not found, we put a "0xff..." so that we can import it *)
          ([|Char.chr 0xff; Char.chr 0xff; Char.chr 0xff; Char.chr 0xff|])
        else
          (Pkcs11.hton_char_array check_value)
      else 
        if compare check_value [||] = 0 then
          ([|Char.chr 0xff|])
        else
          (* If it is not a CKA_CLASS attribute, it is a boolean *)
          if compare (Pkcs11.char_array_to_bool check_value) Pkcs11.cK_TRUE = 0 then
            ([|Char.chr 0x1|])
          else
            ([|Char.chr 0x0|])
  ) (critical_attributes !segregate_usage) in
  (Array.concat (Array.to_list out_array))

(* Extract critical attributes from a buffer *)
let char_array_to_template_array buffer =
  let i = ref 0 in
  let out_template_array = (
  if compare (Array.length buffer) (Array.length (critical_attributes !segregate_usage)+3) = 0 then
    Array.map (
      fun the_attribute ->
      if compare the_attribute.Pkcs11.type_ Pkcs11.cKA_CLASS = 0 then
        (* We have an ulong value *)
        (* Take 4 bytes           *)
        let extracted_chars = Array.sub buffer !i 4 in
        let the_value = (
          if compare extracted_chars [|Char.chr 0xff; Char.chr 0xff; Char.chr 0xff; Char.chr 0xff|] = 0 then
            ([||])
          else
            (Pkcs11.ntoh_char_array extracted_chars)
        ) in
        i := !i + 4;
        ({Pkcs11.type_ = the_attribute.Pkcs11.type_; 
          Pkcs11.value = the_value})
      else
        (* We have a boolean value *)
        let the_value = (
          if compare buffer.(!i) (Char.chr 0x1) = 0 then
            (Pkcs11.bool_to_char_array Pkcs11.cK_TRUE)
          else
            if compare buffer.(!i) (Char.chr 0x0) = 0 then
              (Pkcs11.bool_to_char_array Pkcs11.cK_FALSE)
            else
            ([||])
        ) in
        i := !i + 1;
        ({Pkcs11.type_ = the_attribute.Pkcs11.type_; 
          Pkcs11.value = the_value})
    ) (critical_attributes !segregate_usage)
  else
    ([||])
  ) in
  (* Expurge the template from empty attributes *)
  (expurge_template_from_irrelevant_attributes out_template_array)


(**************    WARNING ************************************)
(* We use the key configured in the filter configuration file *)
(* You might preferably want to use a key secured in a token  *)
(************************************************************************************************************)


let wrapping_format_patch fun_name arg =
  (* Raise an error if the key is empty *)
  if Array.length !wrapping_format_key = 0 then
    let s = Printf.sprintf "[User defined extensions] %s error for WRAPPING_FORMAT: no wrapping key format has been defined in the configuration file!\n" fun_name in netplex_log_critical s; failwith s;
  else
    match fun_name with
    (* WrapKey *)
    ("C_WrapKey")  ->
        let (sessionh, mechanism, wrappingh, wrappedh) = deserialize arg in
        (* Call Wrap in the backend to get binary blob *)
        let (ret, wrapped_key_buffer) = Backend.c_WrapKey sessionh mechanism wrappingh wrappedh in
        (* If we have an error here, return it as is *)
        if compare ret Pkcs11.cKR_OK <> 0 then
          (serialize (true, (ret, [||])))
        else
          (* Get the attributes of the object we want to wrap *)
          let (ret, templates) = filter_getAttributeValue sessionh wrappedh (critical_attributes !segregate_usage) in
          if (compare ret Pkcs11.cKR_OK <> 0) || (compare templates [||] = 0) then
            if (compare ret Pkcs11.cKR_OK <> 0) then
              (serialize (true, (Pkcs11.cKR_KEY_NOT_WRAPPABLE, [||])))
            else
              let s = "[User defined extensions] C_GettAttributeValue CRITICAL ERROR when getting critical attributes (it is not possible to get these attributes from the backend ...): occured during C_WrapKey for WRAPPING_FORMAT\n" in netplex_log_critical s; failwith s;
          else
            let (ret, templates_values) = filter_getAttributeValue sessionh wrappedh templates in
            if compare ret Pkcs11.cKR_OK <> 0 then
              (serialize (true, (Pkcs11.cKR_KEY_NOT_WRAPPABLE, [||])))
            else
              (* Compute the buffer *)
              let buffer = Array.append wrapped_key_buffer (template_array_to_char_array templates_values) in
              (* Compute the CMAC *)
              let buffer_cmac = cmac_compute buffer !wrapping_format_key in
              (* Append the CMAC to the buffer *)
              let wrapping_format_buffer = Array.append buffer buffer_cmac in
              (serialize (true, (Pkcs11.cKR_OK, wrapping_format_buffer)))
    (* UnwrapKey *)
    | ("C_UnwrapKey")  ->
        let (sessionh, mechanism, unwrappingh, buffer, asked_attributes) = deserialize arg in
        let attributes_array_buffer_length = (Array.length (critical_attributes !segregate_usage))+3 in
        (****)
        let extraction_error_ = false in
        let extraction_error = ref extraction_error_ in
        let buffer_attributes = (try Array.sub buffer ((Array.length buffer) - attributes_array_buffer_length - 16) attributes_array_buffer_length
          with _ -> extraction_error := true; ([||])
        ) in
        let real_wrapped_key_buffer =  (try Array.sub buffer 0 ((Array.length buffer) - attributes_array_buffer_length - 16)
          with _ -> extraction_error := true; ([||])
        ) in
        if compare !extraction_error true = 0 then
          (* In case of an extraction error ... *)
          let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected bad CMAC" fun_name in
          let _ = print_debug info_string 1 in
          (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
        else
          (* Compute the CMAC *)
          let check_cmac = cmac_verify buffer !wrapping_format_key in
          if compare check_cmac false = 0 then
            (* CMAC is not OK: return an error *)
            let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected bad CMAC" fun_name in
            let _ = print_debug info_string 1 in
            (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
          else
            (* CMAC is OK, check the templates consistency *)
            let saved_attributes = char_array_to_template_array buffer_attributes in
            let check_templates_nok = check_are_templates_nonconforming fun_name saved_attributes asked_attributes in
            if compare check_templates_nok true = 0 then
              let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s detected templates inconsistency" fun_name in
              let _ = print_debug info_string 1 in
              (serialize (true, (Pkcs11.cKR_TEMPLATE_INCONSISTENT, Pkcs11.cK_INVALID_HANDLE)))
            else
              (* Sanitize the merged template *)
              let object_class = get_object_class asked_attributes in
              let sanitized_attributes_ = sanitize_creation_templates fun_name asked_attributes object_class in
              (* NB: we cannot use the generic patch because of our user extension system limitation *)
              (* since the wrapping_format must be an "end point"                                    *)
              if compare sanitized_attributes_ None = 0 then
                let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s error, NO CKA_CLASS in template" fun_name in
                let _ = print_debug info_string 1 in
                (serialize (true, (Pkcs11.cKR_FUNCTION_FAILED, Pkcs11.cK_INVALID_HANDLE)))
              else
                let info_string = Printf.sprintf "[User defined extensions]: WRAPPING_FORMAT for %s has CMAC and templates OK" fun_name in
                let _ = print_debug info_string 1 in
                (* All is OK, call the real Unwrap function from the backend *)
                (serialize (true, (Backend.c_UnwrapKey sessionh mechanism unwrappingh real_wrapped_key_buffer (get sanitized_attributes_))))
    (* Default if we are in a non concerned function is to passthrough *)
    | _ -> (serialize (false, ()))
