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

    The current source code is part of the RPC 2] source tree:
                          --------  socket (TCP or Unix)  --------------------
                         |2] RPC  |<+++++++++++++++++++> |                    |
                         |  Layer | [SSL/TLS optional]   |  --------          |
                          --------                       | |2] RPC  |         |
                                                         | |  Layer |         |
                                                         |  --------          |
                                                          --------------------

    Project: PKCS#11 Filtering Proxy
    File:    src/rpc-pkcs11/rpc_helpers.ml

************************** MIT License HEADER ***********************************)
open Pkcs11_rpc_aux
open Pkcs11

(* Manual conversion functions *)

let ck_version_pkcs11_to_rpc_aux input = 
  let output = {
    Pkcs11_rpc_aux.major = Pkcs11.char_array_to_string (Array.make 1 input.major);
    Pkcs11_rpc_aux.minor = Pkcs11.char_array_to_string (Array.make 1 input.minor) 
    } in
  (output)

let ck_info_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_info_cryptoki_version = (ck_version_pkcs11_to_rpc_aux input.ck_info_cryptoki_version);
        Pkcs11_rpc_aux.rpc_ck_info_manufacturer_id = (Pkcs11.char_array_to_string input.ck_info_manufacturer_id);
        Pkcs11_rpc_aux.rpc_ck_info_flags = Int64.of_nativeint input.ck_info_flags;
        Pkcs11_rpc_aux.rpc_ck_info_library_description = (Pkcs11.char_array_to_string input.ck_info_library_description);
        Pkcs11_rpc_aux.rpc_ck_info_library_version = (ck_version_pkcs11_to_rpc_aux input.ck_info_library_version)
      } in
    (output)

let ck_slot_info_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_slot_info_slot_description = (Pkcs11.char_array_to_string input.ck_slot_info_slot_description);
        Pkcs11_rpc_aux.rpc_ck_slot_info_manufacturer_id = (Pkcs11.char_array_to_string input.ck_slot_info_manufacturer_id);
        Pkcs11_rpc_aux.rpc_ck_slot_info_flags = Int64.of_nativeint input.ck_slot_info_flags;
        Pkcs11_rpc_aux.rpc_ck_slot_info_hardware_version = (ck_version_pkcs11_to_rpc_aux input.ck_slot_info_hardware_version);
        Pkcs11_rpc_aux.rpc_ck_slot_info_firmware_version = (ck_version_pkcs11_to_rpc_aux input.ck_slot_info_firmware_version);
      } in
    (output)

let ck_token_info_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_token_info_label = (Pkcs11.char_array_to_string input.ck_token_info_label);
        Pkcs11_rpc_aux.rpc_ck_token_info_manufacturer_id = (Pkcs11.char_array_to_string input.ck_token_info_manufacturer_id);
        Pkcs11_rpc_aux.rpc_ck_token_info_model = (Pkcs11.char_array_to_string input.ck_token_info_model);
        Pkcs11_rpc_aux.rpc_ck_token_info_serial_number = (Pkcs11.char_array_to_string input.ck_token_info_serial_number);
        Pkcs11_rpc_aux.rpc_ck_token_info_flags = Int64.of_nativeint input.ck_token_info_flags;
        Pkcs11_rpc_aux.rpc_ck_token_info_max_session_count = Int64.of_nativeint input.ck_token_info_max_session_count;
        Pkcs11_rpc_aux.rpc_ck_token_info_session_count = Int64.of_nativeint input.ck_token_info_session_count;
        Pkcs11_rpc_aux.rpc_ck_token_info_max_rw_session_count = Int64.of_nativeint input.ck_token_info_max_rw_session_count;
        Pkcs11_rpc_aux.rpc_ck_token_info_rw_session_count = Int64.of_nativeint input.ck_token_info_rw_session_count;
        Pkcs11_rpc_aux.rpc_ck_token_info_max_pin_len = Int64.of_nativeint input.ck_token_info_max_pin_len;
        Pkcs11_rpc_aux.rpc_ck_token_info_min_pin_len = Int64.of_nativeint input.ck_token_info_min_pin_len;
        Pkcs11_rpc_aux.rpc_ck_token_info_total_public_memory = Int64.of_nativeint input.ck_token_info_total_public_memory;
        Pkcs11_rpc_aux.rpc_ck_token_info_free_public_memory = Int64.of_nativeint input.ck_token_info_free_public_memory;
        Pkcs11_rpc_aux.rpc_ck_token_info_total_private_memory = Int64.of_nativeint input.ck_token_info_total_private_memory;
        Pkcs11_rpc_aux.rpc_ck_token_info_free_private_memory = Int64.of_nativeint input.ck_token_info_free_private_memory;
        Pkcs11_rpc_aux.rpc_ck_token_info_hardware_version = (ck_version_pkcs11_to_rpc_aux input.ck_token_info_hardware_version);
        Pkcs11_rpc_aux.rpc_ck_token_info_firmware_version = (ck_version_pkcs11_to_rpc_aux input.ck_token_info_firmware_version);
        Pkcs11_rpc_aux.rpc_ck_token_info_utc_time = (Pkcs11.char_array_to_string input.ck_token_info_utc_time)
      } in
    (output)

let ck_attribute_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_attribute_type = Int64.of_nativeint input.type_;
        Pkcs11_rpc_aux.rpc_ck_attribute_value = (Pkcs11.char_array_to_string input.value);
        Pkcs11_rpc_aux.rpc_ck_attribute_value_len = Int64.of_int (Array.length input.value)
      } in
    (output)

let ck_date_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_date_year = (Pkcs11.char_array_to_string input.year);
        Pkcs11_rpc_aux.rpc_ck_date_month = (Pkcs11.char_array_to_string input.month);
        Pkcs11_rpc_aux.rpc_ck_date_day = (Pkcs11.char_array_to_string input.day)
      } in
    (output)

let ck_mechanism_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_mechanism_mechanism = Int64.of_nativeint input.mechanism;
        Pkcs11_rpc_aux.rpc_ck_mechanism_parameter = (Pkcs11.char_array_to_string input.parameter);
      } in
    (output)

let ck_session_info_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_session_info_slot_id = Int64.of_nativeint input.ck_session_info_slot_id;
        Pkcs11_rpc_aux.rpc_ck_session_info_state = Int64.of_nativeint input.ck_session_info_state;
        Pkcs11_rpc_aux.rpc_ck_session_info_flags = Int64.of_nativeint input.ck_session_info_flags;
        Pkcs11_rpc_aux.rpc_ck_session_info_device_error = Int64.of_nativeint input.ck_session_info_device_error
      } in
    (output)

let ck_mechanism_info_pkcs11_to_rpc_aux input =
    let output = {
        Pkcs11_rpc_aux.rpc_ck_mechanism_info_min_key_size = Int64.of_nativeint input.ck_mechanism_info_min_key_size;
        Pkcs11_rpc_aux.rpc_ck_mechanism_info_max_key_size = Int64.of_nativeint input.ck_mechanism_info_max_key_size;
        Pkcs11_rpc_aux.rpc_ck_mechanism_info_flags = Int64.of_nativeint input.ck_mechanism_info_flags
      } in
    (output)


(* GO in CLIENT *)
let ck_version_rpc_aux_to_pkcs11 input = 
  let output = {
    Pkcs11.major = (Pkcs11.string_to_char_array (input.Pkcs11_rpc_aux.major)).(0);
    Pkcs11.minor = (Pkcs11.string_to_char_array (input.Pkcs11_rpc_aux.minor)).(0) 
    } in
  (output)

let ck_info_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.ck_info_cryptoki_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_info_cryptoki_version);
        Pkcs11.ck_info_manufacturer_id = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_info_manufacturer_id);
        Pkcs11.ck_info_flags = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_info_flags;
        Pkcs11.ck_info_library_description = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_info_library_description);
        Pkcs11.ck_info_library_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_info_library_version)
      } in
    (output)

let ck_slot_info_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.ck_slot_info_slot_description = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_slot_info_slot_description);
        Pkcs11.ck_slot_info_manufacturer_id = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_slot_info_manufacturer_id);
        Pkcs11.ck_slot_info_flags = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_slot_info_flags;
        Pkcs11.ck_slot_info_hardware_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_slot_info_hardware_version);
        Pkcs11.ck_slot_info_firmware_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_slot_info_firmware_version);
      } in
    (output)

let ck_token_info_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.ck_token_info_label = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_token_info_label);
        Pkcs11.ck_token_info_manufacturer_id = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_token_info_manufacturer_id);
        Pkcs11.ck_token_info_model = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_token_info_model);
        Pkcs11.ck_token_info_serial_number = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_token_info_serial_number);
        Pkcs11.ck_token_info_flags = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_flags;
        Pkcs11.ck_token_info_max_session_count = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_max_session_count;
        Pkcs11.ck_token_info_session_count = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_session_count;
        Pkcs11.ck_token_info_max_rw_session_count = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_max_rw_session_count;
        Pkcs11.ck_token_info_rw_session_count = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_rw_session_count;
        Pkcs11.ck_token_info_max_pin_len = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_max_pin_len;
        Pkcs11.ck_token_info_min_pin_len = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_min_pin_len;
        Pkcs11.ck_token_info_total_public_memory = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_total_public_memory;
        Pkcs11.ck_token_info_free_public_memory = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_free_public_memory;
        Pkcs11.ck_token_info_total_private_memory = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_total_private_memory;
        Pkcs11.ck_token_info_free_private_memory = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_token_info_free_private_memory;
        Pkcs11.ck_token_info_hardware_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_token_info_hardware_version);
        Pkcs11.ck_token_info_firmware_version = (ck_version_rpc_aux_to_pkcs11 input.Pkcs11_rpc_aux.rpc_ck_token_info_firmware_version);
        Pkcs11.ck_token_info_utc_time = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_token_info_utc_time)
      } in
    (output)

let ck_attribute_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.type_ = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_attribute_type;
        Pkcs11.value = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_attribute_value);
      } in
    (output)

let ck_date_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.year = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_date_year);
        Pkcs11.month = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_date_month);
        Pkcs11.day = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_date_day)
      } in
    (output)

let ck_mechanism_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.mechanism = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_mechanism_mechanism;
        Pkcs11.parameter = (Pkcs11.string_to_char_array input.Pkcs11_rpc_aux.rpc_ck_mechanism_parameter);
      } in
    (output)

let ck_session_info_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.ck_session_info_slot_id = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_session_info_slot_id;
        Pkcs11.ck_session_info_state = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_session_info_state;
        Pkcs11.ck_session_info_flags = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_session_info_flags;
        Pkcs11.ck_session_info_device_error = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_session_info_device_error
      } in
    (output)

let ck_mechanism_info_rpc_aux_to_pkcs11 input =
    let output = {
        Pkcs11.ck_mechanism_info_min_key_size = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_mechanism_info_min_key_size;
        Pkcs11.ck_mechanism_info_max_key_size = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_mechanism_info_max_key_size;
        Pkcs11.ck_mechanism_info_flags = Int64.to_nativeint input.Pkcs11_rpc_aux.rpc_ck_mechanism_info_flags;
      } in
    (output)

