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
    File:    src/tests/ocaml/destroy.ml

************************** MIT License HEADER ***********************************)
open Printf
open P11_common

let destroy_all session obj = 
  let ret_value = Pkcs11.mL_CK_C_DestroyObject session obj in
  printf "C_DestroyObject ret: %s for object %s\n" (Pkcs11.match_cKR_value ret_value) (Nativeint.to_string obj)

let _ = 
    let _ = init_module in
    let conf_user_pin = fetch_pin in
    let ret_value = Pkcs11.mL_CK_C_Initialize () in
    printf "C_Initialize ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    (* GetSlotList *)
    let (ret_value, slot_list_, count) = Pkcs11.mL_CK_C_GetSlotList 0n 0n in
    printf "C_GetSlotList ret: %s, Count = %s, slot_list =" (Nativeint.to_string ret_value) (Nativeint.to_string count);
    Pkcs11.print_int_array slot_list_;

    let (ret_value, slot_list_, count) = Pkcs11.mL_CK_C_GetSlotList 0n count in
    printf "C_GetSlotList ret: %s, Count = %s, slot_list =" (Nativeint.to_string ret_value) (Nativeint.to_string count);
    Pkcs11.print_int_array slot_list_;

    (* Print SlotInfo and TokenInfo *)
    Array.iter print_slots slot_list_;

    (* hardcoded take first available slot *)
    let slot_id = slot_list_.(0) in

    let (_, session) = Pkcs11.mL_CK_C_OpenSession slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let pin = Pkcs11.string_to_char_array conf_user_pin in
    let ret_value = Pkcs11.mL_CK_C_Login session Pkcs11.cKU_USER pin in
    printf "C_Login ret: %s\n" (Pkcs11.match_cKR_value ret_value);

    let ret_value =  Pkcs11.mL_CK_C_FindObjectsInit session [||] in
    printf "C_FindObjectsInit ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, found_, number_) =  Pkcs11.mL_CK_C_FindObjects session 100n in
    printf "C_FindObjects ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let ret_value =  Pkcs11.mL_CK_C_FindObjectsFinal session in
    printf "C_FindObjectsFinal ret %s Found %s objects\n" (Pkcs11.match_cKR_value ret_value) (Nativeint.to_string number_);

    Array.iter (destroy_all session) found_;

    let ret_value = Pkcs11.mL_CK_C_Logout session in
    printf "C_Logout ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let ret_value = Pkcs11.mL_CK_C_CloseSession session in
    printf "C_CloseSession ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let ret_value = Pkcs11.mL_CK_C_Finalize () in
    printf "C_Finalize ret: %s\n" (Pkcs11.match_cKR_value ret_value)
