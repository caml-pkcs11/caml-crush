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
    File:    src/filter/filter/p11fix_patches/cmac.ml

************************** MIT License HEADER ***********************************)
(********** Pure OCaml CMAC *************************)
(*** WARNING! This is slow as hell, do not use it   *)
(* for real applications! This AES is only here as  *)
(* part of a proof of concept so that no other lib  *)
(* dependency is added to the project. For a real   *)
(* crypto library, please use native libs such as   *)
(* Cryptokit:                                       *)
(*  http://forge.ocamlcore.org/projects/cryptokit/  *)

(* AES algorithm *)
let rijndael_sbox_ = [|
                        0x63; 0x7C; 0x77; 0x7B; 0xF2; 0x6B; 0x6F; 0xC5; 0x30; 0x01; 0x67; 0x2B; 0xFE; 0xD7; 0xAB; 0x76;
                        0xCA; 0x82; 0xC9; 0x7D; 0xFA; 0x59; 0x47; 0xF0; 0xAD; 0xD4; 0xA2; 0xAF; 0x9C; 0xA4; 0x72; 0xC0;
                        0xB7; 0xFD; 0x93; 0x26; 0x36; 0x3F; 0xF7; 0xCC; 0x34; 0xA5; 0xE5; 0xF1; 0x71; 0xD8; 0x31; 0x15;
                        0x04; 0xC7; 0x23; 0xC3; 0x18; 0x96; 0x05; 0x9A; 0x07; 0x12; 0x80; 0xE2; 0xEB; 0x27; 0xB2; 0x75;
                        0x09; 0x83; 0x2C; 0x1A; 0x1B; 0x6E; 0x5A; 0xA0; 0x52; 0x3B; 0xD6; 0xB3; 0x29; 0xE3; 0x2F; 0x84;
                        0x53; 0xD1; 0x00; 0xED; 0x20; 0xFC; 0xB1; 0x5B; 0x6A; 0xCB; 0xBE; 0x39; 0x4A; 0x4C; 0x58; 0xCF;
                        0xD0; 0xEF; 0xAA; 0xFB; 0x43; 0x4D; 0x33; 0x85; 0x45; 0xF9; 0x02; 0x7F; 0x50; 0x3C; 0x9F; 0xA8;
                        0x51; 0xA3; 0x40; 0x8F; 0x92; 0x9D; 0x38; 0xF5; 0xBC; 0xB6; 0xDA; 0x21; 0x10; 0xFF; 0xF3; 0xD2;
                        0xCD; 0x0C; 0x13; 0xEC; 0x5F; 0x97; 0x44; 0x17; 0xC4; 0xA7; 0x7E; 0x3D; 0x64; 0x5D; 0x19; 0x73;
                        0x60; 0x81; 0x4F; 0xDC; 0x22; 0x2A; 0x90; 0x88; 0x46; 0xEE; 0xB8; 0x14; 0xDE; 0x5E; 0x0B; 0xDB;
                        0xE0; 0x32; 0x3A; 0x0A; 0x49; 0x06; 0x24; 0x5C; 0xC2; 0xD3; 0xAC; 0x62; 0x91; 0x95; 0xE4; 0x79;
                        0xE7; 0xC8; 0x37; 0x6D; 0x8D; 0xD5; 0x4E; 0xA9; 0x6C; 0x56; 0xF4; 0xEA; 0x65; 0x7A; 0xAE; 0x08;
                        0xBA; 0x78; 0x25; 0x2E; 0x1C; 0xA6; 0xB4; 0xC6; 0xE8; 0xDD; 0x74; 0x1F; 0x4B; 0xBD; 0x8B; 0x8A;
                        0x70; 0x3E; 0xB5; 0x66; 0x48; 0x03; 0xF6; 0x0E; 0x61; 0x35; 0x57; 0xB9; 0x86; 0xC1; 0x1D; 0x9E;
                        0xE1; 0xF8; 0x98; 0x11; 0x69; 0xD9; 0x8E; 0x94; 0x9B; 0x1E; 0x87; 0xE9; 0xCE; 0x55; 0x28; 0xDF;
                        0x8C; 0xA1; 0x89; 0x0D; 0xBF; 0xE6; 0x42; 0x68; 0x41; 0x99; 0x2D; 0x0F; 0xB0; 0x54; 0xBB; 0x16
                     |]
let rijndael_sbox = ref rijndael_sbox_

let do_lookup_table table a = 
  (Char.chr (table.(Char.code a)))

let rijndael_add a b =
  (Char.chr ((Char.code a) lxor (Char.code b)))

let rijndael_mul a b =
  let p_ = 0x0 in
  let p = ref p_ in
  let a_acc_ = (Char.code a) in
  let a_acc = ref a_acc_ in
  let b_acc_ = (Char.code b) in
  let b_acc = ref b_acc_ in
  for i = 0 to 7 do
    let a_ = (!a_acc lsl 1) in
    let b_ = (!b_acc lsr 1) in
    p := (
      if compare (!b_acc land 0x1) 0 <> 0 then
        (!p lxor !a_acc)
      else
        (!p)
    );
    a_acc := (
      if compare (!a_acc land 0x80) 0 <> 0 then
        (a_ lxor 0x1b)
      else
        (a_)
    );
    b_acc :=  b_;
  done;
  (Char.chr (!p land 0xff))

let mixcolumns column =  
  (* a_ = 2*a0 + 3*a1 + a2 + a3 *)
  let a_ = rijndael_mul (Char.chr 0x2) column.(0) in
  let a_ = rijndael_add a_ (rijndael_mul (Char.chr 0x3) column.(1)) in
  let a_ = rijndael_add a_ column.(2) in
  let a_ = rijndael_add a_ column.(3) in
  (* b_ = a0 + 2*a1 + 3*a2 + a3 *)
  let b_ = column.(0) in
  let b_ = rijndael_add b_ (rijndael_mul (Char.chr 0x2) column.(1)) in
  let b_ = rijndael_add b_ (rijndael_mul (Char.chr 0x3) column.(2)) in
  let b_ = rijndael_add b_ column.(3) in
  (* c_ = a0 + 1*a1 + 2*a2 + 3*a3 *)
  let c_ = column.(0) in
  let c_ = rijndael_add c_ column.(1) in
  let c_ = rijndael_add c_ (rijndael_mul (Char.chr 0x2) column.(2)) in
  let c_ = rijndael_add c_ (rijndael_mul (Char.chr 0x3) column.(3)) in
  (* c_ = 3*a0 + 1*a1 + 1*a2 + 2*a3 *)
  let d_ = rijndael_mul (Char.chr 0x3) column.(0) in
  let d_ = rijndael_add d_ column.(1) in
  let d_ = rijndael_add d_ column.(2) in
  let d_ = rijndael_add d_ (rijndael_mul (Char.chr 0x2) column.(3)) in
  ([| a_; b_; c_; d_ |])

(* AES rounds *)
let aes_round state roundkey last =
  let mixcolumns_op = (
    if compare last true = 0 then
      (fun a -> a)
    else
      mixcolumns) in
  let cola = mixcolumns_op [| do_lookup_table !rijndael_sbox state.(0); do_lookup_table !rijndael_sbox state.(5); do_lookup_table !rijndael_sbox state.(10); do_lookup_table !rijndael_sbox state.(15) |] in
  let colb = mixcolumns_op [| do_lookup_table !rijndael_sbox state.(4); do_lookup_table !rijndael_sbox state.(9); do_lookup_table !rijndael_sbox state.(14); do_lookup_table !rijndael_sbox state.(3) |] in
  let colc = mixcolumns_op [| do_lookup_table !rijndael_sbox state.(8); do_lookup_table !rijndael_sbox state.(13); do_lookup_table !rijndael_sbox state.(2); do_lookup_table !rijndael_sbox state.(7) |] in
  let cold = mixcolumns_op [| do_lookup_table !rijndael_sbox state.(12); do_lookup_table !rijndael_sbox state.(1); do_lookup_table !rijndael_sbox state.(6); do_lookup_table !rijndael_sbox state.(11) |] in
  let new_state = Array.concat [cola; colb; colc; cold] in
  let new_state = Array.mapi (fun index elem -> rijndael_add elem roundkey.(index)) new_state in
  (new_state)

(* AES core cipher *)
let aes_core_encrypt input roundkeys = 
  let new_state_ = input in
  let new_state = ref new_state_ in
  (* Key whitening *)
  new_state := Array.mapi (fun index elem -> rijndael_add elem roundkeys.(index)) !new_state;
  (* Get our AES type *)
  let rounds = (match (Array.length roundkeys) with
      176 -> 10
    | 208 -> 12
    | 240 -> 14
    | _ -> let error = Printf.sprintf "AES roundkeys length %d error\n" (Array.length roundkeys) in failwith error
  ) in
  for i = 1 to rounds-1 do
    new_state :=  aes_round !new_state (Array.sub roundkeys (16*i) (16)) false; 
  done;
  new_state := aes_round !new_state (Array.sub roundkeys (16*rounds) (16)) true;
  (!new_state);;


(**********************************************************)
(* AES key schedule *)
let rcon = [| 0x01; 0x02; 0x04;	0x08; 0x10; 0x20; 0x40; 0x80; 0x1b; 0x36; 0x6c; 0xd8; 0xab; 0x4d; 0x9a |]

let subword word = 
  (Array.map (fun w -> do_lookup_table !rijndael_sbox w) word)

let rotword word =
  ([| word.(1); word.(2); word.(3); word.(0) |])

let rcon_xor word i nk = 
  ([| Char.chr (rcon.(i/nk-1) lxor (Char.code word.(0))); word.(1); word.(2); word.(3) |])

let aes_key_schedule key = 
  let roundkeys_ = key in
  let roundkeys = ref roundkeys_ in
  let keylen = Array.length key in
  let nr = (match keylen with
      16 -> 10
    | 24 -> 12
    | 32 -> 14
    | _ -> let error = Printf.sprintf "AES key length %d error\n" (Array.length key) in failwith error 
  ) in 
  let nk = (match keylen with
      16 -> 4
    | 24 -> 6
    | 32 -> 8
    | _ -> let error = Printf.sprintf "AES key length %d error\n" (Array.length key) in failwith error 
  ) in
  let nb = 4 in
  for i = nk to (nb*(nr+1))-1 do
    let curr_word = Array.sub !roundkeys (nb*(i-1)) (nb) in
    let curr_word = (
      if compare (i mod nk) 0 = 0 then 
        (rcon_xor (subword (rotword curr_word)) i nk)
      else
        (curr_word)
    ) in
    let curr_word = (
      if (compare (i mod nk) 4 = 0) && (compare nk 8 = 0) then
        (subword curr_word)
      else
        (curr_word)
    ) in
    let curr_word = Array.mapi (fun j byte -> rijndael_add byte !roundkeys.(nb*(i-nk)+j)) curr_word in
    roundkeys := Array.append !roundkeys curr_word;
  done;
  (!roundkeys)

(**********************************************************)
(* AES encrypt in ECB mode *)
let aes_encrypt_ecb input key = 
  (* Do the key schedule once and for all *)
  let roundkeys = aes_key_schedule key in
  (* Apply the encryption on each block until we reach the end *)
  let i_ = 0 in
  let i = ref i_ in
  let output_ = [||] in
  let output = ref output_ in
  while !i < (Array.length input) do
    let block = (
      try Array.sub input !i 16 
      with
         (* Last block case *)
         Invalid_argument _ -> 
           let padding = Array.make (16 - ((Array.length input) mod 16)) (Char.chr 0x0) in
           let original_block = Array.sub input !i ((Array.length input) mod 16) in
           Array.append original_block padding
        | _ -> let error = Printf.sprintf "Unknown exception during AES ECB\n" in failwith error
    ) in
    output := Array.append !output (aes_core_encrypt block roundkeys);
    i := !i + 16;
  done;
  (!output)

(* AES encrypt in CBC mode *)
let aes_encrypt_cbc input key iv = 
  (* Do the key schedule once and for all *)
  let roundkeys = aes_key_schedule key in
  (* Apply the encryption on each block until we reach the end *)
  let i_ = 0 in
  let i = ref i_ in
  let output_ = [||] in
  let output = ref output_ in
  let prev_block_ = iv in
  let prev_block = ref prev_block_ in
  while !i < (Array.length input) do
    let block = (
      try Array.sub input !i 16 
      with
         (* Last block case *)
         Invalid_argument _ -> 
           let padding = Array.make (16 - ((Array.length input) mod 16)) (Char.chr 0x0) in
           let original_block = Array.sub input !i ((Array.length input) mod 16) in
           Array.append original_block padding
        | _ -> let error = Printf.sprintf "Unknown exception during AES ECB\n" in failwith error
    ) in
    (* CBC chaining *)
    let block = Array.mapi (fun j byte -> rijndael_add byte !prev_block.(j)) block in
    prev_block := aes_core_encrypt block roundkeys;
    output := Array.append !output !prev_block; 
    i := !i + 16;
  done;
  (!output)

(* CMAC padding *)
let cmac_padding block = 
  (* Put a 100... *) 
  let input_len = Array.length block in
  if compare (input_len mod 16) 0 <> 0 then
    let padding_length = 16 - (input_len mod 16) in
    let padding_block = Array.append (Array.make 1 (Char.chr 0x80)) (Array.make (padding_length - 1) (Char.chr 0x0)) in
    (Array.append block padding_block)
  else
    if compare input_len 0 = 0 then
      (Array.append (Array.make 1 (Char.chr 0x80)) (Array.make 15 (Char.chr 0x0)))
    else
      (block)

(* CMAC subkeys generation *)
let array_msb input = 
  ((Char.code input.(0)) land 0x80)

let array_shift_left input = 
  let reversed_input = List.rev (Array.to_list input) in
  let overflow_ = 0 in
  let overflow = ref overflow_ in
  let new_reversed_input = List.map (    
    fun byte -> 
      let new_byte = ((Char.code byte) lsl 1) lxor !overflow in
      if compare ((Char.code byte) land 0x80) 0 = 0 then
        begin
        overflow := 0;
        (Char.chr (new_byte land 0xff))
        end
      else
        begin
        overflow := 1;
        (Char.chr (new_byte land 0xff))
       end
  ) reversed_input in
  let output = Array.of_list (List.rev new_reversed_input) in
  (output) 

let cmac_generate_subkeys aes_roundkeys =
  let rb = Array.append (Array.make 15 (Char.chr 0x0)) [|Char.chr 0x87|] in
  (* Encrypt zeros *)
  let l = aes_core_encrypt (Array.make 16 (Char.chr 0x0)) aes_roundkeys in
  let k1 = (
    let lshifted = array_shift_left l in
    if compare (array_msb l) 0 = 0 then
      (lshifted)
    else
      (Array.mapi (fun j byte -> rijndael_add byte rb.(j)) lshifted) 
  ) in
  let k2 = (
    let k1shifted = array_shift_left k1 in
    if compare (array_msb k1) 0 = 0 then
      (k1shifted)
    else
      (Array.mapi (fun j byte -> rijndael_add byte rb.(j)) k1shifted)
  ) in
  (k1, k2) 

(* AES CMAC *)
let cmac_compute input key =
  (* Keep track of the empty string special case *)
  let old_len = Array.length input in
  (* If we have an empty input, just send a full padded block to the algorithm *)
  let input = (
    (* Special case of the empty string *)
    if compare (Array.length input) 0 = 0 then
      (cmac_padding [||])
    else
      (input)
  ) in
  (* Do the key schedule once and for all *)
  let roundkeys = aes_key_schedule key in
  (* CMAC subkeys *)
  let (k1,k2) = cmac_generate_subkeys roundkeys in
  let len = Array.length input in
  (* CBC chaining *)
  let i_ = 0 in
  let i = ref i_ in
  let prev_block_ = Array.make 16 (Char.chr 0x0) in
  let prev_block = ref prev_block_ in
  while !i < len do
    let block = (
      let the_block = (try Array.sub input !i 16 
        with
          (* Last block in padding case *)
          Invalid_argument _ -> 
            let last_block = Array.sub input !i (len mod 16) in
            let padded_last_block = cmac_padding last_block in
            (Array.mapi (fun j byte -> rijndael_add byte padded_last_block.(j)) k2)
          | _ -> let error = Printf.sprintf "Unknown exception during AES CBC-MAC\n" in failwith error
        ) in
        if compare (!i+16) len = 0 then
          (* Empty string case *)
          if compare old_len 0 = 0 then
            (Array.mapi (fun j byte -> rijndael_add byte the_block.(j)) k2)
          else
            (* Last block in NON padding case *)
            (Array.mapi (fun j byte -> rijndael_add byte the_block.(j)) k1)
        else
          (* Regular blocks *)
          (the_block)
    ) in
    (* CBC chaining *)
    let block = Array.mapi (fun j byte -> rijndael_add byte !prev_block.(j)) block in
    prev_block := aes_core_encrypt block roundkeys;
    i := !i + 16;
  done;
  (!prev_block)

(* Verify a CMAC given a string containing it at the end *)
let cmac_verify input key = 
  let too_small_ = false in
  let too_small = ref too_small_ in
  (* Extract the cmac value at the end of the input *)
  let cmac_to_check = (
    try Array.sub input (Array.length input - 16) 16
      with
         Invalid_argument _ -> too_small := true; ([||])
        | _ -> let error = Printf.sprintf "Unknown exception during AES CBC-MAC verification\n" in failwith error
  ) in
  let input_to_check =  (
    try Array.sub input 0 (Array.length input - 16)
      with
         Invalid_argument _ -> too_small := true; ([||])
        | _ -> let error = Printf.sprintf "Unknown exception during AES CBC-MAC verification\n" in failwith error
  ) in
  if compare !too_small true = 0 then
    (false)
  else
    (* Compute the CMAC on the input *)
    let cmac_value = cmac_compute input_to_check key in
    if compare cmac_value cmac_to_check = 0 then
      (true)
    else
      (false)
