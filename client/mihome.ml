open Core

let token = ref Cstruct.empty

[%%cstruct
type mihome =
  { magic : uint16_t
  ; len : uint16_t
  ; unknown : uint32_t
  ; id : uint32_t
  ; stamp : uint32_t
  ; token : uint8_t [@len 16]
  }
[@@big_endian]]

let create_packet
    ~id
    ~stamp
    ?(token = String.init 16 ~f:(fun _ -> '\xff'))
    ?(unknown = 0l)
    ?(payload = Bytes.of_string "")
    ()
  =
  let packet =
    Cstruct.of_bigarray
    @@ Bigarray.Array1.create Bigarray.char Bigarray.c_layout sizeof_mihome
  in
  set_mihome_magic packet 0x2131;
  set_mihome_unknown packet unknown;
  set_mihome_id packet id;
  set_mihome_stamp packet stamp;
  set_mihome_token token 0 packet;
  set_mihome_len packet @@ (Bytes.length payload + sizeof_mihome);
  let packet = Cstruct.append packet @@ Cstruct.of_bytes payload in
  (* if payload is zero, then use the token that was supplied as argument
       otherwise, append the payload and calculate MD5 hash. then use this
       hash as the token *)
  if Bytes.length payload > 0
  then (
    let open Nocrypto.Hash in
    let hash = MD5.digest packet in
    set_mihome_token (Cstruct.to_string hash) 0 packet;
    packet)
  else packet
;;

let encrypt_payload payload ~token =
  let open Nocrypto.Cipher_block in
  let open Nocrypto.Hash in
  let key = MD5.digest token in
  let iv = MD5.digest @@ Cstruct.append key token in
  let ciphertext =
    AES.CBC.encrypt ~key:(AES.CBC.of_secret key) ~iv @@ Util.pad_pkcs7 payload
  in
  ciphertext
;;

let decrypt_payload payload token =
  let open Nocrypto.Cipher_block in
  let open Nocrypto.Hash in
  let key = token |> MD5.digest in
  let iv = Cstruct.append key token |> MD5.digest in
  let plain =
    AES.CBC.decrypt ~key:(AES.CBC.of_secret key) ~iv payload |> Util.unpad_pkcs7
  in
  plain
;;

let dump_packet packet token =
  let ret = "" in
  let ret = ret ^ sprintf "\tmagic   : 0x%04x\n" @@ get_mihome_magic packet in
  let ret = ret ^ sprintf "\tlen     : 0x%04x\n" @@ get_mihome_len packet in
  let ret =
    ret
    ^ sprintf "\tunknown : 0x%08x\n"
    @@ ((Int32.to_int_exn @@ get_mihome_unknown packet) land 0xffffffff)
  in
  let ret =
    ret
    ^ sprintf "\tid      : 0x%08x\n"
    @@ ((Int32.to_int_exn @@ get_mihome_id packet) land 0xffffffff)
  in
  let ret =
    ret
    ^ sprintf "\tstamp   : 0x%08x\n"
    @@ ((Int32.to_int_exn @@ get_mihome_stamp packet) land 0xffffffff)
  in
  let token_str =
    Cstruct.to_bytes @@ get_mihome_token packet
    |> Bytes.to_list
    |> List.fold_left ~f:(fun init x -> sprintf "%s%02x" init @@ int_of_char x) ~init:""
  in
  let ret = ret ^ sprintf "\ttoken   : %s\n" token_str in
  let payload = Cstruct.shift packet sizeof_mihome in
  if Cstruct.length payload > 0
  then (
    let ret = ret ^ Cstruct.to_string @@ decrypt_payload payload token in
    let ret = ret ^ "\n" in
    ret)
  else ret
;;
