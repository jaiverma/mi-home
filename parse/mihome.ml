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

let mi_mac = "52:ec:50:83:5f:64"
let token_key = ref Cstruct.empty

let validate_packet packet =
  match get_mihome_magic packet with
  | 0x2131 -> Ok ()
  | _ -> Error "invalid magic"
;;

let update_token mac token =
  match Cstruct.is_empty !token_key with
  | true ->
    (match String.compare mac mi_mac with
    | 0 ->
      (match Cstruct.get_byte token 0 with
      | 0xff -> ()
      | _ -> token_key := token)
    | _ -> ())
  | false -> ()
;;

let decrypt_payload payload token =
  let open Nocrypto.Cipher_block in
  let open Nocrypto.Hash in
  let key = token |> MD5.digest in
  let iv = Cstruct.append key token |> MD5.digest in
  let plain =
    AES.CBC.decrypt ~key:(AES.CBC.of_secret key) ~iv payload |> Utils.unpad_pkcs7
  in
  plain
;;

let dump_packet packet =
  Printf.printf "\tmagic  : 0x%04x\n" @@ get_mihome_magic packet;
  Printf.printf "\tlen    : 0x%04x\n" @@ get_mihome_len packet;
  Printf.printf "\tunknow : 0x%08x\n"
  @@ ((Int32.to_int @@ get_mihome_unknown packet) land 0xffffffff);
  Printf.printf "\tid     : 0x%08x\n"
  @@ ((Int32.to_int @@ get_mihome_id packet) land 0xffffffff);
  Printf.printf "\tstamp  : 0x%08x\n"
  @@ ((Int32.to_int @@ get_mihome_stamp packet) land 0xffffffff);
  let token_str =
    Cstruct.to_bytes @@ get_mihome_token packet
    |> Bytes.to_seq
    |> Seq.fold_left (fun init x -> Printf.sprintf "%s%02x" init @@ int_of_char x) ""
  in
  Printf.printf "\ttoken  : %s\n" token_str
;;
