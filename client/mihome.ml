open Core

[%%cstruct
type mihome = {
    magic: uint16_t;
    len: uint16_t;
    unknown: uint32_t;
    id: uint32_t;
    stamp: uint32_t;
    token: uint8_t [@len 16];
} [@@big_endian]
]

let create_packet ~unknown ~id ~stamp ~token ?(payload=Bytes.of_string "") () =
    let packet =
        Cstruct.of_bigarray
        @@ Bigarray.Array1.create Bigarray.char Bigarray.c_layout sizeof_mihome
    in

    set_mihome_magic packet 0x2131;
    set_mihome_unknown packet unknown;
    set_mihome_id packet id;
    set_mihome_stamp packet stamp;
    set_mihome_token token 0 packet;
    set_mihome_len packet @@ Bytes.length payload + sizeof_mihome;

    Cstruct.append packet @@ Cstruct.of_bytes payload

let dump_packet packet =
    let ret = "" in
    let ret = ret ^ sprintf "\tmagic  : 0x%04x\n"
        @@ get_mihome_magic packet in
    let ret = ret ^ sprintf "\tlen    : 0x%04x\n"
        @@ get_mihome_len packet in
    let ret = ret ^ sprintf "\tunknow : 0x%08x\n"
        @@ (Int32.to_int_exn
        @@ get_mihome_unknown packet)
        land 0xffffffff in
    let ret = ret ^ sprintf "\tid     : 0x%08x\n"
        @@ (Int32.to_int_exn
        @@ get_mihome_id packet)
        land 0xffffffff in
    let ret = ret ^ sprintf "\tstamp  : 0x%08x\n"
        @@ (Int32.to_int_exn
        @@ get_mihome_stamp packet)
        land 0xffffffff in
    let token_str =
        Cstruct.to_bytes @@ get_mihome_token packet
        |> Bytes.to_list
        |> List.fold_left ~f:(fun init x ->
            Printf.sprintf "%s%02x" init @@ int_of_char x) ~init:""
    in
    let ret = ret ^ sprintf "\ttoken  : %s\n" token_str in

    ret
