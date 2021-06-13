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

let create_packet ~unknown ~id ~stamp ~token ?(payload=Bytes.empty) () =
    let packet =
        Cstruct.of_bigarray
        @@ Bigarray.Array1.create Bigarray.char Bigarray.c_layout sizeof_mihome
    in

    set_mihome_magic packet 0x2131;
    set_mihome_unknown packet @@ Int32.of_int unknown;
    set_mihome_id packet @@ Int32.of_int id;
    set_mihome_stamp packet @@ Int32.of_int stamp;
    set_mihome_token token 0 packet;
    set_mihome_len packet @@ Bytes.length payload + sizeof_mihome;

    Cstruct.append packet @@ Cstruct.of_bytes payload
