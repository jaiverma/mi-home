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

let validate_packet packet =
    match get_mihome_magic packet with
    | 0x2131 -> Ok ()
    | _ -> Error "invalid magic"
