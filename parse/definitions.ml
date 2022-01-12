[%%cstruct
type ethernet =
  { dst : uint8_t [@len 6]
  ; src : uint8_t [@len 6]
  ; ethertype : uint16_t
  }
[@@big_endian]]

[%%cstruct
type ipv4 =
  { hlen_version : uint8_t
  ; tos : uint8_t
  ; len : uint16_t
  ; id : uint16_t
  ; off : uint16_t
  ; ttl : uint8_t
  ; proto : uint8_t
  ; csum : uint16_t
  ; src : uint8_t [@len 4]
  ; dst : uint8_t [@len 4]
  }
[@@big_endian]]

[%%cstruct
type udpv4 =
  { srouce_port : uint16_t
  ; dest_port : uint16_t
  ; length : uint16_t
  ; checksum : uint16_t
  }
[@@big_endian]]

let get_mac eth =
  eth
  |> Cstruct.to_bytes
  |> Bytes.to_seq
  |> List.of_seq
  |> List.map int_of_char
  |> List.map (Printf.sprintf "%02x")
  |> String.concat ":"
;;

let get_mac_src eth = get_mac @@ get_ethernet_src eth
let get_mac_dst eth = get_mac @@ get_ethernet_dst eth

let get_ip ip =
  ip |> Cstruct.to_string ~len:4 |> Ipaddr.V4.of_octets_exn |> Ipaddr.V4.to_string
;;

let get_ip_src ip = get_ip @@ get_ipv4_src ip
let get_ip_dst ip = get_ip @@ get_ipv4_dst ip
