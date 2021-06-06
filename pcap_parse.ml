[%%cstruct
type ethernet = {
    dst: uint8_t [@len 6];
    src: uint8_t [@len 6];
    ethertype: uint16_t;
  } [@@big_endian]
]

[%%cstruct
type ipv4 = {
    hlen_version: uint8_t;
    tos: uint8_t;
    len: uint16_t;
    id: uint16_t;
    off: uint16_t;
    ttl: uint8_t;
    proto: uint8_t;
    csum: uint16_t;
    src: uint8_t [@len 4];
    dst: uint8_t [@len 4];
  } [@@big_endian]
]

[%%cstruct
type udpv4 = {
    srouce_port: uint16_t;
    dest_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
  } [@@big_endian]
]

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

let glob_token = "\x18\x6d\xaf\x33\x67\xcc\x57\x3f\x3f\x6a\x7e\x09\xfb\x8e\x0c\xf4"
    |> Cstruct.of_string

let unpad_pkcs7 ?(blocksize=16) data =
    match ((Cstruct.length data) mod blocksize) with
    | 0 ->
        let len = Cstruct.length data in
        let last = (len - 1) |> Cstruct.get_byte data in

        if last > len then data
        else (
            let pad =
                Cstruct.sub data (len - last) last
                |> Cstruct.filter (fun c -> int_of_char c = last)
            in
            if (Cstruct.length pad) = last then
                Cstruct.sub data 0 (len - last)
            else
                data
        )
    | _ -> data

let decrypt_wrapper ?(blocksize=16) ~data ~token () =
    let open Nocrypto.Cipher_block in
    let open Nocrypto.Hash in

    let aes_key = MD5.digest token in
    let iv =
        Cstruct.append aes_key token
        |> MD5.digest
    in
    let key = AES.CBC.of_secret aes_key in

    (* all args of type Cstruct.t *)
    let rec decrypt_block ~iv payload acc =
        match (Cstruct.is_empty payload) with
        | true -> acc
        | false ->
            let block, rem = Cstruct.split payload blocksize in
            let plain =
                AES.CBC.decrypt ~key ~iv block
                |> unpad_pkcs7
            in
            decrypt_block ~iv:block rem (Cstruct.append acc plain)
    in

    decrypt_block ~iv data Cstruct.empty

let print_byte_data b =
    b
    |> Bytes.to_seq
    |> List.of_seq
    |> List.map (fun x -> int_of_char x)
    |> List.map (fun x -> x |> Printf.sprintf "%02x")
    |> String.concat " "
    |> Printf.printf "%s\n"

let open_file filename =
    let fd = Unix.openfile filename [O_RDONLY] 0 in
    Mmap.V1.map_file fd Bigarray.char Bigarray.c_layout false [|-1|]
    |> Bigarray.array1_of_genarray
    |> Cstruct.of_bigarray

let read_header filename =
    let buf = open_file filename in
    match Pcap.detect buf with
    | Some h -> h, buf
    | None ->
        filename
        |> Printf.sprintf "failed to parse pcap header for file: %s"
        |> failwith

let load_pcap ~(buf: Cstruct.t) =
    let header, body = Cstruct.split buf Pcap.sizeof_pcap_header in
    match Pcap.detect header with
    | Some h -> Pcap.packets h body
    | None -> failwith "failed to parse pcap header"

let read_packets filename =
    let data_iter =
        open_file filename
        |> (fun b -> load_pcap ~buf:b)
    in

    let rec parse iterator =
        match (iterator ()) with
        | Some (hdr, eth) ->
            hdr |> Pcap.LE.get_pcap_packet_incl_len |> Int32.to_string |> Printf.printf "sz: %s\n";

            let ip = Cstruct.shift eth sizeof_ethernet in
            let ip_src = ip |> get_ipv4_src in
            let ip_dst = ip |> get_ipv4_dst in

            ip_src
            |> Cstruct.to_string ~len:4
            |> Ipaddr.V4.of_octets_exn
            |> Ipaddr.V4.to_string
            |> Printf.printf "ip src: %s\n";

            ip_dst
            |> Cstruct.to_string ~len:4
            |> Ipaddr.V4.of_octets_exn
            |> Ipaddr.V4.to_string
            |> Printf.printf "ip src: %s\n";

            let udp = Cstruct.shift ip sizeof_ipv4 in

            let mi_data = Cstruct.shift udp sizeof_udpv4 in
            let _mi_magic = match mi_data |> get_mihome_magic with
            | 0x2131 as x -> x
            | _ -> failwith "magic mismatch"
            in

            let mi_len = mi_data |> get_mihome_len in
            Printf.printf "[+] packet len: %d\n" mi_len;
            Printf.printf "\t[!] payload len: %d\n" (mi_len - sizeof_mihome);

            let token = mi_data |> get_mihome_token
            in
            token |> Cstruct.to_bytes ~len:16 |> print_byte_data;
            token |> Cstruct.length |> Printf.printf "token size: %d\n";
            Printf.printf "----------------\n";

            if mi_len = sizeof_mihome then
                Printf.printf "no extra data\n"
            else (
                Printf.printf "extra data present\n";
                let payload = Cstruct.shift mi_data sizeof_mihome in
                (* let open Nocrypto.Cipher_block in
                let open Nocrypto.Hash in
                let key = glob_token |> MD5.digest in
                let iv =
                    let a = key |> MD5.digest in
                    Cstruct.append a token
                    |> MD5.digest
                in
                let plain =
                    AES.CBC.decrypt
                        ~key:(AES.CBC.of_secret key)
                        ~iv
                        payload
                    |> unpad_pkcs7
                in *)

                let plain = decrypt_wrapper ~data:payload ~token:glob_token () in

                Cstruct.to_string plain |> Printf.printf "%s\n"
            );

            parse iterator

        | None -> Printf.printf "no packets left!\n"

    in
    parse data_iter

let _ =
    read_packets "/tmp/yolo.pcap"
