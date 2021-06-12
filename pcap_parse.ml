module Def = Definitions
module Mi = Mihome

let glob_token = "\x18\x6d\xaf\x33\x67\xcc\x57\x3f\x3f\x6a\x7e\x09\xfb\x8e\x0c\xf4"
    |> Cstruct.of_string

type direction = INCOMING | OUTGOING

let mi_mac = "52:ec:50:83:5f:64"

let token_key = ref Cstruct.empty

let open_file filename =
    let fd = Unix.openfile filename [O_RDONLY] 0 in
    Mmap.V1.map_file fd Bigarray.char Bigarray.c_layout false [|-1|]
    |> Bigarray.array1_of_genarray
    |> Cstruct.of_bigarray

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
        | Some (_hdr, eth) ->
            let mac_src = Def.get_mac_src eth in
            let mac_dst = Def.get_mac_dst eth in
            let ip = Cstruct.shift eth Def.sizeof_ethernet in
            let ip_src = Def.get_ip_src ip in
            let ip_dst = Def.get_ip_dst ip in
            let udp = Cstruct.shift ip Def.sizeof_ipv4 in
            let mi_data = Cstruct.shift udp Def.sizeof_udpv4 in

            Printf.printf "mac src: %s\n" mac_src;
            Printf.printf "mac dst: %s\n" mac_dst;
            Printf.printf "ip src: %s\n" ip_src;
            Printf.printf "ip dst: %s\n" ip_dst;

            Result.bind (Mi.validate_packet mi_data)
            (fun _ ->
            let mi_len = Mi.get_mihome_len mi_data in
            Printf.printf "[+] packet len: %d\n" mi_len;
            Printf.printf "\t[!] payload len: %d\n" (mi_len - Mi.sizeof_mihome);

            let token = mi_data |> Mi.get_mihome_token
            in
            token |> Cstruct.to_bytes ~len:16 |> Utils.print_byte_data;
            Printf.printf "----------------\n";

            (match (Cstruct.is_empty !token_key) with
            | true -> (
                match (String.compare mac_src mi_mac) with
                | 0 -> (
                    match (Cstruct.get_byte token 0) with
                    | 0xff -> ()
                    | _ -> token_key := token)
                | _ -> ())
            | false -> ());

            if mi_len = Mi.sizeof_mihome then
                Printf.printf "no extra data\n"
            else (
                Printf.printf "extra data present\n";
                let open Nocrypto.Cipher_block in
                let open Nocrypto.Hash in

                let payload = Cstruct.shift mi_data Mi.sizeof_mihome in
                let key = !token_key |> MD5.digest in
                let iv =
                    Cstruct.append key !token_key
                    |> MD5.digest
                in
                let plain =
                    AES.CBC.decrypt
                        ~key:(AES.CBC.of_secret key)
                        ~iv
                        payload
                    |> Utils.unpad_pkcs7
                in

                Cstruct.to_string plain |> Printf.printf "%s\n"
            );
            parse iterator)

        | None -> Error "no packets left"
    in
    parse data_iter

let _ =
    read_packets "/tmp/yolo.pcap"
