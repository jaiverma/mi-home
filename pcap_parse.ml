module Def = Definitions
module Mi = Mihome

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
        | Some (_hdr, eth) -> (
            let mac_src = Def.get_mac_src eth in
            let mac_dst = Def.get_mac_dst eth in
            let ip = Cstruct.shift eth Def.sizeof_ethernet in
            let ip_src = Def.get_ip_src ip in
            let ip_dst = Def.get_ip_dst ip in
            let udp = Cstruct.shift ip Def.sizeof_ipv4 in
            let mi_data = Cstruct.shift udp Def.sizeof_udpv4 in

            Result.bind (Mi.validate_packet mi_data)
            (fun _ ->
            let mi_len = Mi.get_mihome_len mi_data in
            let token = Mi.get_mihome_token mi_data in
            Mi.update_token mac_src token;

            let payload =
                match mi_len with
                | x when x = Mi.sizeof_mihome -> Cstruct.empty
                | _ -> (
                    let payload = Cstruct.shift mi_data Mi.sizeof_mihome in
                    Mi.decrypt_payload payload !Mi.token_key)
            in

            Printf.printf "src: [%s] [%s] -> dst: [%s] [%s]\n"
                mac_src ip_src mac_dst ip_dst;

            Mi.dump_packet mi_data;

            (match (Cstruct.length payload) with
            | 0 -> ()
            | _ -> Printf.printf "%s\n" @@ Cstruct.to_string payload);

            parse iterator))

        | None -> Error "no packets left"
    in

    parse data_iter

let () =
    ignore @@ read_packets "/tmp/yolo.pcap"
