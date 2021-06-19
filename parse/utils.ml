let unpad_pkcs7 ?(blocksize=16) data =
    match ((Cstruct.length data) mod blocksize) with
    | 0 ->
        let len = Cstruct.length data in
        let last = (len - 1) |> Cstruct.get_byte data in

        if last > len then data
        else (
            Printf.printf "data: %s\n" @@ Cstruct.to_string data;
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

let print_byte_data b =
    b
    |> Bytes.to_seq
    |> List.of_seq
    |> List.map int_of_char
    |> List.map (fun x -> x |> Printf.sprintf "%02x")
    |> String.concat " "
    |> Printf.printf "%s\n"

let dump_to_file ~filename data =
    let oc = open_out filename in
    Printf.fprintf oc "%s" data;
    close_out oc
