open Core

let pad_pkcs7 payload =
    let pad_length = 16 - (Cstruct.length payload mod 16) in
    let pad =
        String.init pad_length ~f:(fun _ -> char_of_int pad_length)
        |> Cstruct.of_string
    in

    Cstruct.append payload pad
