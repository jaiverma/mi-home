open Core
open Async

let pad_pkcs7 payload =
  let pad_length = 16 - (Cstruct.length payload mod 16) in
  let pad =
    String.init pad_length ~f:(fun _ -> char_of_int pad_length) |> Cstruct.of_string
  in
  Cstruct.append payload pad
;;

let unpad_pkcs7 ?(blocksize = 16) data =
  match Cstruct.length data mod blocksize with
  | 0 ->
    let len = Cstruct.length data in
    let last = len - 1 |> Cstruct.get_byte data in
    if last > len
    then data
    else (
      let pad =
        Cstruct.sub data (len - last) last
        |> Cstruct.filter (fun c -> int_of_char c = last)
      in
      if Cstruct.length pad = last then Cstruct.sub data 0 (len - last) else data)
  | _ -> data
;;

let load_config filename =
  Monitor.try_with (fun () ->
      Reader.file_contents filename
      >>| fun str ->
      String.split_on_chars ~on:[ '\n' ] str
      |> List.map ~f:(String.split_on_chars ~on:[ ':' ])
      |> List.map ~f:(List.map ~f:String.strip)
      |> List.filter ~f:(fun l -> List.length l = 2)
      |> List.map ~f:(function
             | [ k; v ] -> k, v
             | _ -> failwith "we'll never reach here"))
  >>| function
  | Ok config -> config
  | Error _ -> raise_s @@ Sexp.of_string "(Failed to read config)"
;;
