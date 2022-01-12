open Core
open Async

let pad_pkcs7 payload =
  let pad_length = 16 - (Cstruct.length payload mod 16) in
  let pad =
    String.init pad_length ~f:(fun _ -> char_of_int pad_length) |> Cstruct.of_string
  in
  Cstruct.append payload pad
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
