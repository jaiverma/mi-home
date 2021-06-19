open Core
open Async

module Mi = Mihome

let load_config filename =
    Monitor.try_with (fun () ->
    Reader.file_contents filename
    >>| fun str ->
    String.strip str)
    >>| function
    | Ok s -> Hex.to_cstruct @@ `Hex s
    | Error _ -> raise_s @@ Sexp.of_string "(Failed to read config)"

let () =
    (* -- flow of turning on device
            1. send `hello` packet (`send_recv_one`)
            2. parse `hello` response to retrieve `stamp` and `id`
            3. create new packet and put in `stamp` and `id` from prev packet
            4. create and encrypt payload with token
            5. calculate MD5 has and put it in `token` field
            6. `send_recv_one`                                            -- *)

    let token_path =
        match Sys.getenv "MITOKEN_PATH" with
        | Some f -> f
        | None -> raise_s @@ Sexp.of_string "(MITOKEN_PATH is not set!)"
    in

    load_config token_path
    >>| (fun token ->
    Mi.token := token)

    >>= (fun _ ->
    Msg.send_recv_msg
        ~addr:"10.0.0.4"
        ~port:54321
        Msg.power_off)

    >>> (fun _ -> shutdown 0);

    never_returns @@ Scheduler.go ()
