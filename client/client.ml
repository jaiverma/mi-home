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

let msg_handler r =
    let buf = Bytes.create 1024 in
    Reader.read r buf

    >>| (function
    | `Eof -> raise_s @@ Sexp.of_string "(EOF...)"
    | `Ok n -> String.init ~f:(fun i -> Bytes.get buf i) n)

    >>| (fun cmd ->
    let send_msg_f = Msg.send_recv_msg ~addr:"10.0.0.2" ~port: 54321 in
    match String.strip cmd with
    | "on" -> ignore @@ send_msg_f Msg.power_on
    | "off" -> ignore @@ send_msg_f Msg.power_off
    | x -> ignore @@ Msg.my_log @@ sprintf "cmd: %s\n" x)

let run () =
    let host_and_port =
        Tcp.Server.create
            ~on_handler_error:`Raise
            (Tcp.Where_to_listen.of_port 10001)
            (fun _addr r _w -> msg_handler r)
    in

    ignore host_and_port

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

    >>> (fun _ ->
    run ());

    never_returns @@ Scheduler.go ()
