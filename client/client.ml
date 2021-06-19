open Core
open Async

module Mi = Mihome

let load_config filename =
    Monitor.try_with (fun () ->
    Reader.file_contents filename
    >>| fun str ->
    String.strip str)
    >>= function
    | Ok s -> return s
    | Error _ ->
        eprintf "[-] Failed to read config from file: %s\n" filename;
        exit 0

let () =
    let _packet = Mi.create_packet
        ~unknown:0xffffffffl
        ~id:0xffffffffl
        ~stamp:0xffffffffl
        ~token:"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        ()
    in

    (* -- flow of turning on device
            1. send `hello` packet (`send_recv_one`)
            2. parse `hello` response to retrieve `stamp` and `id`
            3. create new packet and put in `stamp` and `id` from prev packet
            4. create and encrypt payload with token
            5. calculate MD5 has and put it in `token` field
            6. `send_recv_one`                                            -- *)

    Mi.token := Cstruct.of_string
        "\x00\xb2\xa2\x28\x54\x6c\x57\xdf\x33\x6b\xbc\xe4\x44\x39\xe4\xaf";

    let turn_on_packet = Msg.create_msg Msg.power_on () in
    Msg.my_log
    @@ Mi.dump_packet
    @@ turn_on_packet ~id:0x101dbfd4l ~stamp:0x0000433cl
    |> ignore;

    Msg.send_recv_one
        ~addr:"10.0.0.9"
        ~port:54321
        @@ Cstruct.to_bytes @@ turn_on_packet ~id:0x101dbfd4l ~stamp:0x0000433cl
    |> ignore;

    never_returns @@ Scheduler.go ()
