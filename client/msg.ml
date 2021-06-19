open Core
open Async
open Async_udp

module Mi = Mihome

let power_on =
    `Assoc [
        ("id", `Int 1);
        ("method", `String "set_properties");
        ("params", `List [
                `Assoc [
                    ("did", `String "power");
                    ("siid", `Int 2);
                    ("piid", `Int 2);
                    ("value", `Bool true);
                ]
            ]
        )
    ]

let power_off =
    `Assoc [
        ("id", `Int 1);
        ("method", `String "set_properties");
        ("params", `List [
                `Assoc [
                    ("did", `String "power");
                    ("siid", `Int 2);
                    ("piid", `Int 2);
                    ("value", `Bool false);
                ]
            ]
        )
    ]

let create_msg msg ~id ~stamp () =
    let tmp = "{\"id\": 1, \"method\": \"set_properties\", \"params\": [{\"did\": \"power\", \"siid\": 2, \"piid\": 2, \"value\": true}]}" in

    let p =
        tmp
        |> Cstruct.of_string
        |> (fun x -> Cstruct.append x @@ Cstruct.of_string "\x00")
        |> Util.pad_pkcs7
    in

    Out_channel.with_file "/tmp/test.txt" ~f:(fun chan ->
        Out_channel.output_string chan @@ Cstruct.to_string p);

    let payload =
        Yojson.Safe.to_string msg
        |> Cstruct.of_string
        |> (fun x -> Cstruct.append x @@ Cstruct.of_string "\x00")
        |> Mi.encrypt_payload ~token:(!Mi.token)
        |> Cstruct.to_bytes
    in

    Mi.create_packet
        ~id
        ~stamp
        ~payload
        ~token:(Cstruct.to_string !Mi.token)
        ()

let my_log s =
    (Writer.write @@ Lazy.force Writer.stdout) s;
    Writer.flushed @@ Lazy.force Writer.stdout

let msg_processor packet out =
    let stdout = Lazy.force Writer.stdout in

    Writer.write stdout "[*] Received packet:\n";

    Monitor.try_with (fun () ->
        return
        @@ Mi.dump_packet
        @@ Cstruct.of_string packet)

    >>| (function
    | Ok p -> p
    | Error _ -> "[-] failed to parse packet")

    >>> fun p ->
    Writer.write stdout p;

    ignore
    @@ Writer.flushed
    @@ Lazy.force Writer.stdout

let manage_socks ~addr ~port f =
    let sock = bind_any () in
    Monitor.protect
        ~run:`Schedule
        ~finally:(fun () -> Fd.close @@ Socket.fd sock)
        (fun () ->
            let `Inet (_host, _port) = Unix.Socket.getsockname sock in
            let addr =
                Socket.Address.Inet.create ~port
                @@ Unix.Inet_addr.of_string addr
            in
            f ~sock ~addr)

let send_recv_one ~addr ~port payload =
    match sendto () with
    | Error _ -> return ()
    | Ok send_fn ->
        manage_socks
            ~addr
            ~port
            (fun ~sock ~addr ->
                my_log "[+] Sending...\n"

                >>= fun _ ->
                send_fn
                    (Socket.fd sock)
                    (Iobuf.of_bytes payload)
                    addr

                >>= fun _ ->
                Monitor.try_with
                    ~run:`Schedule
                    ~rest:`Log
                    (fun () ->
                        recvfrom_loop
                            (Socket.fd sock)
                            (fun b _ ->
                                let buf = Iobuf.to_string b in
                                msg_processor buf;

                                ignore
                                @@ Fd.close
                                @@ Socket.fd sock))

                >>| function
                | Ok (Closed | Stopped) -> ()
                | Error e -> raise e)

let send_recv_packet _packet = ()
    
