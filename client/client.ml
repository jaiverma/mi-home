open Core
open Async
open Async_udp

module Mi = Mihome

let my_log s =
    (Writer.write @@ Lazy.force Writer.stdout) s;
    ignore @@ Writer.flushed @@ Lazy.force Writer.stdout

let send_recv_data buf _r w =
    Writer.write_bytes w buf;
    ignore @@ Writer.flushed w

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
                let stopped = ref false in
                let recvd = Bvar.create () in

                if !stopped then return ()
                else Deferred.all_unit [
                    Deferred.all_unit [
                        send_fn
                            (Socket.fd sock)
                            (Iobuf.of_bytes payload)
                            addr;
                        Bvar.wait recvd
                    ];

                    Monitor.try_with
                        ~run:`Schedule
                        ~rest:`Log
                        (fun () ->
                            recvfrom_loop
                                (Socket.fd sock)
                                (fun b _ ->
                                    let buf = Iobuf.to_string b in
                                    my_log buf;
                                    Bvar.broadcast recvd ();
                                    stopped := true;

                                    ignore
                                    @@ Fd.close
                                    @@ Socket.fd sock))
                    >>| function
                    | Ok (Closed | Stopped) -> ()
                    | Error e -> raise e
                ])

let () =
    let _packet = Mi.create_packet
        ~unknown:0xffffffff
        ~id:0xffffffff
        ~stamp:0xffffffff
        ~token:"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    in

    send_recv_one
        ~addr:"127.0.0.1"
        ~port:54321
        @@ Bytes.of_string "hello world\n"
    |> ignore;

    never_returns @@ Scheduler.go ()
