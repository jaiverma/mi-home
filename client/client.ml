open Core
open Async
open Async_udp

module Mi = Mihome

let my_log s =
    (Writer.write @@ Lazy.force Writer.stdout) s;
    Writer.flushed @@ Lazy.force Writer.stdout

let msg_processor packet =
    let stdout = Lazy.force Writer.stdout in

    Writer.write stdout "[*] Received packet:\n";
    Writer.write stdout
    @@ Mi.dump_packet
    @@ Cstruct.of_string packet;

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
                let stopped = ref false in
                let recvd = Bvar.create () in

                if !stopped then return ()
                else Deferred.all_unit [
                    Deferred.all_unit [
                        my_log "[+] Sending...\n";
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
                                    msg_processor buf;
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
    let packet = Mi.create_packet
        ~unknown:0xffffffffl
        ~id:0xffffffffl
        ~stamp:0xffffffffl
        ~token:"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        ()
    in

    let _to_send = Mi.dump_packet packet in
    (* my_log to_send; *)

    send_recv_one
        ~addr:"10.0.0.6"
        ~port:54321
        @@ Cstruct.to_bytes packet
    |> ignore;

    never_returns @@ Scheduler.go ()
