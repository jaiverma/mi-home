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

let run ~addr ~port data =
    let sock = bind_any () in
    Monitor.protect
        ~run:`Schedule
        ~finally:(fun () -> Fd.close @@ Socket.fd sock)
        (fun () ->
            let `Inet (_host, _port) = Unix.Socket.getsockname sock in
            let addr = Socket.Address.Inet.create ~port @@ Unix.Inet_addr.of_string addr in
            let send_fn = Or_error.ok_exn @@ sendto () in
            send_fn (Socket.fd sock) (Iobuf.of_bytes data) addr
            >>= (fun _ ->
            recvfrom_loop (Socket.fd sock) (fun b _ -> Iobuf.to_string b |> my_log))
            >>| (fun res ->
            match res with
            | Closed -> my_log "socket closed!\n"
            | _ -> my_log "something else happend\n"
            ))
            (* let ret = sendto (Socket.fd sock) (Iobuf.of_string "hello world\n") addr in
            match ret with
            | Ok
            | Error -> ()) *)


let () =
    let _packet = Mi.create_packet
        ~unknown:0xffffffff
        ~id:0xffffffff
        ~stamp:0xffffffff
        ~token:"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    in

    ignore @@ run ~addr:"127.0.0.1" ~port:54321
        @@ Bytes.of_string "hello world\n";

    never_returns @@ Scheduler.go ()
