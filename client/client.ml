open Core
open Async
module Mi = Mihome

let msg_handler ~f r =
  let buf = Bytes.create 1024 in
  Reader.read r buf
  >>| (function
        | `Eof -> raise_s @@ Sexp.of_string "(EOF...)"
        | `Ok n -> String.init ~f:(fun i -> Bytes.get buf i) n)
  >>| fun cmd ->
  match String.strip cmd with
  | "on" -> ignore @@ f Msg.power_on
  | "off" -> ignore @@ f Msg.power_off
  | "get_aqi" -> ignore @@ f Msg.get_aqi
  | "get_temperature" -> ignore @@ f Msg.get_temperature
  | "get_humidity" -> ignore @@ f Msg.get_humidity
  | "get_fan_level" -> ignore @@ f Msg.get_fan_level
  | "get_power" -> ignore @@ f Msg.get_power
  | "get_mode" -> ignore @@ f Msg.get_mode
  | x -> ignore @@ Msg.my_log @@ sprintf "cmd: %s\n" x
;;

let run ~f () =
  let host_and_port =
    Tcp.Server.create
      ~on_handler_error:`Raise
      (Tcp.Where_to_listen.of_port 10001)
      (fun _addr r _w -> msg_handler ~f r)
  in
  ignore host_and_port
;;

let () =
  (* -- flow of turning on device
            1. send `hello` packet (`send_recv_one`)
            2. parse `hello` response to retrieve `stamp` and `id`
            3. create new packet and put in `stamp` and `id` from prev packet
            4. create and encrypt payload with token
            5. calculate MD5 has and put it in `token` field
            6. `send_recv_one`                                            -- *)
  let ip = ref "" in
  let port = ref 0 in
  let config_path =
    match Sys.getenv "MICONF_PATH" with
    | Some f -> f
    | None -> raise_s @@ Sexp.of_string "(MICONF_PATH is not set!)"
  in
  (Util.load_config config_path
  >>| (fun conf ->
        List.iter conf ~f:(fun (k, v) ->
            match k with
            | "token" -> Mi.token := Hex.to_cstruct @@ `Hex v
            | "ip" -> ip := v
            | "port" -> port := int_of_string v
            | _ -> ());
        if Cstruct.is_empty !Mi.token then raise_s @@ Sexp.of_string "(token not set!)";
        if String.is_empty !ip then raise_s @@ Sexp.of_string "(ip not set!)";
        if !port = 0 then raise_s @@ Sexp.of_string "(port not set!)")
  >>> fun _ -> run () ~f:(Msg.send_recv_msg ~addr:!ip ~port:!port));
  never_returns @@ Scheduler.go ()
;;
