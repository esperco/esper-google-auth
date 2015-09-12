(*
   Utilities to deal with HTTP response statuses obtained from
   Google APIs.
*)

open Printf
open Lwt

let map (x : _ Google_auth.retriable) f : _ Google_auth.retriable =
  match x with
  | `Retry_unauthorized -> `Retry_unauthorized
  | `Retry_later -> `Retry_later
  | `Result y -> `Result (f y)

(*
   General-purpose function to convert an HTTP response status
   into either an instruction to retry (Retry_later, Retry_unauthorized)
   or proceed further and produce a result or an exception.
*)
let retriable status continue : _ Google_auth.retriable Lwt.t =
  match status with
  | `Unauthorized (* 401 *) -> return `Retry_unauthorized

  | `Too_many_requests (* 429 *)
  | `Internal_server_error (* 500 *)
  | `Bad_gateway (* 502 *)
  | `Service_unavailable (* 503 *)
  | `Gateway_timeout -> return `Retry_later

  | _ ->
      continue () >>= fun result ->
      return (`Result result)

(*
   Raise an appropriate exception based on the HTTP response status.
   This is meant to be called very last when acceptable statuses
   such as 200 OK or 404 Not Found have already been handled.
*)
let fail call_name status body =
  let error_fun =
    match status with
    | `Bad_request (* 400 *) ->
        Http_exn.internal_error
    | `Forbidden (* 403 *) ->
        (* TODO: inspect response and determine whether it's retriable;
           Gmail API seems to be using code 429 rather than 403
           for their rateLimitExceeded error. *)
        Http_exn.forbidden
    | `Not_found (* 404 *) ->
        Http_exn.not_found
    | _ ->
        Http_exn.internal_error
  in
  let message =
    sprintf "%s: %s: %s"
      call_name
      (Cohttp.Code.string_of_status status)
      body
  in
  error_fun message

(*
   Run an HTTP request to Google, transparently retried
   if one of the retriable response status is obtained.

   This should always be used in place of Google_auth.request unless
   no retries are desired.
*)
let request token_store user_key http_call_with_token =
  Google_auth.request token_store user_key (fun token ->
    http_call_with_token token >>= fun ((status, header, body) as result) ->
    retriable status (fun () ->
      return result
    )
  )
