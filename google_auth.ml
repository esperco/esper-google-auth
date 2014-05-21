open Log
open Lwt

let client_id = "791317799058.apps.googleusercontent.com"
let client_secret = "dJjpTdtAouZq8UNzm1q0csbG"

(*
   List of permissions requested
*)
let scopes = String.concat " " (List.sort String.compare [
  (*
     Sign-in (this scope includes the profile scope)
     https://developers.google.com/+/api/oauth#plus.login
     https://developers.google.com/+/api/oauth#profile
  *)
  "https://www.googleapis.com/auth/plus.login";

  (*
     Let us retrieve the email address used by the user for authentication
     so we can tie it to an Esper account.
     https://developers.google.com/+/api/oauth#email
  *)
  "email";

  (* GMail messages *)
  "https://mail.google.com/";

  (* Addressbook *)
  "https://www.google.com/m8/feeds";

  (* Calendar *)
  "https://www.googleapis.com/auth/calendar";
])

(* email is only a login hint *)
let auth_uri state email =
  Uri.make
    ~scheme:"https"
    ~host:"accounts.google.com"
    ~path:"/o/oauth2/auth"
    ~query:["response_type", ["code"];
            "client_id", [client_id];
            "redirect_uri", [App_path.google_oauth_callback_url ()];
            "scope", [scopes];
            "state", [Google_api_j.string_of_state state];
            "access_type", ["offline"];
            "approval_prompt", ["force"];
           ]
    ()

let oauth_token_uri () =
  Uri.of_string "https://accounts.google.com/o/oauth2/token"

let oauth_revoke_uri access_token =
  Uri.of_string ("https://accounts.google.com/o/oauth2/revoke?token="
                 ^ Uri.pct_encode access_token)

let form_headers =
  ["Content-Type", "application/x-www-form-urlencoded"]

let auth_header access_token =
  "Authorization", "Bearer " ^ access_token

type ('a,'b)result = Good of 'a | Bad of 'b

let oauth_revoke access_token =
  Util_http_client.get (oauth_revoke_uri access_token) >>= function
  | (`OK, _headers, _body) ->
      (* Google returns true even if the token was already revoked *)
      return true
  | (_status, _headers, body) ->
      (* Malformed token etc. *)
      logf `Warning "Google token revocation failed: %s" body;
      return false

let get_token code redirect_uri =
  let q = ["code",          [code];
           "client_id",     [client_id];
           "client_secret", [client_secret];
           "redirect_uri",  [redirect_uri];
           "grant_type",    ["authorization_code"]] in
  let body = Uri.encoded_of_query q in
  Util_http_client.post ~headers:form_headers ~body (oauth_token_uri ())
  >>= fun (_status, _headers, body) ->
  match Google_api_j.oauth_token_result_of_string body with
    | {Google_api_t.error = Some error} ->
      return (Bad error)

    | {Google_api_t.refresh_token = Some refresh_token; error = None;
       access_token; expires_in} ->
      let expiration = Unix.time () +. BatOption.default 0. expires_in in
      return (Good {Account_t.access_token; refresh_token; expiration})

    | {Google_api_t.refresh_token = None; error = None} ->
      return (Bad "no refresh token")

let refresh token =
  match token with
    | {Account_t.access_token = Some _ as access_token; expiration}
        when Unix.time () +. 600. <= expiration ->
        return (None, access_token)
    | {Account_t.refresh_token} ->
        logf `Info "refresh: need to refresh";
        let q = ["refresh_token", [refresh_token];
                 "client_id",     [client_id];
                 "client_secret", [client_secret];
                 "grant_type",    ["refresh_token"]] in
        let body = Uri.encoded_of_query q in
        Util_http_client.post ~headers:form_headers ~body (oauth_token_uri ())
        >>= fun (_status, _headers, body) ->
        match Google_api_j.oauth_token_result_of_string body with
        | {Google_api_t.access_token = Some _ as access_token; expires_in} ->
            let expiration = Unix.time () +. BatOption.default 0. expires_in in
            return (Some {Account_t.refresh_token; access_token; expiration},
                        access_token)
        | _ ->
            return (None, None)
