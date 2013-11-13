let client_id = "791317799058.apps.googleusercontent.com"
let client_secret = "dJjpTdtAouZq8UNzm1q0csbG"

let (>>=) = Lwt.(>>=)

(* email is only a login hint *)
let auth_uri uid email =
  Uri.make
    ~scheme:"https"
    ~host:"accounts.google.com"
    ~path:"/o/oauth2/auth"
    ~query:["response_type", ["code"];
            "client_id", [client_id];
            "redirect_uri", [App_path.google_oauth_callback_url ()];
            "scope", ["https://www.googleapis.com/auth/calendar"];
            "state", [Uid.to_string uid];
            "access_type", ["offline"];
            "approval_prompt", ["force"];
            "login_hint", [Email.to_string email]]
    ()

let oauth_token_uri () =
  Uri.of_string "https://accounts.google.com/o/oauth2/token"

let form_headers =
  ["Content-Type", "application/x-www-form-urlencoded"]

let auth_header access_token =
  "Authorization", "Bearer " ^ access_token

type ('a,'b)result = Good of 'a | Bad of 'b

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
      Lwt.return (Bad error)

    | {Google_api_t.refresh_token = Some refresh_token; error = None;
       access_token; expires_in} ->
      let expiration = Unix.time () +. BatOption.default 0. expires_in in
      Lwt.return (Good {Account_t.access_token; refresh_token; expiration})

    | {Google_api_t.refresh_token = None; error = None} ->
      Lwt.return (Bad "no refresh token")

let refresh token =
  match token with
    | {Account_t.access_token = Some _ as access_token; expiration}
        when Unix.time () +. 600. <= expiration ->
      Lwt.return (None, access_token)
    | {Account_t.refresh_token} ->
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
          Lwt.return (Some {Account_t.refresh_token; access_token; expiration},
                      access_token)
        | _ ->
          Lwt.return (None, None)
