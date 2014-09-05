open Log
open Lwt

let client_id =
  "1037853372111-j9jiqqpju3q0ovihj3vnon9fi7nuclvr.apps.googleusercontent.com"
let client_secret = "SRXOeDGlOHiup67sHcluTazd"

(*
   List of permissions requested
*)
let scopes = String.concat " " [
  (*
     Access user's basic profile (name, photo)

     See https://developers.google.com/+/api/oauth#profile

     Google recommends that we use plus.login, which requests scary
     Google+ write permissions so we don't do that. As far as I can see
     we don't need that, it's just Google trying to push us to use
     their Google+ social network.
  *)
  "profile";

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
]

let auth_uri ?login_hint ~request_new_refresh_token state =
  let approval_prompt =
    if request_new_refresh_token then
      (*
        This results in a new refresh_token,
        however the user will be prompted for "offline access"
        even if they already gave their permission for all the scopes
        for the previous token.

        In order to not prompt the user each time they click on the
        "Sign in with Google" button, one must not request a new refresh_token.
      *)
      "force"
    else
      (*
        Prompt the user for missing permissions if any, but don't produce
        a new refresh_token.
      *)
      "auto"
  in
  let login_hint =
    match login_hint with
    | None -> []
    | Some email -> [ "login_hint", [Email.to_string email] ]
  in
  Uri.make
    ~scheme:"https"
    ~host:"accounts.google.com"
    ~path:"/o/oauth2/auth"
    ~query: ([
      "response_type", ["code"];
      "client_id", [client_id];
      "redirect_uri", [App_path.google_oauth_callback_url ()];
      "scope", [scopes];
      "state", [Google_api_j.string_of_state state];
      "access_type", ["offline"];
      "approval_prompt", [approval_prompt];
    ] @ login_hint)
    ()

let oauth_token_uri () =
  Google_api_util.make_uri
    ~host: "accounts.google.com"
    ~path: "/o/oauth2/token"
    ()

let oauth_revoke_uri access_token =
  Google_api_util.make_uri
    ~host: "accounts.google.com"
    ~path: "/o/oauth2/revoke"
    ~query: ["token", [access_token]]
    ()

let oauth_validate_uri token =
  Google_api_util.make_uri
    ~path: "/oauth2/v1/tokeninfo"
    ~query: ["id_token", [token]]
    ()

let form_headers =
  ["Content-Type", "application/x-www-form-urlencoded"]

let auth_header access_token =
  "Authorization", "Bearer " ^ access_token

type token_result =
  | All_tokens of Account_t.google_oauth_token
  | Only_access_token of string
  | Error of string

let oauth_revoke access_token =
  Util_http_client.get (oauth_revoke_uri access_token) >>= function
  | (`OK, _headers, _body) ->
      (* Google returns true even if the token was already revoked *)
      return true
  | (_status, _headers, body) ->
      (* Malformed token etc. *)
      logf `Warning "Google token revocation failed: %s" body;
      return false

(*
  Get a refresh_token (i.e. a permanent access token) in exchange for
  a one-time code posted by Google.
*)
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
    | { Google_api_t.error = Some error } ->
        return (Error error)

    | { Google_api_t.refresh_token = Some refresh_token;
        access_token;
        expires_in } ->
        let expiration = Unix.time () +. BatOption.default 0. expires_in in
        return (All_tokens {Account_t.access_token; refresh_token; expiration})

    | { Google_api_t.refresh_token = None;
        access_token = Some access_token; } ->
        return (Only_access_token access_token)

    | _ ->
        return (Error "missing tokens")

(*
   Get a valid access_token from a refresh_token, fetching and storing
   a new one from Google regardless of the expiration date, which
   is unreliable because of clock issues.

   Possible outcomes:
   - Some: got an access_token
   - None: invalid refresh_token
   - exception: retry later
*)
let refresh tokens =
  logf `Info "Refreshing Google access token";
  let open Account_t in
  let {refresh_token} = tokens in
  let q = ["refresh_token", [refresh_token];
           "client_id",     [client_id];
           "client_secret", [client_secret];
           "grant_type",    ["refresh_token"]] in
  let body = Uri.encoded_of_query q in
  Util_http_client.post ~headers:form_headers ~body (oauth_token_uri ())
  >>= fun (_status, _headers, body) ->
  match Google_api_j.oauth_token_result_of_string body with
  | {Google_api_t.access_token = Some access_token; expires_in} ->
      let expiration = Unix.time () +. BatOption.default 0. expires_in in
      return (Some ({
        Account_t.refresh_token;
        access_token = Some access_token;
        expiration
      }, access_token))

  | {Google_api_t.error = Some "invalid_grant"} ->
      return None

  | {Google_api_t.error = Some errmsg} ->
      failwith ("Unknown error response from Google: " ^ errmsg)
  | _ ->
      failwith "Invalid response from Google"


let get_token_email token =
  (* An extra two hours to the expires_in time because Google gets
     desynchronized from our server... *)
  let grace_period = 60. *. 60. *. 2. in
  Util_http_client.get (oauth_validate_uri token) >>= function
  | (`OK, _headers, body) ->
      (match Google_api_j.token_info_of_string body with
      | {Google_api_t.token_issuer = "accounts.google.com";
         token_email = Some email;
         token_audience; token_expires_in; token_issued_at}
        when token_audience = client_id
          && Unix.time () <= token_issued_at +. token_expires_in +. grace_period ->
          return (Some (Email.of_string email))
      | _ ->
          logf `Warning "token validated, but with wrong info: %s" body;
          return None)
  | (_status, _headers, body) ->
      logf `Warning "token validation failed: %s" body;
      return None
