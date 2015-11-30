open Log
open Lwt

let client_id =
  "1037853372111-j9jiqqpju3q0ovihj3vnon9fi7nuclvr.apps.googleusercontent.com"
let client_secret = "SRXOeDGlOHiup67sHcluTazd"

(*
   Minimum list of permissions requested upfront for anyone signing in
   with Google.
*)
let minimum_scopes = [
  (*
     Access user's basic profile (name, photo)

     See https://developers.google.com/+/api/oauth#profile

     Google recommends that we use plus.login, which requests scary
     Google+ write permissions so we don't do that. As far as I can see
     we don't need that, it's just Google trying to push us to use
     their Google+ social network.
  *)
  `Profile;

  (*
     Let us retrieve the email address used by the user for authentication
     so we can tie it to an Esper account.
     https://developers.google.com/+/api/oauth#email
  *)
  `Email_address;

  (*
     Calendar access.

     Assistant: required

     Executive: required, should be made optional.
     This is used only to make it easier for the executive
     to delegate calendars to the assistant.
     We should request this permission optionally where it is needed
     in the setup flow.
  *)
  `Calendar;

  `Contacts;
]

let minimum_executive_scopes = minimum_scopes

let minimum_assistant_scopes = minimum_scopes @ [
  (* GMail messages *)
  `Gmail;
]

(* Return value used by API calls that my fail the first time
   and should be retried after fixing something.

   In the case of Google APIs, we try a request using the saved access token
   and if it fails the first time (`Retry), we request a fresh
   access token and retry.

   This type is equivalent to the option type, but its intent is clearer.
*)
type 'a retriable = [
  | `Result of 'a
      (* Final result *)
  | `Retry_unauthorized
      (* Invalid access token, need to obtain a new token before retrying *)
  | `Retry_later
      (* Retry later with exponential backoff *)
]

let auth_uri ?login_hint ~request_new_refresh_token ~scopes state =
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
      "scope", [Google_scope.concat scopes];
      "state", [Google_api_j.string_of_state state];
      "access_type", ["offline"];
      "approval_prompt", [approval_prompt];
      "include_granted_scopes", ["true"];
    ] @ login_hint)
    ()

let oauth_token_uri () =
  Google_api_util.make_uri
    ~host: "accounts.google.com"
    "/o/oauth2/token"

let oauth_revoke_uri access_token =
  Google_api_util.make_uri
    ~host: "accounts.google.com"
    ~query: ["token", [access_token]]
    "/o/oauth2/revoke"

let oauth_id_token_info_uri token =
  Google_api_util.make_uri
    ~query: ["id_token", [token]]
    "/oauth2/v1/tokeninfo"

let oauth_access_token_info_uri token =
  Google_api_util.make_uri
    ~query: ["access_token", [token]]
    "/oauth2/v1/tokeninfo"

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
let refresh (refresh_token, opt_access_token) =
  logf `Info "Refreshing Google access token";
  let open Account_t in
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
      return (Some (
        (refresh_token, Some (access_token, expiration)),
        access_token
      ))

  | {Google_api_t.error = Some "invalid_grant"} ->
      return None

  | {Google_api_t.error = Some errmsg} ->
      failwith ("Unknown error response from Google: " ^ errmsg)
  | _ ->
      failwith "Invalid response from Google"

let get_access_token_info access_token =
  Util_http_client.get (oauth_access_token_info_uri access_token) >>= function
  | (`OK, _headers, body) ->
      return (Some (Google_api_j.access_token_info_of_string body))
  | (_status, _headers, body) ->
      logf `Warning "Access token validation failed: %s" body;
      return None

let get_id_token_info id_token =
  Util_http_client.get (oauth_id_token_info_uri id_token) >>= function
  | (`OK, _headers, body) ->
      return (Some (Google_api_j.id_token_info_of_string body))
  | (_status, _headers, body) ->
      logf `Warning "ID token validation failed: %s" body;
      return None

let get_id_token_email token =
  (* An extra two hours to the expires_in time because Google gets
     desynchronized from our server... *)
  let grace_period = 60. *. 60. *. 2. in
  get_id_token_info token >>= function
  | Some { Google_api_t.id_token_issuer = "accounts.google.com";
           id_token_email = Some email;
           id_token_audience; id_token_expires_in; id_token_issued_at}
    when id_token_audience = client_id
      && Unix.time () <=
         id_token_issued_at +. id_token_expires_in +. grace_period ->
      return (Some email)
  | None ->
      return None
  | Some x ->
      logf `Warning "token validated, but with wrong info: %s"
        (Google_api_j.string_of_id_token_info x);
      return None


let access_valid tokens =
  match tokens with
  | refresh_token, Some (access_token, expiration) ->
      Unix.time () < expiration -. 60.
  | _ ->
      false

(*
   (refresh_token, Some (access_token, access_token_expiration))
*)
type google_oauth_tokens = string * (string * float) option

(*
   Abstract definition of the storage functions required for OAuth.
   The storage key 'k is associated with at most one Google account.
*)
type 'k token_store = {
  string_of_key: 'k -> string;
    (* for logging *)
  username: 'k -> string option Lwt.t;
    (* Google email address *)
  get: 'k -> google_oauth_tokens option Lwt.t;
  put: 'k -> google_oauth_tokens -> unit Lwt.t;
  remove: 'k -> google_oauth_tokens option Lwt.t;
}

let get_access_token (ts : _ token_store) ~refresh:refresh_it key =
  ts.get key >>= function
  | Some (refresh_token, Some (access_token, t) as tokens)
      when not refresh_it && access_valid tokens ->
      (* return access_token without checking its validity, which
         requires an API call. *)
      return (Some access_token)

  | Some tokens ->
      (refresh tokens >>= function
       | Some (tokens, access_token) ->
           ts.put key tokens >>= fun () ->
           return (Some access_token)
       | None ->
           (* invalid refresh_token needs to be removed *)
           logf `Warning "refresh_token became invalid, removing it";
           ts.remove key >>= function
           | None -> return None
           | Some (refresh_token, _) ->
               oauth_revoke refresh_token >>= fun _success ->
               return None
      )
  | None ->
      return None

(*
   Make a request requiring a Google access token.
   If the stored access token turns out to be invalid,
   the call is retried after obtaining a fresh access token from Google.

   This also incorporate retries with exponential backoff.
*)
let rec request
    (ts : _ token_store)
    ?(max_attempts = 6)
    ?(backoff_sleep = 1.)
    key
    (request_with_token : string -> 'a retriable Lwt.t)
  : 'a Lwt.t =

  if max_attempts <= 0 then
    invalid_arg "Google_auth.request: max_attempts";

  if not (backoff_sleep >= 0.) then
    invalid_arg "Google_auth.request: initial_backoff_sleep";

  let run_request token =
    Cloudwatch.time "google.api.any.latency" (fun () ->
      request_with_token token
    )
  in

  get_access_token ts ~refresh:false key >>= function
  | None ->
      Http_exn.unauthorized
        ("Missing OAuth token for " ^ ts.string_of_key key)
  | Some token ->
      run_request token >>= fun x ->
      match x with
      | `Retry_unauthorized when max_attempts > 1 ->
          (get_access_token ts ~refresh:true key >>= function
           | None ->
               failwith
                 ("Cannot authenticate with fresh access_token"
                  ^ ts.string_of_key key)
           | Some _access_token ->
               request ts ~max_attempts:(max_attempts - 1) ~backoff_sleep
                 key request_with_token
          )
      | `Retry_later when max_attempts > 1 ->
          Lwt_unix.sleep backoff_sleep >>= fun () ->
          request ts
            ~max_attempts: (max_attempts - 1)
            ~backoff_sleep: (backoff_sleep *. 2.)
            key request_with_token

      | `Retry_unauthorized | `Retry_later -> (* giving up *)
          Http_exn.service_unavailable "Google service is down"

      | `Result result ->
          return result
