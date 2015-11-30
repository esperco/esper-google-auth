(*
   Non exhaustive list of scopes defined by Google APIs.
*)
type scope = [
  | `Profile
  | `Email_address
  | `Calendar
  | `Contacts
  | `Gmail
  | `Drive
      (* Requests *full* access to a user's Google Drive. This is fine for
         internal use (ie docs@esper.com) but too broad for clients. *)
]

type t = scope list

(*
   See https://developers.google.com/+/api/oauth#scopes
   for details on the profile and email scopes.
*)
let parse_scope = function
  | "profile"
      (* View your basic profile info *)
  | "https://www.googleapis.com/auth/userinfo.profile"
      (* synonym for "profile" *)
  | "https://www.googleapis.com/auth/plus.login"
      (* Know your basic profile info and list of people in your circles. *)
    -> Some `Profile

  | "email"
      (* View your email address *)
  | "https://www.googleapis.com/auth/userinfo.email"
      (* synonym for "email" *)
  | "https://www.googleapis.com/auth/plus.profile.emails.read"
      (* get email address + other things *)
    -> Some `Email_address

  | "https://www.googleapis.com/auth/calendar" -> Some `Calendar

  | "https://mail.google.com/" -> Some `Gmail

  | "https://www.googleapis.com/auth/drive" -> Some `Drive

  | "https://www.googleapis.com/auth/contacts.readonly" -> Some `Contacts

  | _ -> None


let string_of_scope : scope -> string = function
  | `Profile -> "profile"
  | `Email_address -> "email"
  | `Calendar -> "https://www.googleapis.com/auth/calendar"
  | `Gmail -> "https://mail.google.com/"
  | `Drive -> "https://www.googleapis.com/auth/drive"
  | `Contacts -> "https://www.googleapis.com/auth/contacts.readonly"

let split =
  let rex = lazy (Pcre.regexp " +") in
  fun s ->
    let l = Pcre.split ~rex: (Lazy.force rex) s in
    BatList.filter_map parse_scope l

let concat l =
  String.concat " " (BatList.map string_of_scope l)

let wrap s = split s
let unwrap l = concat l
