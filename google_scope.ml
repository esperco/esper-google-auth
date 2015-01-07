(*
   Non exhaustive list of scopes defined by Google APIs.
*)
type scope = [
  | `Profile
  | `Email_address
  | `Calendar
  | `Gmail
]

type t = scope list

let parse_scope = function
  | "profile"
  | "https://www.googleapis.com/auth/userinfo.profile" -> Some `Profile

  | "email"
  | "https://www.googleapis.com/auth/userinfo.email" -> Some `Email_address

  | "https://www.googleapis.com/auth/calendar" -> Some `Calendar

  | "https://mail.google.com/" -> Some `Gmail

  | _ -> None


let string_of_scope : scope -> string = function
  | `Profile -> "profile"
  | `Email_address -> "email"
  | `Calendar -> "https://www.googleapis.com/auth/calendar"
  | `Gmail -> "https://mail.google.com/"

let split =
  let rex = lazy (Pcre.regexp " +") in
  fun s ->
    let l = Pcre.split ~rex: (Lazy.force rex) s in
    BatList.filter_map parse_scope l

let concat l =
  String.concat " " (BatList.map string_of_scope l)

let wrap s = split s
let unwrap l = concat l
