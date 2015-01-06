type t = string list

let split =
  let rex = lazy (Pcre.regexp " +") in
  fun s -> Pcre.split ~rex: (Lazy.force rex) s

let concat l = String.concat " " l

let wrap s = split s
let unwrap l = concat l
