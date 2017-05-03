(* nslcd.conf module for Augeas          *)

module Nslcd =
autoload xfm


(* Define useful primitives *)
let eol = del /[ ]*\n/ "\n"
let empty = Util.empty
let spc = del /[ \t]+/ " "

(* Main lens components *)
let key_name = /[^ #\n\t\/][^ #\n\t\/]+/
let entry_single_value =  /[^#\n\r\t ]+/ | /[^#\n\r\t ]+[ ][^#\n\r\t ]+/
let simple_entry = [ key key_name . spc . store entry_single_value+ . eol ]


(* Define lens *)
let lns = (simple_entry|empty|Util.comment)+

let filter = incl "/etc/nslcd.conf"
             . Util.stdexcl

let xfm = transform lns filter



