; here we declare `message` as a global, and we say it's of type
; `data` (as opposed to `function`). We also have to specify
; its length, which is `end-start`, read `message.end - message`
global message:data message.end-message

; we only have a data section for this file
section .data

; `message` is a label - which makes sense, a label is just a name for
; a place in memory!
message: db "hi there, this is a longer message than usual", 10
; this here is a local label - it belongs to `message` and can be referred
; using `message.end`. This is how we compute the length of `message`!
 .end:
