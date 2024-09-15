p/x (0x555555554000 + 0x3fe8)
p/x (0x7ffff7fbf000 + 0x3fe0)


❯ readelf -WS chimera
There are 20 section headers, starting at offset 0x3288:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000000318 000318 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE            0000000000000338 000338 000030 00   A  0   0  8
  [ 3] .note.gnu.build-id NOTE            0000000000000368 000368 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        0000000000000390 000390 00001c 00   A  5   0  8
  [ 5] .dynsym           DYNSYM          00000000000003b0 0003b0 000048 18   A  6   1  8
  [ 6] .dynstr           STRTAB          00000000000003f8 0003f8 00002b 00   A  0   0  1
  [ 7] .rela.dyn         RELA            0000000000000428 000428 000018 18   A  5   0  8
  [ 8] .rela.plt         RELA            0000000000000440 000440 000018 18  AI  5  15  8
  [ 9] .plt              PROGBITS        0000000000001000 001000 000020 10  AX  0   0 16
  [10] .text             PROGBITS        0000000000001020 001020 000043 00  AX  0   0  1
  [11] .eh_frame_hdr     PROGBITS        0000000000002000 002000 000024 00   A  0   0  4
  [12] .eh_frame         PROGBITS        0000000000002028 002028 00007c 00   A  0   0  8
  [13] .dynamic          DYNAMIC         0000000000003e70 002e70 000170 10  WA  6   0  8
  [14] .got              PROGBITS        0000000000003fe0 002fe0 000008 08  WA  0   0  8
  [15] .got.plt          PROGBITS        0000000000003fe8 002fe8 000020 08  WA  0   0  8
  [16] .comment          PROGBITS        0000000000000000 003008 00001f 01  MS  0   0  1
  [17] .symtab           SYMTAB          0000000000000000 003028 000138 18     18   6  8
  [18] .strtab           STRTAB          0000000000000000 003160 00006c 00      0   0  1
  [19] .shstrtab         STRTAB          0000000000000000 0031cc 0000b5 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

playground/part-11/data-and-function on  main [!] via C v16.0.6-clang on ☁️  proseau@google.com 
❯ readelf -WS libfoo.so 
There are 13 section headers, starting at offset 0x2138:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.property NOTE            0000000000000200 000200 000030 00   A  0   0  8
  [ 2] .note.gnu.build-id NOTE            0000000000000230 000230 000024 00   A  0   0  4
  [ 3] .gnu.hash         GNU_HASH        0000000000000258 000258 000024 00   A  4   0  8
  [ 4] .dynsym           DYNSYM          0000000000000280 000280 000030 18   A  5   1  8
  [ 5] .dynstr           STRTAB          00000000000002b0 0002b0 000010 00   A  0   0  1
  [ 6] .eh_frame         PROGBITS        0000000000001000 001000 000000 00   A  0   0  8
  [ 7] .dynamic          DYNAMIC         0000000000001f40 001f40 0000c0 10  WA  5   0  8
  [ 8] .data             PROGBITS        0000000000002000 002000 000004 00  WA  0   0  4
  [ 9] .comment          PROGBITS        0000000000000000 002004 00001f 01  MS  0   0  1
  [10] .symtab           SYMTAB          0000000000000000 002028 000078 18     11   4  8
  [11] .strtab           STRTAB          0000000000000000 0020a0 000017 00      0   0  1
  [12] .shstrtab         STRTAB          0000000000000000 0020b7 00007d 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

playground/part-11/data-and-function on  main [!] via C v16.0.6-clang on ☁️  proseau@google.com 
❯ readelf -WS libbar.so 
There are 17 section headers, starting at offset 0x31d0:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.property NOTE            00000000000002a8 0002a8 000030 00   A  0   0  8
  [ 2] .note.gnu.build-id NOTE            00000000000002d8 0002d8 000024 00   A  0   0  4
  [ 3] .gnu.hash         GNU_HASH        0000000000000300 000300 000024 00   A  4   0  8
  [ 4] .dynsym           DYNSYM          0000000000000328 000328 000048 18   A  5   1  8
  [ 5] .dynstr           STRTAB          0000000000000370 000370 000017 00   A  0   0  1
  [ 6] .rela.dyn         RELA            0000000000000388 000388 000018 18   A  4   0  8
  [ 7] .text             PROGBITS        0000000000001000 001000 00001c 00  AX  0   0  1
  [ 8] .eh_frame_hdr     PROGBITS        0000000000002000 002000 000014 00   A  0   0  4
  [ 9] .eh_frame         PROGBITS        0000000000002018 002018 000038 00   A  0   0  8
  [10] .dynamic          DYNAMIC         0000000000003ef0 002ef0 0000f0 10  WA  5   0  8
  [11] .got              PROGBITS        0000000000003fe0 002fe0 000008 08  WA  0   0  8
  [12] .got.plt          PROGBITS        0000000000003fe8 002fe8 000018 08  WA  0   0  8
  [13] .comment          PROGBITS        0000000000000000 003000 00001f 01  MS  0   0  1
  [14] .symtab           SYMTAB          0000000000000000 003020 0000c0 18     15   6  8
  [15] .strtab           STRTAB          0000000000000000 0030e0 000047 00      0   0  1
  [16] .shstrtab         STRTAB          0000000000000000 003127 0000a3 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)


break _start

# GOT of chimera
watch *(0x555555554000 + 0x3fe0)

# link to fall back for plt in chimera
watch *(0x555555554000 + 0x3ff8)

# GOT.PLT of chimera (head of .got.plt is at + 0x3fe8, but this points to the fall back, and it never changes)
watch *(0x555555554000 + 0x4000)

# GOT of libbar
watch *(0x7ffff7fbf000 + 0x3fe0)


watch *(0x555555554000 + 0x3fe0)
watch *(0x555555554000 + 0x3ff8)
watch *(0x555555554000 + 0x4000)
watch *(0x7ffff7fbf000 + 0x3fe0)


❯ gdb chimera
GNU gdb (GDB) 14.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-unknown-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from chimera...
(No debugging symbols found in chimera)
(gdb) break _start
Breakpoint 1 at 0x103c
(gdb) watch *(0x555555554000 + 0x3fe0)
Hardware watchpoint 2: *(0x555555554000 + 0x3fe0)

(gdb) watch *(0x555555554000 + 0x3ff8)
Hardware watchpoint 3: *(0x555555554000 + 0x3ff8)

(gdb) watch *(0x555555554000 + 0x4000)
Hardware watchpoint 4: *(0x555555554000 + 0x4000)

(gdb) watch *(0x7ffff7fbf000 + 0x3fe0)
Hardware watchpoint 5: *(0x7ffff7fbf000 + 0x3fe0)

(gdb) starti
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera 

Program stopped.
0x00007ffff7fe5730 in ?? () from /lib64/ld-linux-x86-64.so.2
(gdb) continue
Continuing.

Hardware watchpoint 5: *(0x7ffff7fbf000 + 0x3fe0)


Old value = <unreadable>
New value = -134488064
0x00007ffff7fda395 in ?? () from /lib64/ld-linux-x86-64.so.2
(gdb) info proc mapping
process 275123
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555556000     0x555555557000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555557000     0x555555559000     0x2000     0x2000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x7ffff7fb9000     0x7ffff7fbc000     0x3000        0x0  rw-p   
      0x7ffff7fbc000     0x7ffff7fbd000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbd000     0x7ffff7fbe000     0x1000     0x1000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbe000     0x7ffff7fbf000     0x1000     0x2000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbf000     0x7ffff7fc0000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc0000     0x7ffff7fc1000     0x1000     0x1000  r-xp   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc1000     0x7ffff7fc2000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc2000     0x7ffff7fc3000     0x1000     0x2000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc3000     0x7ffff7fc5000     0x2000        0x0  rw-p   
      0x7ffff7fc5000     0x7ffff7fc9000     0x4000        0x0  r--p   [vvar]
      0x7ffff7fc9000     0x7ffff7fcb000     0x2000        0x0  r-xp   [vdso]
      0x7ffff7fcb000     0x7ffff7fcc000     0x1000        0x0  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7fcc000     0x7ffff7ff1000    0x25000     0x1000  r-xp   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ff1000     0x7ffff7ffb000     0xa000    0x26000  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ffb000     0x7ffff7fff000     0x4000    0x30000  rw-p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
(gdb) p/x -134488064
$1 = 0xf7fbe000
(gdb) c
Continuing.

Hardware watchpoint 3: *(0x555555554000 + 0x3ff8)


Old value = 0
New value = -134359536
0x00007ffff7fda1af in ?? () from /lib64/ld-linux-x86-64.so.2
(gdb) p/x -134359536
$2 = 0xf7fdd610
(gdb) # ^ fix the fall back route
(gdb) c
Continuing.

Hardware watchpoint 2: *(0x555555554000 + 0x3fe0)


Old value = 0
New value = -134488064
0x00007ffff7fda395 in ?? () from /lib64/ld-linux-x86-64.so.2
(gdb) p/x -134488064
$3 = 0xf7fbe000
(gdb) # ^ fix the .got of chimera (before we fixed the got of libbar)
(gdb) c
Continuing.

Hardware watchpoint 4: *(0x555555554000 + 0x4000)


Old value = 4118
New value = 1431654422
0x00007ffff7fd93d4 in ?? () from /lib64/ld-linux-x86-64.so.2
(gdb) p/x 4118
$4 = 0x1016
(gdb) p/x 1431654422
$5 = 0x55555016
(gdb) # ^ apply relocations for libbar (just add the offset in the got, to then go to the fall back)
(gdb) c
Continuing.

Breakpoint 1, 0x000055555555503c in _start ()
(gdb) # program starts
(gdb) c
Continuing.

Hardware watchpoint 4: *(0x555555554000 + 0x4000)


Old value = 1431654422
New value = -134479872
0x00007ffff7fdb3f8 in ?? ()
(gdb) p/x -134479872
$6 = 0xf7fc0000
(gdb) # ^ ld fixed the got.plt for chimera to point to change number
(gdb) info proc mappings
process 275123
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555556000     0x555555557000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555557000     0x555555558000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x555555558000     0x555555559000     0x1000     0x3000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
      0x7ffff7fb9000     0x7ffff7fbc000     0x3000        0x0  rw-p   
      0x7ffff7fbc000     0x7ffff7fbd000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbd000     0x7ffff7fbe000     0x1000     0x1000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbe000     0x7ffff7fbf000     0x1000     0x2000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
      0x7ffff7fbf000     0x7ffff7fc0000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc0000     0x7ffff7fc1000     0x1000     0x1000  r-xp   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc1000     0x7ffff7fc2000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc2000     0x7ffff7fc3000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
      0x7ffff7fc3000     0x7ffff7fc5000     0x2000        0x0  rw-p   
      0x7ffff7fc5000     0x7ffff7fc9000     0x4000        0x0  r--p   [vvar]
      0x7ffff7fc9000     0x7ffff7fcb000     0x2000        0x0  r-xp   [vdso]
      0x7ffff7fcb000     0x7ffff7fcc000     0x1000        0x0  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7fcc000     0x7ffff7ff1000    0x25000     0x1000  r-xp   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ff1000     0x7ffff7ffb000     0xa000    0x26000  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ffb000     0x7ffff7fff000     0x4000    0x30000  rw-p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
(gdb) c
Continuing.
[Inferior 1 (process 275123) exited with code 0250]
(gdb) 
