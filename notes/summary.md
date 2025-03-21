# Part 1: What's in a Linux executable?

- We write a simple [assembly program](../playground/hello.asm) using `nasm` and make an executable out of it. This program calls the `write` system call and the `exit` system call.

- `xxd` performs an hex dump of a file.

- On Linux executables are ELF files. ELF is a binary format. There is a detail of the format of the header of an ELF file.

- We start writing a parser in Rust using:
  - the `nom` parsing library
  - the `derive_try_from_primitive` library which provides a macro to get an enum value from a primitive type (adds a `try_from` constructor with a macro) when the enum is encoded with primitive type
  - `derive_more` library which provides a macro to derive the `Add` and `Sub` trait automatically on some types (the Address type in particular)

- Using `gdb` (`ugdb` is a nicer TUI tool over `gdb`) we can set `breakpoints` in an executable for it to stop at particular lines or set `catchpoints` to catch system calls. Note that `gdb` can show the executable in the AT&T assembly syntax (default) or the Intel assembly syntax.

- When parsing our [assembly program](../playground/hello.asm) we see that the entrypoint is at `0x04001000` and when running it with `gdb` we see that we are indeed jumping to an instruction at address `0x04001000`. However when doing the same on the `/bin/true` program, our parser shows an entrypoint at line `0x00002130` but `gdb` shows that we are starting from `0x7ffff7fd4100`...

- We write a simple [C program](../playground/entry_point.c) which prints the address of the main function and we see it prints something different at each run (after one single compilation so the entry_point field in the ELF file is the same). However the address always ends with `0x...139`.

- The question is: what does the address written in the `entry_point` section of the ELF header actually mean? It seems like:
  1. it is bigger than the size of the executable
  2. it does not necessarily match the actual start of a program such as for `/bin/true` or for our simple [C program](../playground/entry_point.c)

# Part 2: Running an executable without exec

- We modify our parsing program to also run the program afterwards.

- We use `ndisasm` (n disasembler) to disassemble our [hello executable](../playground/hello.asm) which takes us back to roughly the original `hello.asm` code.

- NB: You need to tell `ndisasm` to interpret instructions over 64 bits (`-b 64`), and to skip (`-k 0,$((0x1000))`) to the address after the header and irrelevant sections of the ELF file before interpreting the bytes as assembly code (in the case of our executable, we skip to the address `0x1000` - we just poke around to find that address by looking at the content)

- We modify our parsing program to also run the `ndisasm` command to print the assembly content (the first `0x25 = 37` bytes from the address `0x1000`) of the ELF file after parsing and running it.

- We modify our parsing program to make a pointer to the 0x1000 byte of the ELK executable, cast it to a raw pointer and then reinterpret the bits of the pointer as a function pointer using the unsafe `std::mem::transmute(addr)` function (`transmute` tell Rustc to reinterpret the bytes as something else with very little checks on the initial bytes):
```rust
let input = fs::read(&input_path)?;
let code = &input[0x1000..];
let code = &code[..std::cmp::min(0x25, code.len())];
let entry_point = code.as_ptr();
unsafe {
    let fn_ptr: fn() -> () = std::mem::transmute(entry_point);
    fn_ptr();
}
```
However running this on our `./hello` program fails with a segfault.

- At this point we modify the [C program](../playground/entry_point.c) to try to do several things:
  - modify a `const` by grabbing a pointer to it and changing the content: this compiles but results in a segfault
  - creating a `const` holding a series of bytes that we know are valid machine language, casting a pointer to the const as a function and trying to jump there: still segfault

- We further analyze the `entry_point` program by running it with `gdb` and looking at the same time to its memory layout with the `pmap <pid>` command which shows the the modes (read, write, execute) of the memory pages (pages are of size 0x1000 - 4096 bits). We see that instructions of the program are mapped on a page with permissions `R-X`, constants are in a separate page with permissions `R--`.

- A (nicer?) alternative to `pmap` is also to `cat /proc/<pid>/maps`.

- To be able to jump to instructions that are specified as a const in our `entry_point.c` program, we use the `memset` lib C function (in `#include <sys/mman.h>` memory management) to set the page where the instructions are stored as executable, and it works.

- The mapping of ELF files to memory (instructions section, constant sections, sections for stack and heap, etc.) are defined in the program headers. The ELF file header specifies the offset of the first program header and how many there are, we retrieve them like so:
```rust
let (i, (program_header_size, program_header_count)) = tuple((&u16_as_usize, &u16_as_usize))(i)?;
...
let progam_header_slices = (&full_input[progam_header_offset.into()..]).chunks(progam_header_size);
let mut program_headers = Vec::new();
for progam_header_slice in progam_header_slices.take(progam_header_count) {
    let (_, progam_header) = ProgramHeader::parse(full_input, progam_header_slice)?;
    program_headers.push(progam_header);
}
```

- We modify our parsing application to:
  1. print the program headers (along with their segment flag - Read, Write, Execute)
  2. identify the bytes to start disassembling from with `ndasm` by finding the section containing the entrypoint through the `ProgramHeader` methods and constructor

- We want to use the same approach as with `entry_point.c` to modify the protection (RWX) of the pages, to make our life simpler we don't use rust's `libc` - which would be the equivalent of what did earlier - but instead the `region` crate (which uses `libc` under the hood)

- Watching the execution of our parser against the `hello` executable with `gdb` we see we jump to execute at the entrypoint address but nothing gets printed...  (NB: you need to set a breakpoint with `break elk::jmp` and not `break jmp` as it's shown on the article)

# Part 3: Position-independent code

## Mitigating moveabs: mapping code at the right location instead of keeping it on the heap

- We modify our parsing application to stop before updating the protection on the pages and before jumping to allow looking at the memory map in more details with `cat /proc/<pid>/maps`. We notice that the kernel "splits" the heap, making one page executable and leaving the rest with the original read-write protection:
```
cat /proc/1326308/maps
...
55fd92d58000-55fd92d59000 rw-p 00099000 fd:01 5113550                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
55fd93001000-55fd93022000 rw-p 00000000 00:00 0                          [heap]
7f02077a2000-7f02077a5000 rw-p 00000000 00:00 0
7f02077a5000-7f02077cb000 r--p 00000000 fd:01 4456906                    /usr/lib/x86_64-linux-gnu/libc.so.6
...
```
vs
```
cat /proc/1326308/maps
...
55fd92d58000-55fd92d59000 rw-p 00099000 fd:01 5113550                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
55fd93001000-55fd93003000 rw-p 00000000 00:00 0                          [heap]
55fd93003000-55fd93004000 rwxp 00000000 00:00 0                          [heap]
55fd93004000-55fd93022000 rw-p 00000000 00:00 0                          [heap]
7f02077a2000-7f02077a5000 rw-p 00000000 00:00 0
7f02077a5000-7f02077cb000 r--p 00000000 fd:01 4456906                    /usr/lib/x86_64-linux-gnu/libc.so.6
...
```

- NB: You can print what is in the registers with `info register <reg-name>` while you execute your program in `gdb`.

- Using `ugdb` and executing the parser program, we see that it wants to execute the `movabs rsi,0x402000` at some point. But `0x402000` corresponds to a virtual address to which some data should be mapped (it is actually the virtual address of the string "Hello World"):
```
# output of our parser program
Analyzsing "../playground/hello"
File {
    tpe: Exec,
    machine: X86_64,
    entry_point: 00401000,
    program_headers: [
        file 00000000..000000e8 | mem 00400000..004000e8 | align 00001000 | R.. Load,
        file 00001000..00001025 | mem 00401000..00401025 | align 00001000 | R.X Load,
        file 00002000..0000200d | mem 00402000..0040200d | align 00001000 | RW. Load, <- here!
    ],
}
# checking what is in that section of the file:
$ dd if=../playground/hello bs=1 count=$((0xd)) skip=$((0x2000))
Hello, World
13+0 records in
13+0 records out
1
```
but since we loaded the `hello` ELF file in our parser program, it lives in the heap of the program (this has been done by the rust allocator when reading the file, not by `exec`), hence there is nothing at address `0x402000`! Checking the memory maps shows only addresses starting from:
```
555555554000-55555555d000 r--p 00000000 fd:01 5113010                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
55555555d000-5555555cd000 r-xp 00009000 fd:01 5113010                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
5555555cd000-5555555e8000 r--p 00079000 fd:01 5113010                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
```

- We try to inline the data in the assembly code (no `moveabs` instruction to some fixed address), and then we do see some text printed.

- We modify the parsing program such that for each program header of type LOAD:
  - we require the OS to allocate a new memory page to the process and we map it at the virtual address pointed to by `program_header.virtual_address` (where the section pointed to by the program header should end up being mapped to by `exec` - the section is at `program_header.offset` in the file):
    ```rust
    let mem_range = program_header.mem_range();
    let len: usize = (mem_range.end - mem_range.start).into();
    let addr: *mut u8 = mem_range.start.0 as _;
    let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
    ```
  NB: we used a crate to get the `MemoryMap` structure, that crate relies on the `libc` crate underneath (which generates binary code that is compatible with the binary code of glibc on Linux, cf. `readelf -d ./target/debug/elk | grep "NEEDED"`)
  At the end of this step we see new pages appearing for each segment, eg. after the first call to `MemoryMap::new`:
  ```
  00400000-00401000 -w-p 00000000 00:00 0 <- this is new
  55c3be274000-55c3be27e000 r--p 00000000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be27e000-55c3be2f2000 r-xp 0000a000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be2f2000-55c3be30e000 r--p 0007e000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  ...
  ```
  - we copy the data of the program header (living as a `Vec<u8>` on the heap of the program) at the location of the newly created page:
    ```rust
    let destination = unsafe { std::slice::from_raw_parts_mut(addr, program_header.data.len()) };
    destination.copy_from_slice(&program_header.data[..]);
    ```
  - we update page protections based the protection flages in the program header:
  ```
  00400000-00401000 r--p 00000000 00:00 0 <- updated
  55c3be274000-55c3be27e000 r--p 00000000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be27e000-55c3be2f2000 r-xp 0000a000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be2f2000-55c3be30e000 r--p 0007e000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  ...
  ```
  Eventually the program `hello` which uses the `moveabs` instruction referring to an address which was not available in the process virtual memory (the code was mapped on the heap) executes properly when jumping there.

At this point we understand that `exec`:
- parses the ELF files
- uses `mmap` (or the internal Kernel equivalent) to map memory pages to the virtual address pointed to by the ELF program header file
- adjusts the protection bits of those pages

## Why our parser fails on C programs? dynamic linking

- We then try to run our parsing program on a [C compiled program](../playground/entry_point) (not like our [executable generated from nasm](../playground/hello)). But this fails.

- We update our parsing program such that:
  - it understands more SegmentType (easy)
  - instead of mapping each section at the location indicated by virtual_address in the program header, we map it to the `virtual_address + base` (base chosen to be randomly 0x400000). We do that because one region was mapped to a region starting at address 0 which was suspicious. However doing that probably breaks the execution of `../playground/hello` which made use of the `moveabs` instruction (since now all addresses are shifted -> just tried it does!).
  - instead of mapping each section to its virtual address, we round the virtual address down to be paged align (set the last 3 bits to 0)

- Despite all of that, it segfaults when we jump to execute the code in the section containing the entrypoint. Using `ugdb` we see we jump at the entrypoint section (at address 0x400000 + entrypoint) but we quickly execute a `call` command (which is a call to a function, hence a jump) and when stepping through we are brought to address 0 which is obviously invalid...
```
0x4010a0 xor    ebp,ebp                 # <- jmp gets here
0x4010a2 mov    r9,rdx
0x4010a5 pop    rsi
0x4010a6 mov    rdx,rsp
0x4010a9 and    rsp,0xfffffffffffffff0
0x4010ad push   rax
0x4010ae push   rsp
0x4010af xor    r8d,r8d
0x4010b2 xor    ecx,ecx
0x4010b4 lea    rdi,[rip+0xe2]          # 0x40119d
0x4010bb call   QWORD PTR [rip+0x2eff]  # 0x403fc0
0x4010c1 hlt
...
(gdb) print \x 0x4010c1 + 0x2eff # the comment shows which address corresponds to [rip + 0xABC]
> 0x403fc0
(gdb) x 0x403fc0
> 0x000000 # invalid address
```

- NB: `ugdb` prints the result of `rip + 0xABC` in the comments, we can find the same result by replacing `rip` by the value of the next instruction (`rip` is the program counter, when the instruction executes its value is already incremented, intel makes use of pipelining...)

- We inspect [our C compiled program](../playground/entry_point) with `objdump --disasembler-option intel --disassemble-all` (or `objdump -M intel -D`) and we look for that line of code with `0x2eff`, and it shows in the comment that this address corresponds to a call to `__libc_start_main` (which we didn't define):
```
10af:   45 31 c0                xor    r8d,r8d
10b2:   31 c9                   xor    ecx,ecx
10b4:   48 8d 3d e2 00 00 00    lea    rdi,[rip+0xe2]           # 119d <main>
10bb:   ff 15 ff 2e 00 00       call   QWORD PTR [rip+0x2eff]   # 3fc0 <__libc_start_main@GLIBC_2.34>
10c1:   f4                      hlt
```

- Looking at the symbol table with `nm entry_point` we see that the `__libc_start_main` symbol is undefined (`U`):
```
...
0000000000003dd0 d __frame_dummy_init_array_entry
                 w __gmon_start__
                 U __libc_start_main@GLIBC_2.34
0000000000004048 D _edata
0000000000004050 B _end
0000000000001364 T _fini
0000000000001000 T _init
...
```

- However since the program works when run directly (launched with `exec`) we run it directly with `ugdb` to understand what is going on:
```
(gdb) break _start
Breakpoint 1 at 0x10a0
(gdb) start
(gdb) x/13i $pc # x = examine, 13 = count, i = format (instructions, could be x hexadecimal, d for decimal, check the help)
   0x5555555550a0 <_start>: xor    ebp,ebp
   0x5555555550a2 <_start+2>:   mov    r9,rdx
   0x5555555550a5 <_start+5>:   pop    rsi
   0x5555555550a6 <_start+6>:   mov    rdx,rsp
   0x5555555550a9 <_start+9>:   and    rsp,0xfffffffffffffff0
   0x5555555550ad <_start+13>:  push   rax
   0x5555555550ae <_start+14>:  push   rsp
   0x5555555550af <_start+15>:  xor    r8d,r8d
   0x5555555550b2 <_start+18>:  xor    ecx,ecx
   0x5555555550b4 <_start+20>:  lea    rdi,[rip+0xe2]           # 0x55555555519d <main>
   0x5555555550bb <_start+27>:  call   QWORD PTR [rip+0x2eff]   # 0x555555557fc0
   0x5555555550c1 <_start+33>:  hlt
(gdb) x/1xg 0x555555557fc0 # x = examine, 1 = count, g = giant (8 bytes)
0x555555557fc0: 0x00007ffff7df5700
```
- We see that the address `0x00007ffff7df5700` is mapped to libc:
```
❯ cat /proc/254450/maps | grep "7ffff7df"
7ffff7dce000-7ffff7df4000 r--p 00000000 fd:01 4456906                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7df4000-7ffff7f49000 r-xp 00026000 fd:01 4456906                    /usr/lib/x86_64-linux-gnu/libc.so.6
```
  which means that `exec` also mapped `libc.so.6` at a paricular place and replaced the undefined symbol by its address once mapped!

- Logically checking the symbols in `/usr/lib/x86_64-linux-gnu/libc.so.6` show that the symbol `__libc_start_main` address lowest bits (`700`) match the ones of its address `0x00007ffff7df5700` when mapped by `exec` during execution (they are the same mod 4K bits):
```
❯ readelf -Ws /usr/lib/x86_64-linux-gnu/libc.so.6 | grep libc_start_main
1754: 0000000000027700   321 FUNC    GLOBAL DEFAULT   16 __libc_start_main@@GLIBC_2.34
1756: 0000000000027700   321 FUNC    GLOBAL DEFAULT   16 __libc_start_main@GLIBC_2.2.5
```

- At this point we understand that `exec` also:
  - maps libraries to particular addresses
  - updates the undefined symbols of an executable (which initially points to `0x0`) to point to the final address of the symbol of libraries (where it ends up being mapped to, not its address in the library file obviously)

## Position Independent Executable

- Going back to our [assembly](../playground/hello) program, we notice that references in `.o` files are also resolved/defined by the static linker just like the dynamic linker does for libraries that are found dynamically at runtime. Check out the difference between `hello.o` and the executable `hello`:
```
❯ nasm -f elf64 hello.asm -o hello.o

❯ ndisasm -b 64 hello.o | grep -A5 -B5 "syscall"
00000200  B801000000        mov eax,0x1
00000205  BF01000000        mov edi,0x1
0000020A  48BE000000000000  mov rsi,0x0  <- the .o file has this hanging around pointing to 0x0
         -0000
00000214  BA0D000000        mov edx,0xd
00000219  0F05              syscall
0000021B  B83C000000        mov eax,0x3c
00000220  4831FF            xor rdi,rdi
00000223  0F05              syscall
00000225  0000              add [rax],al
00000227  0000              add [rax],al
00000229  0000              add [rax],al
0000022B  0000              add [rax],al
0000022D  0000              add [rax],al

❯ ld hello.o -o hello

❯ ndisasm -b 64 hello | grep -A5 -B5 "syscall"
00000FFF  00B801000000      add [rax+0x1],bh
00001005  BF01000000        mov edi,0x1
0000100A  48BE002040000000  mov rsi,0x402000 <- this has been updated by `ld` (static link time)
         -0000
00001014  BA0D000000        mov edx,0xd
00001019  0F05              syscall
0000101B  B83C000000        mov eax,0x3c
00001020  4831FF            xor rdi,rdi
00001023  0F05              syscall
00001025  0000              add [rax],al
00001027  0000              add [rax],al
00001029  0000              add [rax],al
0000102B  0000              add [rax],al
0000102D  0000              add [rax],al
```

- Also since we modified our [parsing and execution program](../elk/src/main.rs) to map every section to their virtual_address offseted by some base address (to prevent from errors due to 1 section mapping to address 0), we then try to generate the `hello` executable with the `-pie` (position independent executable) option with the linker and expect not to see any `moveabs`, but:
```
❯ # original
❯ objdump -M intel -D hello | grep -A 5 -B 5 syscall
  401000:       b8 01 00 00 00          mov    eax,0x1
  401005:       bf 01 00 00 00          mov    edi,0x1
  40100a:       48 be 00 20 40 00 00    movabs rsi,0x402000
  401011:       00 00 00
  401014:       ba 0d 00 00 00          mov    edx,0xd
  401019:       0f 05                   syscall
  40101b:       b8 3c 00 00 00          mov    eax,0x3c
  401020:       48 31 ff                xor    rdi,rdi
  401023:       0f 05                   syscall

Disassembly of section .data:

0000000000402000 <message>:
  402000:       48                      rex.W
❯ # VS
❯ ld -pie hello.o -o hello-pie
❯ objdump -M intel -D hello-pie | grep -A 5 -B 5 syscall
    1000:       b8 01 00 00 00          mov    eax,0x1
    1005:       bf 01 00 00 00          mov    edi,0x1
    100a:       48 be 00 30 00 00 00    movabs rsi,0x3000 <- this has changed but still uses the moveabs instruction
    1011:       00 00 00
    1014:       ba 0d 00 00 00          mov    edx,0xd
    1019:       0f 05                   syscall
    101b:       b8 3c 00 00 00          mov    eax,0x3c
    1020:       48 31 ff                xor    rdi,rdi
    1023:       0f 05                   syscall

Disassembly of section .dynamic:

0000000000002ed0 <_DYNAMIC>:
    2ed0:       04 00                   add    al,0x0
```

- Trying to run our parser/executer on it we don't see any output (because there is nothing mapped at address `0x3000`).

- We try various things to instruct `nasm` to use relative addressing but it does not work, so the trick is to replace in the assembly code `mov rsi, message` by `lea rsi, [rel message]` (`lea` stands for `Load Effective Address`)
```
❯ objdump -M intel -D hello-lea-pie | grep -A 5 -B 5 syscall
0000000000001000 <_start>:
    1000:       b8 01 00 00 00          mov    eax,0x1
    1005:       bf 01 00 00 00          mov    edi,0x1
    100a:       48 8d 35 ef 1f 00 00    lea    rsi,[rip+0x1fef]        # 3000 <message> <- this is now relative to RIP the program counter
    1011:       ba 0d 00 00 00          mov    edx,0xd
    1016:       0f 05                   syscall
    1018:       b8 3c 00 00 00          mov    eax,0x3c
    101d:       48 31 ff                xor    rdi,rdi
    1020:       0f 05                   syscall
```

- With the resulting [executable](../playground/hello-lea-pie), the `"Hello World"` string is printed when run through our `elk` program.

- NB: Also we could not run the new `./hello-pie` or `./hello-lea-pie` executables because by default `ld` refers to the interpreter `/lib/ld64.so.1` which does not exist on our machine
```
❯ ./hello-pie
zsh: no such file or directory: ./hello-pie
❯ file hello-pie
hello-pie: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld64.so.1, not stripped
❯ file /lib/ld64.so.1
/lib/ld64.so.1: cannot open `/lib/ld64.so.1' (No such file or directory)
```
To make it work we need to instruct `ld` to link our object file with a valid linker (we found it by checking the one used by our [C program](../playground/entry_point)):
```
❯ file ../playground/entry_point
../playground/entry_point: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce9
eeb1110ea69d0d21d6ff489c835244ef5b2f5, for GNU/Linux 3.2.0, not stripped
❯ ld --dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie hello.o -o hello-pie
ld: hello.o: warning: relocation in read-only section `.text'
ld: warning: creating DT_TEXTREL in a PIE
❯ ./hello-pie
Hello World
```

- At this point we understand that:
  - an ELF file points to an interpreter (a linker typically `ld`) which needs to be present on the host, you can see it with `file <elf-file>`
  - you can instruct `ld` to generate a Position Independent Executable with the option `ld -pie` such that the executable output can be loaded anywhere in memory and work (this is commonly used for shared libraries which need to be mapped when running an arbitrary executable (we don't know what address span will be available)
  - some assembly instructions will break a PIE code, in our case we had to replace a `mov` by a `lea`

# Part 4: ELF relocations

- When disasembling the position dependent [assembly program](../playground/hello), we see that `moveabs` refers to the message bytes:
```
❯ objdump -M intel -D hello | grep -A 16 -B 10 syscall

Disassembly of section .text:

0000000000401000 <_start>:
  401000:       b8 01 00 00 00          mov    eax,0x1
  401005:       bf 01 00 00 00          mov    edi,0x1
  40100a:       48 be 00 20 40 00 00    movabs rsi,0x402000
  401011:       00 00 00
  401014:       ba 0d 00 00 00          mov    edx,0xd
  401019:       0f 05                   syscall
  40101b:       b8 3c 00 00 00          mov    eax,0x3c
  401020:       48 31 ff                xor    rdi,rdi
  401023:       0f 05                   syscall

Disassembly of section .data:

0000000000402000 <message>:             -- this assembly code is irrelevant, these bytes are interpreted as chars --
  402000:       48                      rex.W
  402001:       65 6c                   gs ins BYTE PTR es:[rdi],dx
  402003:       6c                      ins    BYTE PTR es:[rdi],dx
  402004:       6f                      outs   dx,DWORD PTR ds:[rsi]
  402005:       2c 20                   sub    al,0x20
  402007:       57                      push   rdi
  402008:       6f                      outs   dx,DWORD PTR ds:[rsi]
  402009:       72 6c                   jb     402077 <_end+0x67>
  40200b:       64                      fs
  40200c:       0a                      .byte 0xa

❯ printf "\x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\x64\x0a"
Hello, World

❯ gdb ../playground/hello
(gdb) break _start
Breakpoint 1 at 0x401000
(gdb) start
Function "main" not defined.
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/hello

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) x/10i $pc
=> 0x401000 <_start>:   mov    eax,0x1
   0x401005 <_start+5>: mov    edi,0x1
   0x40100a <_start+10>:        movabs rsi,0x402000 <- no surprises there
   0x401014 <_start+20>:        mov    edx,0xd
   0x401019 <_start+25>:        syscall
   0x40101b <_start+27>:        mov    eax,0x3c
   0x401020 <_start+32>:        xor    rdi,rdi
   0x401023 <_start+35>:        syscall
   0x401025:    add    BYTE PTR [rax],al
   0x401027:    add    BYTE PTR [rax],al
```

- However the [PIE version](../playground/hello-pie) still has a `moveabs` but to the `0x3000` address which does not hold any data when looking with `objdump`. However when we execute `hello-pie`, we see that `0x3000` address has been updated:
```
❯ objdump -M intel -D hello-pie | grep -A 16 -B 10 syscall

Disassembly of section .text:

0000000000001000 <_start>:
    1000:       b8 01 00 00 00          mov    eax,0x1
    1005:       bf 01 00 00 00          mov    edi,0x1
    100a:       48 be 00 30 00 00 00    movabs rsi,0x3000
    1011:       00 00 00
    1014:       ba 0d 00 00 00          mov    edx,0xd
    1019:       0f 05                   syscall
    101b:       b8 3c 00 00 00          mov    eax,0x3c
    1020:       48 31 ff                xor    rdi,rdi
    1023:       0f 05                   syscall

Disassembly of section .dynamic:

0000000000002ed0 <_DYNAMIC>:
    2ed0:       04 00                   add    al,0x0
    2ed2:       00 00                   add    BYTE PTR [rax],al
    2ed4:       00 00                   add    BYTE PTR [rax],al
    2ed6:       00 00                   add    BYTE PTR [rax],al
    2ed8:       20 02                   and    BYTE PTR [rdx],al
    2eda:       00 00                   add    BYTE PTR [rax],al
    2edc:       00 00                   add    BYTE PTR [rax],al
    2ede:       00 00                   add    BYTE PTR [rax],al

❯ gdb ../playground/hello-pie
(gdb) break _start
Breakpoint 1 at 0x1000
(gdb) start
Function "main" not defined.
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/hello-pie
Breakpoint 1, 0x0000555555555000 in _start ()
(gdb) x/10i $pc
=> 0x555555555000 <_start>:     mov    eax,0x1
   0x555555555005 <_start+5>:   mov    edi,0x1
   0x55555555500a <_start+10>:  movabs rsi,0x555555557000 <- this is different
   0x555555555014 <_start+20>:  mov    edx,0xd
   0x555555555019 <_start+25>:  syscall
   0x55555555501b <_start+27>:  mov    eax,0x3c
   0x555555555020 <_start+32>:  xor    rdi,rdi
   0x555555555023 <_start+35>:  syscall
   0x555555555025:      add    BYTE PTR [rax],al
   0x555555555027:      add    BYTE PTR [rax],al
(gdb)
```

- This is possible thanks to the `.dynamic` section of the ELF file (which is pointed to by a program header of type `PT_DYNAMIC`).

- We update the parsing library to be able to parse the `PT_DYNAMIC` program header. When encountering a program header of type dynamic, we parse the corresponding segment to get a list of Dynamic Entries (a tag - ie. type - and an address or int - same byte length but can be interpreted differently according to the tag).

- Within those entries, we can find a dynamic entry of type `Rela` of which the address points to bytes which can be parsed as an array of:
```rust
pub struct Rela {
    pub offset: Addr,
    pub relocation_type: u32,
    pub symbol: u32,
    pub addend: Addr
}
```
  This array is called the "Relocation table" (the above struct is also known as `Elf64_Rela` entry). We know how many bytes to consider for parsing the reloction table (array of `Rela`s or relocation_entry) with the information contained in the `RelaSz` dynamic entry (gives the amount of bytes to consider) and the `RelaCount` dynamic entry.

- To summarize, the dynamic program header points to a list of dynamic entries, of which the `Rela` dynamic entry points to the start of the relocation table.

- Note that there are different `relocation_type` for different processor, because they each have different instructions (in machine language), the instructions need to be patched differently.

- We modify our parsing program such that, once we mapped the code in memory, but before we update page permissions (updating permissions could remove the writing capability), for each relocation entry in the relocation table, we update the bytes pointed to by `relocation_entry.offset` and we replace their content by `relocation_entry.addend`. The point is to update the operand of instructions that are invalid because they are relative to the where the code will be mounted (remember we generated `hello-pie` with `ld -pie`).

- Since we have added an offset, `base` (`0x40000`), before mapping the segments in memory, and we decided to update those instructions after them being mapped in memory we find the bytes to modify by adding `base`: `relocation_entry.offset + base`.

- Since the only type of relocation_entry we have in our `hello-pie` ELF file is `Relative`, `relocation_entry.addend` is an address relative to the base address, so instead of updating the operand by `relocation_entry.addend` we update it with `base + relocation_entry.addend` (the operand represents an address in the executable).

- In this particular example, the last bytes of the instruction `moveabs rsi, 0x3000` are modified from `0x3000` to `0x403000 (base + 0x3000)`. This instruction was at `0x1000` in the ELF file and mounted at `base + 0x1000`. In our parsing program we map the instructions on pages at address `0x40000` moving up, so we use that latter address to find the instruction to update.

- In summary, to account for position independent executables you need to:
  - find the ProgramHeader of type Dynamic, and parse its corresponding segment in an array of (tag, addr/int)
  - identify the relocation table thanks to the dynamic entries of type (with tag) `Rela`, `RelaSz` in the Dynamic section
  - parse the relocation table
  - for each relocation entry in the relocation table update the instructions pointed to (applying any modifications necessary if we are mapping instructions at a different address than the virtual address indicated in the program header)

# Part 5: The simplest shared library

- This part is about how to run executables which depend on shared code which is resolved at load/run time (dynamic libraries): how to locate the dynamic libraries, load libraries and update the executable such that it references the libraries code correctly.

- We start by splitting our [assembly application](../playground/hello) in 2 assembly files where one file holds the definition of `message` only. Linking the 2 object files with `ld` results in a working executable which runs fine with our [parsing executable](../elk/src/main.rs) as well.
  ```sh
  nasm -f elf64 hello-with-extern.asm
  nasm -f elf64 message.asm
  ld hello-with-extern.o message.o -o hello-with-extern
  # or with PIE version
  ld -pie --dynamic-linker /lib64/ld-linux-x86-64.so.2 hello-with-extern.o message.o -o hello-with-extern
  ```

- Now we make `message.o` a shared library with:
  ```sh
  ld -shared message.o -o libmessage.so
  ld -pie --dynamic-linker /lib64/ld-linux-x86-64.so.2 hello-with-extern.o libmessage.so -o hello-with-extern
  ```

- But it can't execute because it can't find `libmessage.so` when loading (Analyzsing with `ldd` which resolves and prints dynamic libraries for an executable):
```
❯ ./hello-with-extern
./hello-with-extern: error while loading shared libraries: libmessage.so: cannot open shared object file: No such file or directory

❯ ldd ./hello-with-extern
        linux-vdso.so.1 (0x00007ffee7350000)
        libmessage.so => not found                 <- this is not normal!
```

- NB1: when launching an executable, you can get the interpreter to output logs by setting the `LD_DEBUG` library (this is implemented in the /lib64/ld-linux-x86-64.so.2 binary)
  ```sh
  LD_DEBUG=libs ./hello-with-extern
     1396361:     find library=libmessage.so [0]; searching
     1396361:      search cache=/etc/ld.so.cache
     1396361:      search path=/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4:/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3:/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v
  2:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4:/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3:/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x
  86-64-v2:/usr/lib/x86_64-linux-gnu:/lib/glibc-hwcaps/x86-64-v4:/lib/glibc-hwcaps/x86-64-v3:/lib/glibc-hwcaps/x86-64-v2:/lib:/usr/lib/glibc-hwcaps/x86-64-v4:/usr/l
  ib/glibc-hwcaps/x86-64-v3:/usr/lib/glibc-hwcaps/x86-64-v2:/usr/lib              (system search path)
     1396361:       trying file=/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libmessage.so
     1396361:       trying file=/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libmessage.so
     1396361:       trying file=/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libmessage.so
     1396361:       trying file=/lib/x86_64-linux-gnu/libmessage.so
     ...
  ```

- NB2: an interpreter does not depend on any shared dependencies, those are statically linked:
  ```
  ❯ ldd /lib64/ld-linux-x86-64.so.2
          statically linked   <- objdump -M intel -d /lib64/ld-linux-x86-64.so.2
                                 will show you that libc methods are embedded in the binary itself
  ❯ # VS
  ❯ ldd /bin/cat
          linux-vdso.so.1 (0x00007ffe935d2000)
          libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fae4e68b000)
          /lib64/ld-linux-x86-64.so.2 (0x00007fae4e88f000)
  ```

- The reason why `./hello-with-extern` cannot execute with the shared library is because the binary's search path does not contain the directory where `./libmessage.so` is. You can change that by setting the `RPATH` or `RUNPATH` (we don't cover this one) of the executable when building it to add paths to the builtin search path of the interpreter. You can also update the search path at runtime with `LD_LIBRARY_PATH=./path1:./path2` to instruct the interpreter to add these paths to its path.
  ```sh
  ❯ ld \
    -pie \
    -rpath . \
    --dynamic-linker /lib64/ld-linux-x86-64.so.2 \
    -o hello-with-extern \
    hello-with-extern.o libmessage.so

  ❯ ./hello-with-extern # works!

  ❯ objdump -p hello-with-extern | grep PATH  # -p prints private headers
    RUNPATH              .
  ```

NB: `-rpath .` will cause the binary to fail to load its dynamic libaries if the `CWD` is not where the library is. Instead you can use `-rpath '$ORIGIN'` to instruct the interpreter to add to the search path the parent directory of the executable file itself (however if you move the binary to a different location it will fail to load its libraries as well)

- Our parsing program fails to run our assembly program linked against a shared library, because our Rust code does not include anything to look for the shared library, it neither loads it and nor resovles references. When analyzing the execution of `./hello-with-extern` by our parsing/execution program through `ugdb` we realize that the address for the `message` is still `0x0` (operand `movabs`) which means some relocation is not applied by our parsing/execution program despite the work we did earlier to relocate code that was linked with `-pie`.

- Running the binary directly (not through our custom parser/executer program) and analyzing with `ugdb` and `cat /proc/<pid>/maps` we see that:
  - the `libmessage.so` library has been mapped into the process library at some high address (`0x7fff...`)
  - the address operand for moveabs has been replaced to some address close to the instructions (`0x555555557000`), just like before

  ```
  ❯ gdb ./hello-with-extern
  GNU gdb (GDB) 14.1
  Reading symbols from ./hello-with-extern...
  (No debugging symbols found in ./hello-with-extern)
  (gdb) break _start
  Breakpoint 1 at 0x1000
  (gdb) x/10i 0x1000
     0x1000 <_start>:     mov    eax,0x1
     0x1005 <_start+5>:   mov    edi,0x1
     0x100a <_start+10>:  movabs rsi,0x0          <- this is how the instructions are written
     0x1014 <_start+20>:  mov    edx,0x2e
     0x1019 <_start+25>:  syscall
     0x101b <_start+27>:  mov    eax,0x3c
     0x1020 <_start+32>:  xor    rdi,rdi
     0x1023 <_start+35>:  syscall
     0x1025:      Cannot access memory at address 0x1025
  (gdb) start

  Breakpoint 1, 0x0000555555555000 in _start ()
  (gdb) x/10i $pc
  => 0x555555555000 <_start>:     mov    eax,0x1
     0x555555555005 <_start+5>:   mov    edi,0x1
     0x55555555500a <_start+10>:  movabs rsi,0x555555557000  <- once the executable is started, a relocation is applied
     0x555555555014 <_start+20>:  mov    edx,0x2e
     0x555555555019 <_start+25>:  syscall
     0x55555555501b <_start+27>:  mov    eax,0x3c
     0x555555555020 <_start+32>:  xor    rdi,rdi
     0x555555555023 <_start+35>:  syscall
     0x555555555025:      add    BYTE PTR [rax],al
     0x555555555027:      add    BYTE PTR [rax],al
  ```

and
  ```
  ❯ cat /proc/1524648/maps
  555555554000-555555555000 r--p 00000000 fd:01 5115391                    /home/proseau/projects/perso/rust-executable-packer/playground/hello-with-extern
  555555555000-555555556000 r-xp 00001000 fd:01 5115391                    /home/proseau/projects/perso/rust-executable-packer/playground/hello-with-extern
  555555556000-555555557000 r--p 00002000 fd:01 5115391                    /home/proseau/projects/perso/rust-executable-packer/playground/hello-with-extern
  555555557000-555555558000 rw-p 00000000 00:00 0                          [heap]
  7ffff7fc0000-7ffff7fc1000 r--p 00000000 fd:01 5113041                    /home/proseau/projects/perso/rust-executable-packer/playground/libmessage.so
  7ffff7fc1000-7ffff7fc2000 r--p 00001000 fd:01 5113041                    /home/proseau/projects/perso/rust-executable-packer/playground/libmessage.so
  7ffff7fc2000-7ffff7fc3000 rw-p 00002000 fd:01 5113041                    /home/proseau/projects/perso/rust-executable-packer/playground/libmessage.so
  7ffff7fc3000-7ffff7fc5000 rw-p 00000000 00:00 0
  7ffff7fc5000-7ffff7fc9000 r--p 00000000 00:00 0                          [vvar]
  7ffff7fc9000-7ffff7fcb000 r-xp 00000000 00:00 0                          [vdso]
  7ffff7fcb000-7ffff7fcc000 r--p 00000000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  7ffff7fcc000-7ffff7ff1000 r-xp 00001000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  7ffff7ff1000-7ffff7ffb000 r--p 00026000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  7ffff7ffb000-7ffff7fff000 rw-p 00030000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
  ```

- We update our parsing code to understand more relocation entry (so far we only interpreted the entries of type `Relative`). In particular we notice that when linked to a shared library (ie. library to load dynamically), the `Relative` entry is gone, but we now have 2 entries: one of type `64` and one of type `Copy`, and both of them have their symbol field set to `1` (it was `0` when not dynamically linking).
  ```
  # Case with PIE linking but no shared library
  Found 1 relocation entries
  - Rela { offset: 0000100c, relocation_type: Known(Relative), symbol: 0, addend: 00003000 }

  # VS

  # Case with dynamic linking to libmessage.so
  Found 2 relocation entries
  - Rela { offset: 0000100c, relocation_type: Known(_64), symbol: 1, addend: 00000000 }
  - Rela { offset: 00003000, relocation_type: Known(Copy), symbol: 1, addend: 00000000 }
  ```

- NB: You can recover the same information with `readelf --relocs`:
```
> readelf --relocs hello-with-extern

Relocation section '.rela.dyn' at offset 0x2b0 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
00000000100c  000100000001 R_X86_64_64       0000000000003000 message + 0
000000003000  000100000005 R_X86_64_COPY     0000000000003000 message + 0
```

- Also we notice that new dynamic entries are in the dynamic table (pointed to by the program header of type `Dynamic`):
  ```
  Dynamic entries
  - DynamicEntry { tag: Needed, addr: 00000009 }   <- this is new
  - DynamicEntry { tag: RunPath, addr: 00000017 }  <- this is new
  - DynamicEntry { tag: Hash, addr: 00000220 }
  - DynamicEntry { tag: GnuHash, addr: 00000238 }
  - DynamicEntry { tag: StrTab, addr: 00000290 }
  - DynamicEntry { tag: SymTab, addr: 00000260 }   <- address of the symbol table
  - DynamicEntry { tag: StrSz, addr: 0000001f }
  - DynamicEntry { tag: SymEnt, addr: 00000018 }
  - DynamicEntry { tag: Debug, addr: 00000000 }
  - DynamicEntry { tag: Rela, addr: 000002b0 }
  - DynamicEntry { tag: RelaSz, addr: 00000030 }
  - DynamicEntry { tag: RelaEnt, addr: 00000018 }
  - DynamicEntry { tag: TextRel, addr: 00000000 }
  - DynamicEntry { tag: Flags, addr: 00000004 }
  - DynamicEntry { tag: Flags1, addr: 08000000 }
  ```

- Our assumption at this point is that the dynamic loader:
  - finds the shared library through the Needed / RunPath dynamic entries (these probably point to entries in the String Table which is pointed to by `StrTab`)
  - loads the shared libraries in memory
  - uses the Relocation entries in the Relocation table (pointed to by the `Rela` dynamic entry in the dynamic table) to copy data (the message data in this case) from the shared library to another location in memory and to update the references to that data (for the `moveabs`)

- To be able to look at the needed libraries and runpath, we will need to look at the offset they point to into the String Table `StrTab` until we find a null character (`\00`):
```
❯ dd status=none if=./hello-with-extern bs=1 skip=$((0x290)) count=$((0x1f)) | xxd
00000000: 006d 6573 7361 6765 006c 6962 6d65 7373  .message.libmess
00000010: 6167 652e 736f 0024 4f52 4947 494e 00    age.so.$ORIGIN.
```

- To be able to link code from the shared library in the final executable, we need to make use of the Symbol table.

- The DynamicEntry for `SymTab` actually points to an address in the file (`0x260` in this case), but we don't know how long the Symbol table is.

- We need to modify our parsing program to also parse section headers. There is actually a section header of which the `address` field matches the value of the `SymTab` dynamic entry and its `entry_size` field matches the value of the `SymEnt` dynamic entry.
```
Section headers:
SectionHeader { name: 00000000, section_type: 0, flags: 0, address: 00000000, offset: 00000000, size: 00000000, link: 0, info: 0, align: 00000000, entry_size: 00000000 }
SectionHeader { name: 0000001b, section_type: 1, flags: 2, address: 00000200, offset: 00000200, size: 0000001c, link: 0, info: 0, align: 00000001, entry_size: 00000000 }
SectionHeader { name: 00000027, section_type: 5, flags: 2, address: 00000220, offset: 00000220, size: 00000014, link: 4, info: 0, align: 00000008, entry_size: 00000004 }
SectionHeader { name: 00000023, section_type: 1879048182, flags: 2, address: 00000238, offset: 00000238, size: 00000024, link: 4, info: 0, align: 00000008, entry_size: 00000000 }
# This one corresponds to the symbol table and gives us the size of the Symbol table (30)
SectionHeader { name: 0000002d, section_type: 11, flags: 2, address: 00000260, offset: 00000260, size: 00000030, link: 5, info: 1, align: 00000008, entry_size: 00000018 }
SectionHeader { name: 00000035, section_type: 3, flags: 2, address: 00000290, offset: 00000290, size: 0000001f, link: 0, info: 0, align: 00000001, entry_size: 00000000 }
SectionHeader { name: 0000003d, section_type: 4, flags: 2, address: 000002b0, offset: 000002b0, size: 00000030, link: 4, info: 0, align: 00000008, entry_size: 00000018 }
SectionHeader { name: 00000047, section_type: 1, flags: 6, address: 00001000, offset: 00001000, size: 00000025, link: 0, info: 0, align: 00000010, entry_size: 00000000 }
SectionHeader { name: 0000004d, section_type: 1, flags: 2, address: 00002000, offset: 00002000, size: 00000000, link: 0, info: 0, align: 00000008, entry_size: 00000000 }
SectionHeader { name: 00000057, section_type: 6, flags: 3, address: 00002eb0, offset: 00002eb0, size: 00000150, link: 5, info: 0, align: 00000008, entry_size: 00000010 }
SectionHeader { name: 00000060, section_type: 8, flags: 3, address: 00003000, offset: 00003000, size: 00000030, link: 0, info: 0, align: 00000004, entry_size: 00000000 }
SectionHeader { name: 00000001, section_type: 2, flags: 0, address: 00000000, offset: 00003000, size: 000000d8, link: 12, info: 4, align: 00000008, entry_size: 00000018 }
SectionHeader { name: 00000009, section_type: 3, flags: 0, address: 00000000, offset: 000030d8, size: 00000040, link: 0, info: 0, align: 00000001, entry_size: 00000000 }
SectionHeader { name: 00000011, section_type: 3, flags: 0, address: 00000000, offset: 00003118, size: 00000065, link: 0, info: 0, align: 00000001, entry_size: 00000000 }
```

- After finding the section header which holds all the information (address, size, number of entry) about the symbol table we can parse all the symbols. In this case we have 2 symbols: `echo "$((0x30)) / $((0x18))"`

# Part 6: Loading multiple ELF objects

- An ELF file can be either an executable or a library. When loading an executable, the loader needs to look at the `NEEDED` dynamic entry as well as the `RUNPATH` dynamic entry to locate all the necessary libraries. These need to be loaded in a BFS order.

# Part 7: Dynamic symbol resolution

- Running an executable requires to load various files (the executable file and its dynamic libraries). For each of these files you need to load several segments (pointed to by Program Headers of type `Load`). We need to compute a virtual address range necessary for all segments of each file, such that we can load each file in a distinct address space (ie. from a different base address). We need to be careful to segments that are not page aligned, and add the corresponding padding. Once those ranges are determined, we can map the content of each segment of each file to the memory ranges computed. (Contrarily to what we have done previously, we map the file bytes directly using `MemoryMap` which accepts `MapOption::MapFd` file descriptor while initially we read those in memory and copied those bytes from the heap to the page we mapped for that).

- A trick is that when the object `MemoryMap` goes out of scope the `drop` method actually calls `unmap`. To prevent that we instantiate `MemoryMap` with:
```rust
let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(mem_size, &[])?);
```

- We then need to apply relocations on all files (libraries) in the reverse order of the one we used to load them (opposite to the BFS order where the root is the executable to run).

# Part 8: Dynamic linker speed and correctness

- This is a refactoring part.

- The only thing we changed is to take into account executables with a `.bss` section which holds uninitialized data that contribute to the program's memory image size. By definition, the system initializes the data with zeros when the program begins to run. The section occupies no file space. We need to make sure we zero out the bits beyond the file size (up to the end of the memory range to which the section is mapped).

# Part 9: GDB scripting and Indirect functions

- Our linker can load C applications that don't rely on `glibc`. We can test that by inlining assembly code (which end up calling `syscall`) inside C code and by compiling through `gcc` with the option `-nodefaultlibs`.

- `glibc` actually has several implementation of C functions depending on the hardware used. To resolve the right implementation when loading the code we need to run some subroutine. To indicate that a Symbol (such as a C function of which implementation depends on the hardware) needs to be resovled through some execution, that symbol is marked of type `STT_GNU_IFUNC` (new symbol type unseen so far).

- We create our own [C program](../playground/ifunc-nolibc.c) using the `ifunc` keyword in the implementation of the `get_msg` function to indicate that the value (ie. the address) of that function will be known at load time after running the `resolve_get_msg` function:
```c
char *get_msg() __attribute__ ((ifunc ("resolve_get_msg")));
```

- In real life we would do that rather to pick some implementation dynamically based on runtime variables (Processor capabilities for example, etc.), but writing such a program allows to simulate what happens when linking to `glibc`. Indeed, since `glibc` features several implementations for the same method this symbol type shows up in the `glibc` code.

- We then try to run it, but prior to that we display how we can extend `gdb` to get more information. Since we use `gdb` against our own linker, `elk`, `gdb` does not read the symbol table of the executable we load through `elk`. Hence we want to extend `gdb` to display details about an address (which file it comes from, location in the file, which section, name of the symbol if matching any).

- We learn that `gdb` is able to source python scripts (ie. it has a python interpreter inside it). In those scripts you can make use of the `gdb` object to automate commands, for example:
```py
pid = gdb.selected_inferior().pid
print("the inferior's PID is %d" % pid)
```

- You can also add `gdb` commands in a python script that you would source with:
```py
class MyCommand(gdb.Command):
    """Help on my command"""

    def __init__(self):
        #todo

    def invoke(self, arg, from_tty):
        #todo
```

- There is also the builtin `add-symbol-file` gdb command which you can use to indicate to gdb to load more symbols from a particular file at a particular address (the address of the symbol table)

- The approach taken in this part is convoluted, we resolve the PID of the program we are running (the pid of `elk <args>`), print the corresponding memory mapping `cat /proc/<pid>/map` and parse the output inside `elk`. We create subcommands in `elk` to resolve the relevant information for a particular address from that data structure built from the memory mappings. We then create a python script which defines gdb command around `elk` and load that python script in `.gdbinit` such that we can run these gdb commands automatically.

- NB: we didn't implement these upgrades in this project, these enhanced capabilities inside gdb are therefore not usable in this project.

- We see that when trying to execute our [C program](../playground/ifunc-nolibc.c) which makes use of `ifunc`, we reach a point when the assembly in `gdb` shows `call <some-address>`. Despite our gdb extensions, no symbol matches `<some-address>`. `<some-address>` actually is the result of the mapping of some address in the `.plt` section.

- PLT stands for Procedure Linkage Table. `function@plt` maps to a code in the PLT which checks if there is an entry for `function` in the `GOT` (Global Offset Table). If there is, it jumps there if not, it will jump to some code in the dynamic loader `ld` (the interpreter marked in the ELF file header, which typically is `ld` is also loaded in memory) which will resolve the symbol and populate the `GOT`.

- This mechanism allows to implement `ifunc`. For symbols of type `STT_GNU_IFUNC` the loader is supposed to run whatever code is referred by `ifunc` (in the [C program](../playground/ifunc-nolibc.c) that is `resolve_get_msg`) which will return the address of the actual function to call in the future, and the loader updates the `GOT` with that returned address.

- In general for any method that is dynamically loaded, the `jmp` points to the address of `function@plt`. This is necessary even if there is only one implementation for `function` (ie. symbols not marked with `STT_GNU_IFUNC`), because we don't know at build time at which location the libraries will be mounted. Hence we need a mechanism to resolve those methods dynamically by using a placeholder, `function@plt`, and a table which maps it to the right address, the `GOT` table. Finding the right address could rely on running some code (like in the `STT_GNU_IFUNC`/`ifunc` case ) or not.

- More on GOT and PLT: https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got

- We need to apply another relocation type so the file address of `function@plt` is not hardcoded in the code but its corresponding virtual address is. Also we instruct in the loader when applying the relocation to first run the function:
```rust
RT::IRelative => unsafe { objrel.addr().set(obj.base + addend); } // applying the relocation, but this will KO because obj.base + added is not the address of `function` (get_msg in the example), but of the ifunc routine (resolve_get_msg in the example) which returns address of `function`
```
into
```rust
 RT::IRelative => unsafe {
    // new! and *very* unsafe!
    let selector: extern "C" fn() -> delf::Addr = std::mem::transmute(obj.base + addend);
    objrel.addr().set(selector()); // runs the ifunc routine which returns the right address to apply in relocations (with ld this it will end up in the GOT table)
},
 ```

- This implies to make the pages RWX when applying relocations (because it could contain some code to be executed, like the one behind `ifunc`) before adjusting protections.

# Part 10: Safer memory-mapped structures

- This part is just a refactoring of some code smells in Rust.

- Where possible the use of `std::mem::transmute` to cast to a pointer (an address) is replaced by regular casts to pointers (which is safe - dereferencing the pointer is not though).

- We can use of the `-> !` syntax to indicate that the `jmp` function will never return, making the compiler saving some instructions to prepare a return address. We also can define type aliases locally turning:
```rust
unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
```
to
```rust
unsafe fn jmp(addr: *const u8) -> ! {
    type EntryPoint = unsafe extern "C" fn() -> !; // the ! indicates no return
    let entry_point: EntryPoint = std::mem::transmute(addr);
    entry_point();
}
```
and then there is no need to add code to satisfy the `main` function which calls `jmp` after the call to `jmp`, Rust understands that if we reach `jmp` we don't care about what is coming after.

- We also rework a piece of code where we want a `struct` to refer to data owned in another `struct` (when loading an object, we want to store all its bytes and we want to include a list of Names which points to those bytes). The trick to make sure Rust compiles is to use `Rc` (reference counters) which will prevent dropping the memory pointed to by the `Rc` if its counter is non zero.
```rust
struct Object {
    map: Rc<Vec<u8>>,
    names: Vec<Name>,
}

struct Name {
    map: Rc<Vec<u8>>,    // bytes of the page, same as Object.map
    range: Range<usize>, // position in the page
}

impl Name {
    fn for_object(obj: &Object, range: Range<usize>) -> Self {
        Self {
            map: obj.map.clone(), // idiomatic way to write this should be Rc::clone(obj.map), because that simply causes the Rc to increment its counter, while usually X.clone() suggests a deep copy (note that obj.map is a reference to the Rc, not the Rc itself, which is the type Rc::clone takes as argument) 
            range,
        }
    }

    fn slice(&self) -> &[u8] {
        &self.map[self.range.clone()]
    }
}
```

- However `Rc` is not thread safe, so we can use `Arc` instead (Atomic Reference counter).

- We then want to have `Name` reference `Object` itself not `Object.map`. When using `Arc` you need to consider in which function you lock the data, because when returning from these functions the lock is automatically released, which prevents you from returning references to that protected data. This can be mitigated by making such function accept closures:
```rust
 fn with_slice<F, T>(&self, mut f: F) -> T
    where
        F: FnMut(&[u8]) -> T,
    {
        f(&self.object.lock().unwrap().map[self.range.clone()])
    }
```

- At some point the author suggests using `RwLock` but he does not use it himself.

- There is a discussion about the use of `Weak` instead of `Rc`, in the final design the `Object` struct is split in 2 structs:
```rust
struct Object {
  // some of the data was split into a new struct
  data: Arc<ObjectData>,
  names: Vec<Name>,
}

// and here's that new struct. It owns the path and the memory contents.
struct ObjectData {
  path: PathBuf,
  map: Vec<u8>,
}

struct Name {
    // this doesn't refer to `Object` aymore
    obj_data: Arc<ObjectData>,
    range: Range<usize>,
}
```

# Part 11: More ELF relocations

- So far we have executed [a binary](../playground/hello-with-extern.asm) written in assembly which refered to some external data and we also run a 1 file [C program](../playground/ifunc-nolibc.c) which mimicked the result of linking the code to `glibc` (which contains symbol of type `STT_GNU_IFUNC` through the use of the `ifunc` keyword).

- In this part we try to run C programs which refers to some external [data](../playground/part-11/data-only/chimera.c) and [functions](../playground/part-11/data-and-functions/chimera.c).

- We start by introducing a reference to external data:
```c
extern int number;
```

- We notice that the assembly code generated (and hence the object code) is different whether we use the `-fPIC` (Position Independent Code) option when compiling with `gcc`:
```asm
movl    number(%rip), %eax          # number(%rip) means address of number + rip, the assembly generated here is relative %rip
movl    %eax, %edi
call    ftl_exit
```
vs (PIC version):
```asm
movq    number@GOTPCREL(%rip), %rax # number@GOTPCREL specifies the offset to the GOT entry for the symbol number from the current code location, 
                                    # the addressing is relative to the PC as well here but it points to another location, 
                                    # the GOT rather than the symbol address directly
movl    (%rax), %eax
movl    %eax, %edi
call    ftl_exit@PLT                # number@PLT specifies the offset to the PLT entry of symbol name from the current code location
```

- In the PIC version, we notice that we first load the address of `number@GOT` which lives inside the `GOT` (Global Offset Table) and points to the address of `number` in the `.text` segment of the library which contains it. However in the non PIC version, `number` is directly referenced in the `.text` segment of the library which contains it (there is no going through the GOT).

- Running the non PIC version:
```
❯ gdb ./chimera-no-pic
GNU gdb (GDB) 14.1
(gdb) break _start
Breakpoint 1 at 0x101c
(gdb) run
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/chimera-no-pic 

Breakpoint 1, 0x000055555555501c in _start ()
(gdb) x/4i $rip
=> 0x55555555501c <_start+4>:   mov    eax,DWORD PTR [rip+0x2fde]        # 0x555555558000 <number>
   0x555555555022 <_start+10>:  mov    edi,eax
   0x555555555024 <_start+12>:  call   0x555555555000 <ftl_exit>
   0x555555555029 <_start+17>:  nop
(gdb) x/1dw 0x555555558000
0x555555558000 <number>:        42
(gdb) 
```

- The loader applies the relocation of type `COPY` which means that at run time the loader copies the value of `number` to location `0x555555554000 + 4000` and the placeholders (`0x0`) pointing to `number` are adjusted with the address `0x555555554000 + 4000`:
```
❯ readelf -r chimera-no-pic  
Relocation section '.rela.dyn' at offset 0x360 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000004000  000100000005 R_X86_64_COPY     0000000000004000 number + 0
```

```
❯ /bin/cat /proc/845605/maps
555555554000-555555555000 r--p 00000000 fd:01 5113556                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera-no-pic
555555555000-555555556000 r-xp 00001000 fd:01 5113556                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera-no-pic
555555556000-555555557000 r--p 00002000 fd:01 5113556                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera-no-pic
555555557000-555555558000 r--p 00002000 fd:01 5113556                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera-no-pic
555555558000-555555559000 rw-p 00000000 00:00 0                          [heap]
7ffff7fc0000-7ffff7fc1000 r--p 00000000 fd:01 5112833                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoonopic.so
7ffff7fc1000-7ffff7fc2000 r--p 00001000 fd:01 5112833                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoonopic.so
7ffff7fc2000-7ffff7fc3000 rw-p 00002000 fd:01 5112833                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoonopic.so
7ffff7fc3000-7ffff7fc5000 rw-p 00000000 00:00 0
7ffff7fc5000-7ffff7fc9000 r--p 00000000 00:00 0                          [vvar]
7ffff7fc9000-7ffff7fcb000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fcb000-7ffff7fcc000 r--p 00000000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7fcc000-7ffff7ff1000 r-xp 00001000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ff1000-7ffff7ffb000 r--p 00026000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ffb000-7ffff7fff000 rw-p 00030000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

- Running the PIC version:
```
❯ gdb ./chimera
GNU gdb (GDB) 14.1
(gdb) break _start
Breakpoint 1 at 0x101c
(gdb) run
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/chimera
Breakpoint 1, 0x000055555555501c in _start ()
(gdb) x/4i $rip
=> 0x55555555501c <_start+4>:   mov    rax,QWORD PTR [rip+0x2fbd]        # 0x555555557fe0  # rax <- data stored at the entry number@GOT inside the GOT, 
                                                                                           # it is an address to the number symbol
   0x555555555023 <_start+11>:  mov    eax,DWORD PTR [rax]                                 # eax <- data stored address of the number symbol in the .data of libfoo (42)
   0x555555555025 <_start+13>:  mov    edi,eax                                             # copy the content of number (42) to edi before calling ftl_exit
   0x555555555027 <_start+15>:  call   0x555555555000 <ftl_exit>
(gdb) x/1xg 0x555555557fe0                        # checking the content at the location number@GOT
0x555555557fe0: 0x00007ffff7fc2000                # value is the address of number
(gdb) x/1dw 0x00007ffff7fc2000                    # checking the content at the address of number
0x7ffff7fc2000 <number>:        42                # value is 42
```

- The address of `number` (mapped in the .data section of `libfoo` - notice the RW flag) is inserted in the `GOT` by the linker at build time. At run time the loader applies the relocation (relocation type `GLOB_DAT`) by inserting the address of `number` (mapped somewhere when mapping `libfoo` in memory) in the GOT:
```
❯ readelf -r chimera       
Relocation section '.rela.dyn' at offset 0x358 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000003fe0  000100000006 R_X86_64_GLOB_DAT 0000000000000000 number + 0

❯ /bin/cat /proc/844298/maps
555555554000-555555555000 r--p 00000000 fd:01 5112767                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera
555555555000-555555556000 r-xp 00001000 fd:01 5112767                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera
555555556000-555555557000 r--p 00002000 fd:01 5112767                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera
555555557000-555555558000 r--p 00002000 fd:01 5112767                    /home/proseau/projects/perso/rust-executable-packer/playground/chimera
7ffff7fc0000-7ffff7fc1000 r--p 00000000 fd:01 5112647                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoo.so
7ffff7fc1000-7ffff7fc2000 r--p 00001000 fd:01 5112647                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoo.so
7ffff7fc2000-7ffff7fc3000 rw-p 00002000 fd:01 5112647                    /home/proseau/projects/perso/rust-executable-packer/playground/libfoo.so
7ffff7fc3000-7ffff7fc5000 rw-p 00000000 00:00 0
7ffff7fc5000-7ffff7fc9000 r--p 00000000 00:00 0                          [vvar]
7ffff7fc9000-7ffff7fcb000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fcb000-7ffff7fcc000 r--p 00000000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7fcc000-7ffff7ff1000 r-xp 00001000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ff1000-7ffff7ffb000 r--p 00026000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ffb000-7ffff7fff000 rw-p 00030000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

- We adjust `elk` for this use case, which is straightforward because all we need to do is write the address of the symbol in `./libfoo.so` inside the `GOT`.

- Recall that the purpose of the `GOT` (and the PLT, which we'll get to later) is to avoid having to relocate the executable segment of an executable (in this case the library `libfoo`). Instead the GOT gets updated, so the .text section can be mapped once for any number of instances of that executable.

- We now try to add an `extern` function, `change_number` inside another shared lib, `libbar`, to the code. We hit a different relocation type, `JUMP_SLOT`:
```
❯ readelf -r chimera             

Relocation section '.rela.dyn' at offset 0x380 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000003fe0  000200000006 R_X86_64_GLOB_DAT 0000000000000000 number + 0

Relocation section '.rela.plt' at offset 0x398 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000004000  000100000007 R_X86_64_JUMP_SLO 0000000000000000 change_number + 0
```

- Let's see how `change_number` is resolved when running the program to understand how the linux loader `ld` behaves with this relocation `JUMP_SLOT`.

- Inside `gdb`:
```
❯ gdb ./chimera
GNU gdb (GDB) 14.1
(No debugging symbols found in ./chimera)
(gdb) break _start
Breakpoint 1 at 0x103c
(gdb) run
Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera 

Breakpoint 1, 0x000055555555503c in _start ()
(gdb) # disas is easier to use than x/5i (decode next 5 instructions)
(gdb) disas
Dump of assembler code for function _start:
   0x0000555555555038 <+0>:     push   rbp
   0x0000555555555039 <+1>:     mov    rbp,rsp
=> 0x000055555555503c <+4>:     mov    eax,0x0
   0x0000555555555041 <+9>:     call   0x555555555010 <change_number@plt>
   0x0000555555555046 <+14>:    mov    rax,QWORD PTR [rip+0x2f93]        # 0x555555557fe0
   0x000055555555504d <+21>:    mov    eax,DWORD PTR [rax]
   0x000055555555504f <+23>:    mov    edi,eax
   0x0000555555555051 <+25>:    call   0x555555555020 <ftl_exit>
   0x0000555555555056 <+30>:    nop
   0x0000555555555057 <+31>:    pop    rbp
   0x0000555555555058 <+32>:    ret
End of assembler dump.
(gdb) # we are about to call change_number@plt (not change_number like in the code!), let's see what the instructions there
(gdb) disas 'change_number@plt'
Dump of assembler code for function change_number@plt:
   0x0000555555555010 <+0>:     jmp    QWORD PTR [rip+0x2fea]        # 0x555555558000 <change_number@got.plt>
   0x0000555555555016 <+6>:     push   0x0
   0x000055555555501b <+11>:    jmp    0x555555555000
End of assembler dump.
(gdb) # we are about to jmp (not call, so we won't return) to the address which is stored at address 0x555555558000. 0x555555558000 is the address of symbol 'change_number@got.plt', what is the content stored at this address?
(gdb) x/1xg 0x555555558000
0x555555558000 <change_number@got.plt>: 0x0000555555555016
(gdb) # 'change_number@got.plt' stores '0x0000555555555016', which is actually the second instruction of 'change_number@plt', so we jump from one instruction of `change_number@plt`  to the next 
(gdb) # This feels like we just tried to check if change_number@plt was resolved, but it was not so by default it lets us move with the rest of the code
(gdb) # Let's step instructions after instruction to check we do stay inside 'change_number@plt'
(gdb) stepi
0x0000555555555041 in _start ()
(gdb) disas
Dump of assembler code for function _start:
   0x0000555555555038 <+0>:     push   rbp
   0x0000555555555039 <+1>:     mov    rbp,rsp
   0x000055555555503c <+4>:     mov    eax,0x0
=> 0x0000555555555041 <+9>:     call   0x555555555010 <change_number@plt>
   0x0000555555555046 <+14>:    mov    rax,QWORD PTR [rip+0x2f93]        # 0x555555557fe0
   0x000055555555504d <+21>:    mov    eax,DWORD PTR [rax]
   0x000055555555504f <+23>:    mov    edi,eax
   0x0000555555555051 <+25>:    call   0x555555555020 <ftl_exit>
   0x0000555555555056 <+30>:    nop
   0x0000555555555057 <+31>:    pop    rbp
   0x0000555555555058 <+32>:    ret
End of assembler dump.
(gdb) stepi
0x0000555555555010 in change_number@plt ()
(gdb) disas
Dump of assembler code for function change_number@plt:
=> 0x0000555555555010 <+0>:     jmp    QWORD PTR [rip+0x2fea]        # 0x555555558000 <change_number@got.plt>
   0x0000555555555016 <+6>:     push   0x0
   0x000055555555501b <+11>:    jmp    0x555555555000
End of assembler dump.
(gdb) stepi
0x0000555555555016 in change_number@plt ()
(gdb) disas
Dump of assembler code for function change_number@plt:
   0x0000555555555010 <+0>:     jmp    QWORD PTR [rip+0x2fea]        # 0x555555558000 <change_number@got.plt>
=> 0x0000555555555016 <+6>:     push   0x0
   0x000055555555501b <+11>:    jmp    0x555555555000
End of assembler dump.
(gdb) # we just moved from one instruction to the next, because 'change_number@got.plt' pointed us to that next instruction at address 0x0000555555555016
(gdb) # we see that we are now going to jump to 0x555555555000 
(gdb) disas 0x555555555000
No function contains specified address.
(gdb) # gdb can't see any symbol there so disas does not work, let's do it manually (NB: using the `elk` part we didn't implemented we can see we are in the `.plt
` section now)
(gdb) x/5i 0x555555555000
   0x555555555000:      push   QWORD PTR [rip+0x2fea]        # 0x555555557ff0
   0x555555555006:      jmp    QWORD PTR [rip+0x2fec]        # 0x555555557ff8
   0x55555555500c:      nop    DWORD PTR [rax+0x0]
   0x555555555010 <change_number@plt>:  jmp    QWORD PTR [rip+0x2fea]        # 0x555555558000 <change_number@got.plt>
=> 0x555555555016 <change_number@plt+6>:        push   0x0
(gdb) # we will be pushing something on the stack (NB: elk debugging functions tell us it is some pointer to the heap), and we see that we then jmp to the address contained in 0x555
555557ff8, let's see what is in that address
(gdb) x/1xg 0x555555557ff8
0x555555557ff8: 0x00007ffff7fdd550
```

- Checking the mapping in memory:
```
❯ /bin/cat /proc/877944/maps
555555554000-555555555000 r--p 00000000 fd:01 5114546                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
555555555000-555555556000 r-xp 00001000 fd:01 5114546                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
555555556000-555555557000 r--p 00002000 fd:01 5114546                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
555555557000-555555558000 r--p 00002000 fd:01 5114546                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
555555558000-555555559000 rw-p 00003000 fd:01 5114546                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
7ffff7fb9000-7ffff7fbc000 rw-p 00000000 00:00 0
7ffff7fbc000-7ffff7fbd000 r--p 00000000 fd:01 5114541                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
7ffff7fbd000-7ffff7fbe000 r-xp 00001000 fd:01 5114541                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
7ffff7fbe000-7ffff7fbf000 r--p 00002000 fd:01 5114541                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
7ffff7fbf000-7ffff7fc0000 r--p 00002000 fd:01 5114541                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
7ffff7fc0000-7ffff7fc1000 r--p 00000000 fd:01 5114539                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
7ffff7fc1000-7ffff7fc2000 r--p 00001000 fd:01 5114539                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
7ffff7fc2000-7ffff7fc3000 rw-p 00002000 fd:01 5114539                    /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libfoo.so
7ffff7fc3000-7ffff7fc5000 rw-p 00000000 00:00 0
7ffff7fc5000-7ffff7fc9000 r--p 00000000 00:00 0                          [vvar]
7ffff7fc9000-7ffff7fcb000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fcb000-7ffff7fcc000 r--p 00000000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7fcc000-7ffff7ff1000 r-xp 00001000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ff1000-7ffff7ffb000 r--p 00026000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ffb000-7ffff7fff000 rw-p 00030000 fd:01 4456581                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

- We see from that mapping that we just jumped to some code inside the Linux loader `ld-linux`. Our hypothesis is that running the code at location `0x00007ffff7fdd550` in the loader will populate `change_number@got.plt` with the address of `change_number` (for now it holds `0x0000555555555016`). In subsequent calls we will then jump from `change_number@plt` to `change_number` inside the memory mapped of `libbar` (using the reference stored at `change_number@got.plt`)

- However on the first run we:
  - jump from `change_number@plt` to the next instruction of `change_number@plt` (because this is where `change_number@got.plt`)
  - jump from `change_number@plt` to the top of the `.plt` section at `0x555555555000` (by the way the `plt` entries like `change_number@plt` are a few bytes below)
  - jump from the top of the `.plt` to some function in `ld-linux-x86-64.so.2` which will populate the GOT with the right reference to `change_number` inside `libbar` 
  - jump back from `ld-linux-x86-64` to `change_number` using the entry just populated in `change_number@got.plt`
  - execute `change_number` (inside libbar) and return to the instructions in `_start` since the return address still has not been modified

To test this hypothesis we will set a breakpoint at `change_number` and examine the value of `change_number@got.plt` (analyzing the instructions at `0x00007ffff7fdd550` is too complex to be understood so let's just see the effects):
```
(gdb) break change_number
Breakpoint 2 at 0x7ffff7fbd004
(gdb) x/1xg 0x555555558000
0x555555558000 <change_number@got.plt>: 0x0000555555555016
(gdb) continue
Continuing.

Breakpoint 2, 0x00007ffff7fbd004 in change_number () from /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/libbar.so
(gdb) x/1xg 0x555555558000
0x555555558000 <change_number@got.plt>: 0x00007ffff7fbd000
(gdb) # after reaching change_number we see that the GOT was populated with 0x00007ffff7fbd000, let's check instructions at this address, they should be those of 'change_number'
(gdb) disas 0x00007ffff7fbd000
Dump of assembler code for function change_number:
   0x00007ffff7fbd000 <+0>:     push   rbp
   0x00007ffff7fbd001 <+1>:     mov    rbp,rsp
=> 0x00007ffff7fbd004 <+4>:     mov    rax,QWORD PTR [rip+0x2fd5]        # 0x7ffff7fbffe0
   0x00007ffff7fbd00b <+11>:    mov    eax,DWORD PTR [rax]
   0x00007ffff7fbd00d <+13>:    lea    edx,[rax+rax*1]
   0x00007ffff7fbd010 <+16>:    mov    rax,QWORD PTR [rip+0x2fc9]        # 0x7ffff7fbffe0
   0x00007ffff7fbd017 <+23>:    mov    DWORD PTR [rax],edx
   0x00007ffff7fbd019 <+25>:    nop
   0x00007ffff7fbd01a <+26>:    pop    rbp
   0x00007ffff7fbd01b <+27>:    ret
End of assembler dump.
```

- NB: It is hard to find the code/symbol that corresponds to where we jumped inside `ld-linux-x86-64.so.2` because the dynamic loader is stripped (to save up size of the executable). Until 2019, ELF files debug information was either baked inside or stripped off. Since 2019, this debug information can be exported to some other file and loaded on demand. If you find such a debug file (should be named `ld-X.XX.so.debug`) on your machine, then you could find out the name of the method called inside `ld-linux-x86-64.so.2` to populate the GOT with the right reference:
```
# grepping on the last bit since the address in the debug file corresponds to the file address and not the virtual addres
> nm /usr/lib/debug/usr/lib/ld-2.32.so.debug | grep d550 
000000000001d550 t _dl_runtime_resolve_xsavec
```
Unfortunately I could not find such a debug file for the `ld` dynamic loader on my machine (the above terminal output is copy pasted and adapted from the article)

- NB: the function `_dl_runtime_resolve_xsavec` does not use regular registers to not override the values the arguments and return address of the function it will end up calling, `change_number` in our example, such that this function can return back to the main execution after the call to `change_number@plt`.

- We conclude the article by verifying that:
  - `_dl_runtime_resolve_xsavec` is called only the first time: we add 3 consecutive calls to `change_number` in the C code and set a breakpoint at the begining of `.plt` with `break *0x555555555000`, we then run the program and enter `continue`, we see that we hit the breakpoint only once and not three times
  - running the binary fails if libbar does not contain a `change_number` function: we rename the content of `change_number` inside `libbar` which we recompile and we see that running `chimera` (with the right runpath and `-l` option allowing to locate `libbar`) fails with: "undefined symbol: change_number"
  - we can force the populating of the `GOT` at load time before jumping to `_start` with `LD_BIND_NOW=1 ./chimera`: we run `LD_BIND_NOW=1 gdb ./chimera` and we set a breakpoint at the begining of `.plt` with `break *0x555555555000` (like earlier), the breakpoint is never hit (meaning we never had to jump to `_dl_runtime_resolve_xsavec`, the GOT table was already populated)

- In the `elk` code, instead of inserting code to locate dynamically the symbol and update the GOT accordingly, we statically resolve all the references prior to jumping to `_start` and update the GOT with the right entry, just like we did for `GLOB_DAT` (basically we implement the behaviour of `ld` with `LD_BIND_NOW=1`):
```rust
match reltype {
    // omitted: other arms
    RT::GlobDat | RT::JumpSlot => unsafe {
        objrel.addr().set(found.value());
    },
}
```

# Part 12: A no_std Rust binary

- We want to understand how the arguments and environment variables are passed to the loader and how they are passed to the entrypoint of an ELF file. If you look in any standard executable, you will see the `_start` function does a few stack manipulations (it updates the `rsp` register) and then calls `__libc_start_main@GLIBC_2.2.5`. Using our `elk` binary as an example:
```
❯ objdump -M intel --disassemble=_start ./target/debug/elk
./target/debug/elk:     file format elf64-x86-64
Disassembly of section .init:
Disassembly of section .plt:
Disassembly of section .plt.got:
Disassembly of section .text:
000000000000eb00 <_start>:
    eb00:       31 ed                   xor    ebp,ebp
    eb02:       49 89 d1                mov    r9,rdx
    eb05:       5e                      pop    rsi
    eb06:       48 89 e2                mov    rdx,rsp
    eb09:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
    eb0d:       50                      push   rax
    eb0e:       54                      push   rsp
    eb0f:       45 31 c0                xor    r8d,r8d
    eb12:       31 c9                   xor    ecx,ecx
    eb14:       48 8d 3d 95 d3 00 00    lea    rdi,[rip+0xd395]         # 1beb0 <main>
    eb1b:       ff 15 3f 83 0b 00       call   QWORD PTR [rip+0xb833f]  # c6e60 <__libc_start_main@GLIBC_2.34>
    eb21:       f4                      hlt
```

- So before `ld` makes the CPU jump to `_start`, the memory is already prepared on the stack with all the information `main` will need. For example, `argc` is already on the stack and moved to the `rsi` register with `pop rsi`, then `rsp` is moved to `rdx` such that `rdx` points to `argv`, etc. Eventually we call `__libc_start_main` which will find its arguments in the registers that the C convention expects to find them on. By the way the signature of `__libc_start_main` is (don't know why `init`, `fini` and `rtld_fini` are not passed like in the example):
```c
int __libc_start_main(
    int (*main)(int, char**, char**),
    int argc,
    char** ubp_av,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void(*stack_end)
);
```

- The article shows a [diagram](./stack-layout.png) illustrating how the Stack should be structured by `ld` before `jmp` to `_start`.

- We want to build a Rust program which prints its arguments without using `libc` at all. Basically we want the resulting executable to be made of one object which does not link to anything, not even `ld` (statically linked). We will use the Rust `libcore` which is a subset of the Rust `libstd` which does not depend on `libc` (`libstd` encompasses `libcore` and depends on `libc`). `libcore` provides the core language features (slices, etc.). However it expects a few symbols to be defined. This is why we need to define a `panic_handler`, and an `eh_personality` (more details in `./misc.md`)

- We also use the `no_mangle` and `naked` annotations which respectively allow to preserve the name of the symbol of the `_start` method (`no_mangle`), and to write a function exclusively in assembly using the `asm!` macro (ie. preventing rustc to add prologue such as setting return address etc.). When using `naked` you should wrap the function (`_start`) with `extern "C"` to avoid a warning which will tell you that the RustC ABI is not supported by naked functions.

- We use `asm!` to implement calls to syscalls without `libc`, we also need to implement the `strlen` method which `libcore` expects to find implemented.

- We manage to build a binary that prints arguments in debug mode but which fails in release mode. This is because initially we forgot to specify in our `asm` inline code which registers are used implicitly (syscalls don't preserve certain registers, they return their value in `rax`, etc.). If we don't do that, LLVM tries to use as much registers as possible to avoid writing and reading values from memory (on the stack), and ends up corrupting the values held in those registers after the syscall returns.
```rust
    asm!(
        "syscall",
        in("rax") syscall_number,
        in("rdi") fd,
        in("rsi") buffer,
        in("rdx") count,
        options(nostack)
    );
```
needs to become:
```rust
    asm!(
        "syscall",
        inout("rax") syscall_number => _, // <- change here
        in("rdi") fd,
        in("rsi") buffer,
        in("rdx") count,
        lateout("rcx") _, // <- is not preserved across the syscall
        lateout("r11") _, // <- is not preserved across the syscall
        options(nostack)
    );
```

- The resulting binary is completely self-contained, it does not link to anything not even the dynamic loader `ld`:
```
❯ ldd ./target/debug/echidna             
        statically linked
```
VS (regular rust executable)
```
❯ ldd elk/target/debug/elk
        linux-vdso.so.1 (0x00007fffbd9bd000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1f1da1a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f1f1dcd1000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f1f1d9ed000)
```

- When running `echidna` we can see that its stack is not set by the dynamic loader `ld` (since it does not refer to it). The setting up of the stack is done by the Kernel following the call to the `execve` syscall. So our `elk` is doing more than `ld` it does both what `execve` and `ld` do. For instance the creation of the memory mapping (the one for the current object executable segments only) is done by `execve` (check `man execve` for details). On Linux, `execve` creates the process data structure, the `pid`, sets up the memory mapping and based on the format of the executable (which most often is `ELF`) resolves a dynamic loader - typically `ld.so` - (or not if it is statically linked) and jumps to the entrypoint of that loader for it to load the shared object in memory and adjust relocations. If it is statically linked, `execve` directly jumps to the entrypoint of the executable.

- We simplify the code by:
  1. implementing the `From` trait for the `PrintArg` enum (we do it for `usize`, u8 slices and fixed size arrays of `u8` - necessary for hardcoded strings)
  2. writing macros to generate the `print(&[x.into(), y.into(), ...])` code

- We also want to use the `slice::starts_with` method (defined in `libcore`) but it relies on the `memcpy` function. In a regular rust application (depending on `libstd`) this is provided by the `libc` crate (which defines a lot of `extern` and links to the system `libc` library - `glibc` on Linux for instance) because `libstd` depends on the `libc` crate. However here we only depend on `libcore` so we can either: 
  - implement our own `memcpy` (or our own `starts_with` since that's all we will use in this case)
  - or ask the compiler to generate it by using the `compiler_builtins` crate which includes a series low level functions implemented through `asm`

- NB: the `compiler_builtins` crate is precisely a crate where `intrinsics` (operations that are built-in the compiler) are ported such that you can compile some rust code against a target that `rustc` does not support yet. It boils down to making `rustc` smaller. When trying to compile without this crate:
```toml
[dependencies]
compiler_builtins = { version = "0.1.113", features = ["mem"] }
```
we get the following error:
```
error: linking with `cc` failed: exit status: 1
  |
  = note: LC_ALL="C" PATH="/home/proseau/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin:/home/proseau/.rustup/toolch
= note: rust-lld: error: undefined symbol: memcmp
      >>> referenced by cmp.rs:92 (/rustc/aa1d4f6826de006b02fed31a718ce4f674203721/library/core/src/slice/cmp.rs:92)
      >>>               /home/proseau/projects/perso/rust-executable-packer/echidna/target/debug/deps/echidna-ae6b012009aef92b.4cbfa6toa57ergtvwoz8vjzuv.rcgu.
o:(_$LT$$u5b$A$u5d$$u20$as$u20$core..slice..cmp..SlicePartialEq$LT$B$GT$$GT$::equal::h66c8d255f5ae7df4)
      collect2: error: ld returned 1 exit status
```
However when including it, compiling of the `compiler_builtins` fails - I could not troubleshoot why (I commented the code that makes its use necessary).

- NB: auxiliary vectors are used to make some kernel information available to the running process in user space (for instance: `AT_SYSINFO` provides the address of where we jump to execute a syscall - it is not present/needed on all architectures, for example it is absent on x86-64, `AT_BASE` provides the base address of the program interpreter). Those are placed in the stack right after the environment variables by the kernel prior to jumping to the entry point of the program. Actually, most of the time the kernel prepares the memory layout and maps amongst other things `ld` which will load all the dynamic libraries. `ld` is the main piece of code which reads the data in auxiliary vectors because `ld` needs some kernel information. Auxiliary vectors are a way to avoid resorting to several syscalls to obtain information it very often needs.

- More details on auxiliary vectors: https://lwn.net/Articles/519085/

- NB: `libc` provides the `getauxval` function to reteive those values from the bottom of the stack. The man page of `getauxval` says:
    ```
    The primary consumer of the information in the auxiliary vector is the
    dynamic linker, ld-linux.so(8). The auxiliary vector is a convenient and
    efficient  shortcut  that allows  the kernel to communicate a certain set
    of standard information that the dynamic linker usually or always needs.
    In some cases, the same information could be obtained by system calls, but
    using the auxiliary vector is cheaper.

    The auxiliary vector resides just above the argument list and environment in
    the process address space.
    ```

- We complete `echidna` by adding code that can print the environment variables and the auxiliary vectors on top of the arguments. We do so by keeping walking the memory starting from the top of the stack (we skip over all the `argv` values and keep going to read environment variables and auxiliary vectors). The argument to `main` which is held in the `rdi` register is populated with the content of the stack pointer `rsp` register. This proves that the `execve` syscall sets up the stack in the described way in the [diagram](./stack-layout.png).
```rust
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() {
    asm!(
        "mov rdi, rsp",
        "call main",
        options(noreturn)
    )
}

unsafe fn main(stack_top: *const u8) {
    let argc = *(stack_top as *const u64);

    todo!();
}
```

- We then update `elk` so it can prepare a stack (arguments, environment variables, auxiliary vectors) prior to `jmp`ing to the entrypoint of the executable we are trying to run, just like `execve` does. For testing, we use `elk` to run `echidna` which, again, is a statically linked binary that just prints the content of its stack "manually" (not using any `libc`'s `getaux` or `getenv` methods, but by walking the memory through pointer manipulation from a given address supposed to be the top of the stack). Since the output from running `echidna` directly (through `execve`) and through `elk` is the same, this proves that we populated the stack properly in `elk` just like `execve` does.

- To populate the data on the stack however, we resort to `std::env` and libc's `getauxval` (cf. NB2) to read `elk`'s own environment variables and auxiliary vectors which we just copy inside a `Vec<u64>` which represents the stack content. That `Vec` which lives in the heap of the `elk` process is then copied on the stack by incrementing the `rsp` register:
```rust
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) {
    asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        ".l1:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}", // we are incrementing the stack pointer here! so the elk's stack is growing
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz .l1",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    )
}
```
Hence the stack of the program executed lives on below `elk`'s stack. Said otherwise, above the stack of the program launched by `elk` there is still `elk`'s stack! (it's all one process).

- NB: When creating the `Vec` that represents the stack content, we only push pointers inside that `Vec` - pointers to Strings for environment variables, arguments. Hence this data lives on the heap of the `elk`'s process, and needs to remain accessible to the program launched by `elk` which will need to access that data. In other words we need to make sure it does not get freed before we launch the program we want to execute through `elk`.

- NB2: Instead of pulling the `libc` crate in order to use `getauxval`, we directly link to libc's `getauxval` directly (we know that the lib `libc` is marked as `NEEDED` for `std` rust application hence those symbols will be resolved at runtime):
```rust
// this is a quick libc binding thrown together (so we don't
// have to pull in the `libc` crate).
pub fn get(typ: AuxType) -> Option<Self> {
    extern "C" {
        // from libc (resolved at runtime by `ld.so` cf. part 11)
        fn getauxval(typ: u64) -> u64;
    }

    unsafe {
        match getauxval(typ as u64) {
            0 => None,
            value => Some(Self { typ, value }),
        }
    }
}
```
This is basically what the `getauxval` function in the `libc` crate does, we just don't pull the whole crate just for one function.

- In the `echidna` binary we don't read auxiliary vectors, args and environment using libc's `getaux`, `getenv` and `getargs`, we just manually walk the memory from one particular address (which is supposed to represent the top of the stack) through pointers manipulations so we are indeed reading the values of this "virtual" stack, otherwise `getenv` and `getaux` would take us to the top of the stack of the currently running process which is `elk`. 

- NB: by construction, the auxiliary vector values copied in the "virtual" stack (which lives on top of the `elk`'s stack) are the same as those at the top of the `elk`'s process stack on which they are sitting. Hence the values are not all correct (for instance the AT_BASE is wrong since it points to `elk`'s base address).

- NB: I don't know how libc's `getaux`, `getenv`, etc. find the top of the stack for a particular process. They obviously can't use `getaux` to get the `AT_BASE` value...

# Part 13: Thread local storage

- Refer to the [Threading in Linux](./misc.md) for more context on threads on Linux and Thread Local Storage.

- NB: The `%rip` register holds the virtual address of the instruction we are currently executing. Transferring control means updating the `%rip` register. On `x86_64` you can't write to `%rip` with a `mov` instruction, you need to use the `jmp`, `call` or `ret` instructions. If you are executing some code in userland, changing control also implies changing from ring 0 to ring 3 (more restrained access to the CPU), updating the the virtual memory mapping from the Kernel's to the process's mapping (with `satp` - the author does not go into details here).

- Processes implement a form of pre-emptive multi-tasking. The Kernel keeps setting a timer interrupt which stops the running process each time the timer interrupt fires. Threads behave the same way. However threads share the same address space (memory), which is not the case of processes.

- NB: an alternative to pre-emptive multi-tasking is cooperative multi-tasking where "co-routines" run until they decide to relinquish control explicitly and give a chance to other co-routines to run.

- To analyze the behaviour of threaded programs we write a small [C program](../playground/part-13/two-threads.c) which spawns 2 threads so we can use `gdb` to inspect it. 

- The TLS of each thread is visible to the other threads because they all share the same address space, but upon switching from one thread to another, the kernel updates the `fs` register with the address of the TLS of the thread about to be scheduled. This [diagram](./thread-data-layout.png) shows a schema of the memory layout.

- NB: Here are some useful commands we use in this `gdb` session:
  - `info reg` shows all registers in gdb
  - `info sharedlibrary`: prints all the shared library mounted linked in the executable
  - `info threads`: shows all running threads
  - `thread X`: switch to inspecting thread X
  - `thread apply all <command>`: runs command for all threads, for instance `info registers`.
  - `set scheduler-locking on`: allows `gdb` to ask the Kernel not to pre-empt the current thread (because we want to inspect it).

- NB: there is a whole explanation about when the segment registers were added to the intel architecture:
  - `%ss` (stack segment, pointer to the stack)
  - `%cs` (code segment, pointer to the code)
  - `%ds` (data segment, pointer to the data)
  - `%es` (extra segment, pointer to extra data, 'e' stands for 'extra').
  - `%fs` (f segment, pointer to more extra data, 'f' comes after 'e').
  - `%gs` (g segment, pointer to still more extra data, 'g' comes after 'f').
  These segment registers were introduced back in the days when the addresses were wider than the data. They would hold the most significant bits of the address and were used to interpret an address based on the type of the instruction executed. Now that addresses and data are the same length (at least 32 bits) and that addresses are wide enough to index into the whole memory, these segment registers became less useful. `%fs` in particular was "recylced" to point to Thread Local Storage (`.tdata` section in the ELF file).

- NB: you lacked the debugging information on your machine for `libpthread`, so I added a call to `pthread_self()` so we could disassemble it from the debugging session.

- However `gdb` cannot show the content of `$fs` (it always shows `0`) but you can access the actual content of the `fs` by looking up the `fs_base` variable:
```
(gdb) thread apply all info registers fs

Thread 3 (Thread 0x7ffff75dc6c0 (LWP 361812) "two-threads"):
fs             0x0                 0

Thread 2 (Thread 0x7ffff7ddd6c0 (LWP 361811) "two-threads"):
fs             0x0                 0

Thread 1 (Thread 0x7ffff7dde740 (LWP 361808) "two-threads"):
fs             0x0                 0
```
vs 
```
(gdb) thread apply all info registers fs_base 

Thread 3 (Thread 0x7ffff75da6c0 (LWP 242979) "two-threads"):
fs_base        0x7ffff75da6c0      140737343497920

Thread 2 (Thread 0x7ffff7ddb6c0 (LWP 242978) "two-threads"):
fs_base        0x7ffff7ddb6c0      140737351890624

Thread 1 (Thread 0x7ffff7ddc740 (LWP 242975) "two-threads"):
fs_base        0x7ffff7ddc740      140737351894848
```

- NB: To find out what is the content of `fs` you can also use the `arch_prctl` system call (since `libc` is already linked in the program [two-threads](../playground/part-13/two-threads) we can just call it inside the `gdb` session):
  ```
  # to avoid to switch thread while debugging
  (gdb) set scheduler-locking on
  # the syntax is print (return_type) function(args), here the return type is an address (*void)
  (gdb) print (void*) pthread_self()
  $5 = (void *) 0x7ffff75dc6c0
  # the syscall function does not put the return type in rax, you need to specify the address directly
  (gdb) print (void) arch_prctl(0x1003, $rsp-0x8)
  $6 = void
  # we read the content manually
  (gdb) x/gx $rsp-0x8
  0x7ffff75dbec8: 0x00007ffff75dc6c0
  ```
  The libc wrapper function `arch_prctl` around the syscall of the same name, takes 2 arguments: the first argument controls whether you want to read from/write to fs/gs (`0x1003`: read fs, `0x1004`: write fs), the second argument (here we used the next address below the stack pointer) indicates the address in memory to write the result to.


- We explored a bit the structure of the [memory layout](./playground/part-13/stack-layout-gdb.txt) by running the [C program](../playground/part-13/two-threads.c) through `gdb`. We observed that indeed the `pthread` struct (we just used `tcbhead_t` debug info to parse the binary data here, but this `tcbhead_t` is the first field of the `pthread` struct) is stored at the address which is stored in the `fs` register. That address also corresponds to the thread ID. We have seen that the local stack is placed a few KB above that address by looking at the `rsp` register (stack pointer) for a given thread. Check the details in `./playground/part-13/stack-layout-gdb.txt`

- We then modify `echidna` to include static (ie. we know their size at compile time) Thread Local Storage values with:
  ```rust
  #![feature(thread_local)]
  
  #[thread_local]
  static mut FOO: u32 = 10;
  #[thread_local]
  static mut BAR: u32 = 100;
  
  #[no_mangle]
  unsafe fn play_with_tls() {
      println!(FOO as usize);
      ...
  }
  ```
  After compiling we see the addition of a new section in the ELF executable:
  ```
  readelf -WS ./target/release/echidna
  There are 16 section headers, starting at offset 0xe98:
  
  Section Headers:
    [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    ...
    [ 9] .tdata            PROGBITS        0000000000002b64 000b64 000008 00 WAT  0   0  4
    ...
  Key to Flags:
    W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
    L (link order), O (extra OS processing required), G (group), T (TLS),
    C (compressed), x (unknown), o (OS specific), E (exclude),
    D (mbind), l (large), p (processor specific)
  ```

- Looking at the content in the ELF file at the `Off` location (offset in the file / `Address` is the position in the binary) we can see the initial thread local data written there:
  ```
  # -s is for seek, -e is for little endian, -g 4 is to group 4 bytes together (32 bits)
  xxd -s $((0xb64) -e -g 4 ./echidna | head -n 3
  ```
  Output shows:
  ```
  ❯ xxd -s $((0xb64) -e -g 4 ./echidna | head -n 1
  00000b64: 0000000a 00000064 00000000 0000001e   ....d...........
  ❯ echo $((0x0000000a)) $((0x00000064))
  10 100
  ```
  and we can see that this data is mounted at run time below the address held in the `$fs` register. Indeed when disasembling the instructions while running `echidna` with gdb:
  ```
  (gdb) b play_with_tls 
  Breakpoint 1 at 0x3207: file src/main.rs, line 170.
  (gdb) run
  Starting program: /home/proseau/projects/perso/rust-executable-packer/echidna/target/debug/echidna 
  
  Breakpoint 1, echidna::play_with_tls () at src/main.rs:170
  170         println!(FOO as usize);
  (gdb) p FOO
  Cannot find thread-local storage for process 814315, executable file /home/proseau/projects/perso/rust-executable-packer/echidna/target/debug/echidna:
  Cannot find thread-local variables on this target
  (gdb) # the above does not work because we didn't link echidna with glibc, and gdb relies on glibc to locate each thread local data - cf. our test lower in two-threads.
  (gdb) disas
  Dump of assembler code for function echidna::play_with_tls:
     0x0000555555557200 <+0>:     sub    rsp,0x1c8
  => 0x0000555555557207 <+7>:     mov    eax,DWORD PTR fs:0xfffffffffffffff8 <- this proves that the fs register is leveraged to store the address of TLS data
  (gdb) # let's see what is at this address, knowing that 0xfffffffffffffff8 is just -8 for 32 bytes values (1 letter = 16 bits, 1/2 byte), and that the actual content held in register fs can be seen by using $fs_base
  (gdb) x/d $fs_base - 8
  0x7ffff7fc2b38: 10
  ```

- We also see that the dynamic loader `ld` creates the right `pthread` struct when running `echidna` directly by looking at run time in `gdb` what the memory looks like around `fs`:
  ```
  ❯ gdb target/debug/echidna 
  (gdb) break play_with_tls 
  Breakpoint 1 at 0x3207: file src/main.rs, line 170.
  (gdb) run
  Starting program: /home/proseau/projects/perso/rust-executable-packer/echidna/target/debug/echidna 

  Breakpoint 1, echidna::play_with_tls () at src/main.rs:170
  170         println!(FOO as usize);
  (gdb) p/x $fs_base
  $3 = 0x7ffff7fc2b40
  (gdb) add-symbol-file ../playground/part-13/output/tcb-head.o 
  add symbol table from file "../playground/part-13/output/tcb-head.o"
  (y or n) y
  Reading symbols from ../playground/part-13/output/tcb-head.o...
  (gdb) # necessary since we are running a Rust program
  (gdb) set language c
  Warning: the current language does not match this frame.
  (gdb) set print pretty on
  (gdb) # We have the same data struct in place at the address stored in $fs_base
  (gdb) p *(tcbhead_t *) $fs_base
  $4 = {
    tcb = 0x7ffff7fc2b40,
    dtv = 0x7ffff7fc34c0,
    self = 0x7ffff7fc2b40,
    multiple_threads = 0,
    gscope_flag = 0,
    sysinfo = 0,
    stack_guard = 17362389950405414400,
    pointer_guard = 12822022463573551165,
    vgetcpu_cache = {0, 0},
    feature_1 = 0,
    __glibc_unused1 = 0,
    __private_tm = {0x0 <t>, 0x0 <t>, 0x0 <t>, 0x0 <t>},
    __private_ss = 0x0 <t>,
    ssp_base = 0,
    __glibc_unused2 = {{{
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }}, {{
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }}, {{
          i = {0, 0, 0, 0}
        }, {
          i = {0, 0, 0, 0}
        }, {
        ...
  ```

- We modify `elk` to do the following:
  - we create an area in memory to store the complete TLS image
  - we write a dummy `tcbhead_t` struct there
  - for all objects `NEEDED` (and the ones they need recurively) we look for the segments of type `TLS` and write those before the `tcbhead_t` (we keep a mapping for each objects for where their `TLS` section is written to)
  - we apply relocations for references to those TLS symbols (it seems to me that we just hardcoded the final address of the symbol by finding the TLS section for of the object this symbol belongs to and adding the the value of the symbol - which is its address relative the start of the `.tdata` section. However I would have expected to write an address relative to the start of `tcbhead_t` hoping that such a symbol would be referenced relatively to `fs`)
  - we set the `fs` register to hold the address of `tcbhead_t`
  NB: honestly this part is a bit hard to follow since I didn't edit `elk` along the way and the writing from the author is pretty confusing

- There is a little detour about how to use different type for each state of the process, when you do Process::new you get a `Process<Initialized>`, then on `Process<Initialized>` you define other read only method and a method that takes you to the next state etc.

# Part 14: In the bowels of glibc

- This part is verbose and hard to follow. 

- It goes into talking about:
  - why we need a heap
  - how does malloc gets initialized

- Its main point is that static executables and static PIE executables have relocations as well but don't have an interpreter. Those relocations are indirect relocations and are processed by `libc` which actually depends on `ld.so`.

- It was a good occasion to summarize all that you learnt about the dynamic loader, ELF relocations, C symbols in those [consolidated notes](./program-execution.md) on this part.
