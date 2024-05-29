# Part1: What's in a Linux executable?

- We write a simple [assembly program](../playground/hello.asm) using `nasm` and make an executable out of it. This program calls the `write` system call and the `exit` system call.

- `xxd` performs and hex dump of a file

- On Linux executables are ELF files. ELF is a binary format. There is a detail of the format of the header of an ELF file.

- We start writing a parser in Rust using:
  - the `nom` parsing library 
  - `derive_try_from_primitive` library which provides a macro to get an enum value from a primitive type (adds a `try_from` constructor with a macro) when the enum is encoded with primitive type
  - `derive_more` library which provides a macro to derive the `Add` and `Sub` trait automatically on some types (the Address type in particular)

- Using `gdb` (`ugdb` is a nicer TUI tool over `gdb`) we can set `breakpoints` in an executable for it to stop at particular lines or set `catchpoints` to catch system calls. Note that `gdb` can show the executable in the AT&T assembly syntax (default) or the Intel assembly syntax.

- When parsing our [assembly program](../playground/hello.asm) we see that the entrypoint is at `0x04001000` and when running it with `gdb` we see that we are indeed jumping to an instruction at address `0x04001000`. However when doing the same on the `/bin/true` program, our parser shows an entrypoint at line `0x00002130` but `gdb` shows that we are starting from `0x7ffff7fd4100`...

- We write a simple [C program](../playground/entry_point.c) which prints the address of the main function and we see it prints something different at each run (after one single compilation so the entry_point field in the ELF file is the same). However the address always ends with `0x...139`.

- The question is: what does the address written in the `entry_point` section of the ELF header actually mean? It seems like:
  1. it is bigger than the size of the executable
  2. it does not necessarily match the actual start of a program such as for `/bin/true` or for our simple [C program](../playground/entry_point.c)

# Part2: Running an executable without exec

- We modify our parsing program to also run the program afterwards.

- We use `ndisasm` (n disasembler) to disassemble our [hello executable](../playground/hello.asm) which takes us back to roughly the original `hello.asm` code. NB: You need to tell `ndisasm` to interpret instructions over 64 bits (`-b 64`), and to skip (`k 0,$((0x1000))`) to the address after the header and irrelevant sections of the ELF file before interpreting the bytes as assembly code (in the case of our executable, we skip to the address `0x1000` - we just poke around to find that address by looking at the content)

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
  2. identify the bytes to start disasembling from with `ndasm` by finding the section containing the entrypoint through the `ProgramHeader` methods and constructor

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

- We inspect [our C compiled program](../playground/entry_point) with `objdump --disasembler-option intel --disassemble-all` (or `objdump -M intel -D`) and we look for that line of code with `0x2eff`, and it shows in the comment what this address corresponds to a call to `__libc_start_main` (which we didn't define):
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
    100a:       48 be 00 30 00 00 00    movabs rsi,0x3000 <- this has changed but still marked as moveabs
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
  - you can instruct `ld` to generate a Position Independent Executable with the option `ld -pie` such that the executable output can be loaded anywhere in memory and work (this commonly used for shared libraries which need to be mapped when running an arbitrary executable (we don't know what address span will be available)
  - some assembly instructions will break a PIE code, in our case we had to replace a `mov` by a `lea`
