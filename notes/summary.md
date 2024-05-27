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

- We modify our parsing application to stop before updating the protection on the pages and before jumping to allow looking at the memory map in more details with `cat /proc/<pid>/maps`. We notice that the kernel "splits" the heap, making a small page executable and leaving the rest with the previous read-only protection:
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
  - we require the OS to allocate a new memory page to the process and we map it at the virtual address pointed to by `virtual_address` (the address that the section pointed to by the program header should end up being mapped to by `exec` - the section is at `offset` in the file):
    ```rust
    let mem_range = program_header.mem_range();
    let len: usize = (mem_range.end - mem_range.start).into();
    let addr: *mut u8 = mem_range.start.0 as _;
    let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
    ```
  NB: we used a crate to get the MemoryMap structure, that create relies on the libc crate underneath (it generates binary code that can be linked to C binary code - the code of libc on Linux, cf. `readelf -d ./target/debug/elk | grep "NEEDED"`)
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
  00400000-00401000 r--p 00000000 00:00 0 <- this is new
  55c3be274000-55c3be27e000 r--p 00000000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be27e000-55c3be2f2000 r-xp 0000a000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  55c3be2f2000-55c3be30e000 r--p 0007e000 fd:01 5115110                    /home/proseau/projects/perso/rust-executable-packer/elk/target/debug/elk
  ...
  ```
  Eventually the program `hello` which uses the `movebs` instruction referring to an address which was not available in the process virtual memory (the code was mapped on the heap) executes properly when jumping there.

At this point we understand that `exec`:
- parses the ELF files
- uses `mmap` (or the internal Kernel equivalent) to map memory pages to the virtual address pointed to by the ELF program header file
- adjusts the protection bits of those pages
