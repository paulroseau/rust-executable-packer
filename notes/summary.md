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
