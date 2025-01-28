# How does an ELF executable run

## Intro

- On Linux, executables are written in the ELF binary format. ELF files can be of different types, namely they can be:
    - an executable
    - an object (`.o`) which is a "part" of an executable and which can be bundled with other `.o` to make an executable. This bundling process is called linking
    - a shared object (`.so`) which essentially is a shared library, it is an object which holds some binary code that an executable can link against at run time

- To build such an ELF file you need to write code and compile it (for `C` you would use `gcc`) to get `.o` files and finally link those `.o` files with the linker, `ld`, to get an executable. 

- The resulting executable can be:
  - statically linked: it contains all the binary code necessary to its execution
  - or dynamically linked: parts of the binary code needed is referenced in the ELF file and a special program, called the dynamic linker/loader (`ld.so`) will load those as the executable starts running

- Here are the high-level steps taken to run a statically linked executable:
  - the `execve` syscall is called and the Kernel:
    - creates a process (allocates a memory space)
    - maps the executable load segements in memory
    - allocates a stack
    - `jmp` to the entrypoint of the executable (the `_start` function)
  - the C runtime, which is instructions that run before calling the `main` function (it is written in both assembly and `C` in `libc` and is inserted in the binary at compile time) does the following:
    - runs functions registered in the `init_array` section of the executable passing `argc`, `argv` and `envp` to each of those functions
    - calls the `main` function (it is a convention imposed by the C runtime, it will link against a symbol called `main` that needs to be defined in your code for linking to complete) with `argc`, `argv` and `envp` as arguments
    - once `main` returns, functions registered in the `fini_array` section of
    the ELF file are run
    - the `exit` syscall is called with the return code from `main`

- For a dynamically linked executable, the same as the above happens except:
  - instead of jumping to the entrypoint of the executable, the Kernel jumps to the entrypoint of the dynamic linker (`ld.so`)
  - `ld.so` will start by processing its own relocations which means it will update some of its own instructions while it is being executed (crazy! requires code to be inlined and avoid jumping around)
  - from the the direct relocations of the executable `ld.so` will look for the
  dynamic libraries needed to process those, and `mmap` those dynamic libraries in the process memory
  - `ld.so` will process relocations of each of these dynamic libraries in the reverse order in which they were loaded to finally process the relocations of the running executable. This consists in poplulating each library and the executable's `GOT` and` PLT` which are areas in memory dedicated to insert the address of symbols living in other components of the running program (ie. other `.so` files).
  NB: When doing so `ld.so` processes first the direct relocations and then the indirect relocations, indirect relocations require (running code stored in the component itself, which needs direct relocations to be proecessed to run properly)
  - `ld.so` runs all the functions registered in the `init_array` section of all shared libraries in the reverse order is which they were loaded as well

## Walkthrough of `exec` (from xv6)

- Source: 
  - `git clone git://g.csail.mit.edu/xv6-labs-2020` 
  - https://pdos.csail.mit.edu/6.828/2023/xv6/book-riscv-rev3.pdf 
  (or check [your mirror](git@bitbucket.org:paul_roseau/xv6-labs-2020-mirror.git) the book is on the `master` branch: 

- The `exec` syscall is called (defined in `usys.pl`) through the `ecall` instruction

- An interrupt is triggered which causes:
  - interrupt to be disabled 
  - to jump to kernel mode in the trampoline code in `trampoline.S` (we still are using the user page table). We jump here because the previous time we returned from Kernel mode to user mode through `usertrapret` (in `trap.c`) (which is also called when returning from `forkret`) we set up `uservec` as the `stvec`.
  - saves the old pc to `sepc`

- `uservec` saves all the registers of the current process in the trapframe (we will override those later but that's what we do generically for all syscalls). The trapframe lies in a dedicated page mapped somewhere in the current process memory when the process was initally created (cf. `proc_pagetable` and `allocproc` in `proc.c`). `uservec` restores the Kernel page table which was saved in the process trapframe as well and jumps to `usertrap` (in `trap.c`) of which the address was also set in the trapframe.

- `usertrap` also saves the old pc (which is right after the `ecall` caused by `exec`) in the trapframe (in xv6 we need to use r_sepc() instruction ). This is generic code and is useless for `exec`, and will also be updated later.

- The `syscall` function (in `syscall.c`) jumps to the `sys_exec` (in `sysfile.c`) which finds the path to the executable and collects argc and argv calls the `exec` function (in `exec.c`).

- The `exec` function:
  - check that the path points to an ELF file (check the magic number)
  - it allocates a new page table for the process with a void trapframe through `proc_pagetable` (in `proc.c`) - right now this is just the root of the future page table
  - it `memset` the memory with the content of the `LOAD` segments of the executable
  - it creates the stack by putting the argv in there, update the process's page table root (we are still in the kernel)
  - it updates the current process data structure:
    - the page table (`p->pagetable`) is now the root of the memory space that was just prepared
    - the stack pointer (`p->trapframe-sp`) points to the stack that was just prepared
    - the process PC (user PC) (`p->trapframe->epc`) which was initially set to the instruction after the `ecall` now points to the entrypoint of the ELF file
  - it frees the old pagetable (the one used so far by the process that called exec, the shell that was forked)

- Once we return from `exec` and back to `syscall`, we are back in `usertrap` which finishes by calling `usertrapret`. `usertrapret` is generic code for every user interrupts and:
  - prepares the trapframe with the kernel pagetable, the usertrap function address, and some info necessary for the next time we jump from usercode in the kernel
  - sets the previous PC special register to the value held in `p->trapframe->epc`
  - calls `userret` code (in `trampoline.S`) passing it the process pagetable (satp). `userret`:
    - switches to the user page table with `csrw satp, a1` 
    - loads register values saved in the process trapframe, write the address of the trapframe address in the scratch register for next time (note the hack is that this page is mapped always to the same virtual address for all processes done in `proc_pagetable`)
  - calls `sret` which will lower the privilege and jump to the address stored in the special previous PC register which we updated in `usertrapret` with `p->trapframe->epc` just before calling `userret`. Also `sret` restores SIE from SPIE (to re-enabling interrupts)

## Symbols in an ELF file

- Sources:
  - https://www.youtube.com/watch?v=6XVUIeAaROU
  - https://www.youtube.com/watch?v=E804eTETaQs
  - https://intezer.com/blog/malware-analysis/executable-linkable-format-101-part-2-symbols
  - https://www.cita.utoronto.ca/~merz/intel_c10b/main_cls/mergedProjects/bldaps_cls/cppug_ccl/bldaps_global_symbols_cl.htm

- In an ELF file symbols are an intermediary representation used by the linker to map variables and function definitions (in C or other programming languages) to assembly addresses.

- A symbol can have 1 or many definitions. For example, for a symbol representing a function, the definition is the area in `.text` section where the function instructions are stored. There could be other definitions in the same `.o` file or in some files that we will link to.

- A symbol can be referenced in the `.o` file it is defined or elsewhere. One of the linker's job is to either decide for each symbol reference which definition to use, ie. which memory address to place in the location where the symbol is referenced (eg. if we are calling a function, what is that function's address - initially the location where the symbol address is expected is filled up by `00` bytes).

- When making an executable out of a series of `.o` files, the C linker goes through each `.o` file one after the other and stores symbol definitions and resolves references by searching through the symbols' definition it has uncovered so far. The linker does only one pass so the order of those `.o` files matters! They need to be in topological order: any `.o` file in the chain can only depend on subsequent `.o` files.

- In a given `.o` or executable file, the symbol table (accessible with `readelf -Ws <file>`) lists all the symbols referenced in this file. Each such symbol has:
  - a type:
    - `OBJECT`: means the symbol refers to some data (in the `.data` or `.rodata` section of this `.o` file or some other to be linked against)
    - `FUNCION`: means the symbol refers to some function (in the `.text` section of this `.o` file or some other to be linked against)
  - a binding which says which definition can be used to resolve the current symbol:
    - `GLOBAL`: means references to this symbol can be resolved either from a symbol defined in the same `.o` file or any other `.o` file to be linked against
    - `WEAK`: is like global but means that the linker can override the resolution if it finds another matching symbol further down the `.o` files chain it is linking against
    - `LOCAL`: means references to this symbol can only be resovled by symbols defined in the same `.o` file
  - a visibility which is relevant for `GLOBAL` and `WEAK` symbols only which says where this definition can be referenced:
    - `DEFAULT`: means that other components can use the symbol definition in that `.o` file (if it is defined here) and that symbol definition may be overridden (preempted) by a definition of the same name in another component.
    - `PROTECTED`: means that other components can use the symbol definition in that `.o` file (if it is defined here) BUT that symbol definition cannot be overridden (preempted) by a definition of the same name in another component.
    - `HIDDEN`: means that other components cannot directly reference the symbol but its address can be passed to other components indirectly (for example, as an argument to a call to a function in another component, or by having its address stored in a data item reference by a function in another component).
    - `INTERNAL`: means that other components cannot reference the symbol either directly or indirectly

## Static binaries VS dynamic binaries

### Sources

- https://www.youtube.com/watch?v=Ss2e6JauS0Y
- https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html

### ELF file structure

- An ELF file presents 2 views:
  - the layout of the executable (or library) bytes in the files in the form of segments
  - the layout of the executable (or library) bytes in memory when this file is executing

- Those 2 byte layouts can be very different, segments that are close by in the executable file can be mapped in various different place in memory.

- Vocab: We will use link time and load time instead of build time and run time sometimes. The linker is typically `ld` (not `ld.so`!!) and the loader typically is the syscall `execve`. The dynamic loader, which is loaded by `execve` and can load more libraries dynamically is typically `ld.so` or `ld-linux.so`.

- ELF file bytes are laid out in contiguous segments, but ELF files also have a notion of sections which are pointers to areas in those segments. Those sections are relevant at link time and help the linker understand how to interpret parts of a `.o` file. For example:
  - the `.data` section points to bytes that store global variables
  - the `.rodata` section points to bytes that store read-only variables
  - the `.bss` section points to data that should be initialized to null bytes (with a length, such as an empty array) and hence should be expanded at load time
  - the `.symtab` points to the table of symbols
  - the `.strtab` points to the string table (to store path to other depedencies for example)
  - the `.text` section points to the bytes that hold the program instructions
  - etc.
  Note that some segments just hold metadata (for example the `DYNAMIC` type segment) and only the segments of type `LOAD` are mounted in memory. In short, sections create a structure relevant to the linker, segments are a unit relevant to the loader. The dynamic loader can at run time make use of such "metadata" sections (such as the relocation sections `.rela.dyn` and `.rela.plt`), even though the bytes they point to are not mapped in memory.

### ELF file interpretation

- When launching a process with the `exec` syscall, the Kernel maps all the segments at the address they are specified in the ELF file (in the simple case, if it is loading shared libraries it can map them from a different offset in memory, but the idea is the same).

- Note that when launching a regular dynamic executable with `gdb`, running the program while breaking at the very first instruction with `starti`, `info proc mappings` will show that the dynamic loader (referred to in the `.INTERP` segment) is already loaded in memory. Hence the `exec` syscall is aware of the ELF format and does treat segments differently according to their type. In this case for the `.INTERP` segment, `exec` looks for the file referenced and maps it in memory and jumps to the entry point of that ELF file (the `ld.so`). Then this file will
    ```
    (gdb) starti
    (gdb) info proc mappings # only your executable and ld.so are loaded in memory
    (gdb) p/x $rip           # you are in ld.so (probably at its entrypoint)
    (gdb) x/30i $rip
    (gdb) x/x _start         # entrypoint of your executable
    (gdb) break _start
    (gdb) continue
    (gdb) info proc mappings # at this point libc has been loaded in memory as well, because relocation for your executable have been processed and required loading its dependencies
    (gdb) p/x $rip           # we are in your executable
    ```

### Building an executable (ELF)

- When compiling C code that depends on `libc` (ie. not linked with the `-nostartfiles` `-nodefaultlibs` options), `gcc` wraps the main function inside a `_start` function, which itself calls `__libc_start_main`, which itself calls your `main`.

- `_start` is a little piece of assembly code (it is specific to your architecture) which is linked into your program to do a bit of bookkeeping and to call `__libc_start_main` which is written in C and is part of the `libc` (so you have it compiled inside `libc.so` against which your program is linked). I don't know why `_start` is architecture specific and cannot be compiled from C. I guess most of what `_start` does is placing the arguments of `__libc_start_main` in the right registers (those arguments are probably made available to `_start` in fixed locations by the `exec` syscall).

- `__libc_start_main()` among other things:
  - registers the finalizers to be called before calling exit
  - initializes the threading subsystem (setup of the Thread Local Storage for the main thread)
  - calls the `init` function (which is in the `.init` section of your ELF file)
  - calls `main` with the appropriate arguments
  - calls the finalizers (probably function pointers in an array) registered initially
  - calls `exit` with the return value from `main` as a result code

- Note: all the C code linked around the `main` function (ie. the instructions from `start` to `main` and after the return value of `main` till `exit` is called the C runtime or CRT)

- NB: `init` and `fini` can be useful for setting up profiling. There are dedicated sections in ELF for those functions which live inside a `LOAD` segment with `R-X` permissions

- If you compile a simple static executable (run `make` in `../playground/part-14/hello-world-twice`) you will see they are ~1MB large while the dynamic version is ~10KB large. That is because when compiling with `gcc -static` all the libraries are included in the resulting binary.

- As such the pros and cons of using static compilation:
  - the resulting binary will always run on any machine with the same CPU architecture (eg. x86_64) and Kernel (functions in `libc.so` call syscalls in the end, if you were on windows you would have needed to link against `libc.dll`)
  - the resulting binary is very large, compiling all binaries like this will end up duplicating a lot of the same bytes on disk
  - the resulting binary is very large, running a lot of those binaries will end up duplicating a lot of the same data in memory
  - the use of more memory impairs the benefits of caching (TLB, etc.) because the cache needs to swap in and out many memory addresses and ends up making the applications slower!

- Using dynamic executable allows not only to have smaller executable on disk but also to share all the `R-X` and `R--` sections of shared libraries, maximizing the cache hits!

- With static executable, all the `.text` and `.data` sections of all libraries get mashed up in one big `.text` section and `.data` section at linking time. At load time, we can therefore make use of absolute address to reference any data or function.

- With a dynamic executable, the libraries are `mmap`ed one after the other at different addresses at load time. (Note: the area for mapped libraries is usually in between the heap and the stack, and grows up just like the heap).

### Dynamic linking building blocks

- Quote: "Any problem in CS can be solved by adding a level of indirection"

- Dynamic linking relies on the following concepts to add levels of indirection:
  - Global Offset Table (or GOT)
  - Procedure Linkage Table (or PLT)
  - relocation entries
  Those data structure all live inside the built executable or shared object. Each program component (executable or `.so` dependencies) have their own.

#### The GOT

- The GOT is a RW memory area for a running executable. It serves the purpose of mapping a symbol references to a symbol definitions in another components. Practically, in each entry of the GOT, there is the address of a symbol definition. The code referencing that symbol can already be generated to reference that GOT entry. During execution that entry can be updated (since it is in RW memory). A subsection of it, the GOT.PLT stores addresses to functions.

#### The PLT

- The PLT is a RX memory area (note that it is not writable!). It has an entry for each function symbol that is called across component boundaries (ie. a symbol `Fun` which is called in the `.text` section of component `A` but of which the definition is in the `.text` section of component `B` - making the component `B` a dependency of `A`). Each entry contains 3 assembly instructions:
    - `jump *GOT[offset+PC]`: a jump to the address stored inside the GOT at `offset` (using PC relative address), ie. the GOT (or more specifically the GOT.PLT) is supposed to hold the actual address of `Fun`. Initially this address just holds the address of the next assembly instruction (the `push function_identifier`) which allows to fall through to the 3rd instruction.
    - `push function_identifier`: push the function identifier (its number from the top of the GOT.PLT) on the stack
    - `jump top_of_PLT`: at the top of the PLT, there are another 3 assembly instructions which:
      - `push top_of_GOT.PLT`: pushes the address of the top of the GOT.PLT on the stack
      - `jump *GOT[offset+PC]`: where `offset + PC` (PC relative address) points to the address of the top the GOT.PLT  where the dynamic loader will write a reference to itself once this component is loaded. Jumping there will allow the dynamic loader to update the `GOT.PLT` entry for `Fun` (the top of `GOT.PLT` and the id of `Fun` is on the stack at this point)
      - `noop`
      This `jump top_of_PLT` is a fallback for the first time the address needs to be resolved. The next times we call `Fun@plt` only the first jump of these 3 assembly instructions will be executed.

- Note that each PLT entry has a corresponding entry in the GOT (this part of the GOT is pointed to by section `.got.plt` - which is a subsection of the `.got`) in the ELF file (after linking). Example of what is already populated at link time (`objdump -D regular-hello`) in the GOT and the PLT:
  ```
    Disassembly of section .plt:

    0000000000001020 <puts@plt-0x10>: <- this is the top of the PLT (ignore the annotation which is meaningless)
        1020:       ff 35 ca 2f 00 00       push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>  <- pushes the GOT address on the stack
        1026:       ff 25 cc 2f 00 00       jmp    *0x2fcc(%rip)       # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10> <- jumps to the dynamic loader (ld.so), for now this is all 0s (check lower) but it will be updated when this is loaded, the interpreter (ld.so) will put a reference to itself once mapped in memory
        102c:       0f 1f 40 00             nopl   0x0(%rax)

    0000000000001030 <puts@plt>:
        1030:       ff 25 ca 2f 00 00       jmp    *0x2fca(%rip)       # 4000 <puts@GLIBC_2.2.5>            <- jumps to puts in libc, 4000 is in the GOT
        1036:       68 00 00 00 00          push   $0x0
        103b:       e9 e0 ff ff ff          jmp    1020 <_init+0x20>

    0000000000001040 <__isoc99_scanf@plt>:
        1040:       ff 25 c2 2f 00 00       jmp    *0x2fc2(%rip)       # 4008 <__isoc99_scanf@GLIBC_2.7>    <- jumps to scanf in libc, 4008 is in the GOT
        1046:       68 01 00 00 00          push   $0x1
        104b:       e9 d0 ff ff ff          jmp    1020 <_init+0x20>
   (cut)
    0000000000003fc0 <.got>: <- .GOT holds uninitialized data until the start of GOT.PLT
            ...

    Disassembly of section .got.plt:

    0000000000003fe8 <_GLOBAL_OFFSET_TABLE_>:
        3fe8:       d0 3d 00 00 00 00       sarb   0x0(%rip)        # 3fee <_GLOBAL_OFFSET_TABLE_+0x6>
            ...
        3ffe:       00 00                   add    %al,(%rax)
        4000:       36 10 00                ss adc %al,(%rax)       <- not to be interpreted as instructions, this is address 0x1036 (proceed with fall back branch)
        4003:       00 00                   add    %al,(%rax)
        4005:       00 00                   add    %al,(%rax)
        4007:       00 46 10                add    %al,0x10(%rsi)   <- not to be interpreted as instructions, this is address 0x1046 (proceed with fall back branch)
        400a:       00 00                   add    %al,(%rax)
        400c:       00 00                   add    %al,(%rax)
        ...
  ```

#### Relocation entries

- Relocation entries are also stored in the ELF file. They are to be read by the dynamic loader to find:
  - which memory address to update (typically an address in the GOT, cf. example below)
  - what value to write in that memory address (this is resolved through the name of the symbol and the library/components it lives in).
  The type of the relocation can specify if any computation needs to be done on the value found before writing it,  if the value to write needs to be computed in a particular way (indirect relocations), etc.
  Example of relocations obtained with `readelf -Wr regular-hello`:
  ```
  Relocation section '.rela.dyn' at offset 0x610 contains 8 entries: <- this is for relocation of data (the functions in here are probably called indirectly, by passing their address to some other function)
      Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
  0000000000003dc0  0000000000000008 R_X86_64_RELATIVE                         1140
  0000000000003dc8  0000000000000008 R_X86_64_RELATIVE                         1100
  0000000000004018  0000000000000008 R_X86_64_RELATIVE                         4018
  0000000000003fc0  0000000100000006 R_X86_64_GLOB_DAT      0000000000000000 __libc_start_main@GLIBC_2.34 + 0
  0000000000003fc8  0000000200000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_deregisterTMCloneTable + 0
  0000000000003fd0  0000000400000006 R_X86_64_GLOB_DAT      0000000000000000 __gmon_start__ + 0
  0000000000003fd8  0000000600000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_registerTMCloneTable + 0
  0000000000003fe0  0000000700000006 R_X86_64_GLOB_DAT      0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0

  Relocation section '.rela.plt' at offset 0x6d0 contains 2 entries: <- this is for relocation of functions
      Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
  0000000000004000  0000000300000007 R_X86_64_JUMP_SLOT     0000000000000000 puts@GLIBC_2.2.5 + 0              <- address in the GOT to update with relative address
  0000000000004008  0000000500000007 R_X86_64_JUMP_SLOT     0000000000000000 __isoc99_scanf@GLIBC_2.7 + 0      <- address in the GOT to update with relative address
  ```

### Dynamic linking

#### Link time

- What the linker can do at build time for dynamically built/compiled executable and libraries is:
  - for all local references (variables and functions that are defined and used inside that component) the complier generates PC relative instructions (the address of the symbol is specified relatively to the position of the PC), so that those instructions can work no matter the address the `.text` section ends up being mapped to
  - for all references to external symbols find which definition to use accross the dependency libraries (there can be many definitions, the resolution uses the symbol binding and visibility parameter as explained above) and create a corresponding relocation entry
  - for each variable symbol to be resolved, it does not do anything else
  - for each function symbol to be resolved, it creates a PLT entry in the `.text` with the 3 assembly instructions (detailed above) and creates an entry at the very top of the GOT.PLT which points to the falls back instruction in the PLT which will call the dynamic loader for it to resolve the symbol and update the GOT at run time (more details in the example above)

- NB: also for shared object (`.so`)  are meant to be mapped in memory at any address (they can be dynamically loaded in various processes). Because their location in the process address space is unknown at build time, the compiler will generate the assembly instructions which are position independant: through the usage of relative addressing (relative to the PC) instead of absolute addressing for example.

- Any dynamically linked executable will include an `.interp` section which points to a string in the `strtab` section. That string is the path of the dynamic loader, (eg. `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`). The dynamic loader is also an executable which understands the ELF format and will incrementally load the various components (the the dynamic libraries the executable depends on) as they are needed.

- Hence the linker only needs the symbol tables and the relocation entries of the libraries the executable depends on (it does not need the actual definitions of those symbols).

#### Load time

1. The Kernel maps the executable `LOAD` segments in memory as well as the `LOAD` segments of the dynamic loader which is pointed to in the `.interp` section. It could be the case that the OS actually just maps the dynamic loader, which would then take care of mapping the executable in memory, but from [this](https://unix.stackexchange.com/questions/611733/what-is-the-linker-and-what-is-the-loader-in-dynamic-linking) it seems that the `exec` syscall does map both:
  ```
  ... the kernel loads the executable itself and its interpreter (the dynamic linker/loader), and the interpreter loads all the other required libraries.
  ```

  Note: If you `gdb ../playground/part-11/data-and-function/chimera`, doing `catch syscall mmap` before instructing to `starti` the executable, will not catch anything, and you will end up with both the executable and the loader mapped in memory. My guess is that the `gdb` hooks are in the loader, which would confirm that `exec` maps both the executable AND the dynamic loader in memory (also if you `strace` you won't see any `mmap` for the executable and the loader because `exec` does not call the `mmap` syscall, it goes directly to the Kernel code without going back to user mode and triggering another user interrupt to handle the `mmap` syscall):
  ```
  (gdb) catch syscall mmap
  Catchpoint 1 (syscall 'mmap' [9])
  (gdb) break _start
  Breakpoint 1 at 0x103c
  (gdb) starti
  Starting program: /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera

  Program stopped.
  0x00007ffff7fe5730 in ?? () from /lib64/ld-linux-x86-64.so.2
  (gdb) info proc mappings
  process 243375
  Mapped address spaces:

         Start Addr           End Addr       Size     Offset  Perms  objfile
     0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
     0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
     0x555555556000     0x555555557000     0x1000     0x2000  r--p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
     0x555555557000     0x555555559000     0x2000     0x2000  rw-p   /home/proseau/projects/perso/rust-executable-packer/playground/part-11/data-and-function/chimera
     0x7ffff7fc5000     0x7ffff7fc9000     0x4000        0x0  r--p   [vvar]
     0x7ffff7fc9000     0x7ffff7fcb000     0x2000        0x0  r-xp   [vdso]
     0x7ffff7fcb000     0x7ffff7fcc000     0x1000        0x0  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
     0x7ffff7fcc000     0x7ffff7ff1000    0x25000     0x1000  r-xp   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
     0x7ffff7ff1000     0x7ffff7ffb000     0xa000    0x26000  r--p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
     0x7ffff7ffb000     0x7ffff7fff000     0x4000    0x30000  rw-p   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
     0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
  ```

2. The Kernel jumps into the dynamic loader entrypoint (and not at `_start` of the executable cf. above `gdb` example)

3. The dynamic loader (`ld-linux.so`) reads all the relocation of the current executable, resolves those relocations by searching through the symbols of the dynamic libraries marked as `NEEDED` in the dynamic section (`readelf -Wd <executable>`, those libraries are searched in the directories referenced in the `RUNPATH` which is also part of the dynamic section)

4. The dynamic loader proceeds recursively for all transitive dependencies (the dynamic libraries on which the ones we just loaded depend on, etc.)

5. Once all the libraries are loaded, the dynamic loader applies the relocation for each component in the reverse order in which they were loaded (starting from the components it loaded last - which do not have any relocations depending on other components). At a high level (they are many types of relocations):
  a. relocations for variables (listed in the `.rela.dyn` section of the component) causes the dynamic loader to update the corresponding entry in the `GOT` (pointed to by the offset of the relocation processed, which points to some area between the start of the `GOT` and the start of the `GOT.PLT`)
  b. relocations for functions (listed in the `.rela.plt` section of the component) causes the dynamic loader to:
    i. update the fallback option pointed to in the `.got.plt` (it is actually the first entry of the `GOT.PLT`). It initially is filled up with `00` but the dynamic loader adds a reference to itself here
    ii. updating each entry in the `GOT.PLT` by adding the offset of where the component was loaded to the current value. The current value for now is set to point back to the next instruction of the `function@plt` such that we jump to the fallback case (the first entry of the `.plt` which jumps to the value stored just before `.got.plt` which was updated in 5.b.i.)
  Example from above:
  ```
    0000000000003fe8 <_GLOBAL_OFFSET_TABLE_>:
        3fe8:       d0 3d 00 00 00 00       sarb   0x0(%rip)        # 3fee <_GLOBAL_OFFSET_TABLE_+0x6> <- those 00 are replaced to allow the PC relative addressing at the top of the PLT to point to dynamic loader code
            ...
        3ffe:       00 00                   add    %al,(%rax)
        4000:       36 10 00                ss adc %al,(%rax)       <- 0x1036 is transformed in 0x555555554000 + 0x1036 if that component was mapped at 0x555555554000
        4003:       00 00                   add    %al,(%rax)
        4005:       00 00                   add    %al,(%rax)
        4007:       00 46 10                add    %al,0x10(%rsi)   <- 0x1046 is transformed in 0x555555554000 + 0x1046 if that component was mapped at 0x555555554000
        400a:       00 00                   add    %al,(%rax)
        400c:       00 00                   add    %al,(%rax)
  ```

6. The dynamic loader jumps to the `_start` of the executable

7. As it runs the executable will call functions in the `.plt` (`function@plt`) which the first time will jump into the dynamic loader to resolve the reference to the symbol of `function` and update the `.got.plt` entry accordingly. The following times, `function@plt` will directly jump to `function`.

- Remark 1: with this interaction between the `.plt`, the dynamic loader and the `.got.plt` we are making the common case fast:
  - we incur a slow down the first time we try to call the `function@plt`, because we then go through the 3 assembly instructions for that entry in the `.plt`, which takes us to the first `.plt` entry that points to the dynamic loader (`ld.so`) which then resolves the function, updates the `.got.plt`, and then calls it
  - all the other times, the very first assembly instruction in `function@plt` `jmp`s straight to `function`
  - if the function is never called we will never resolve it (the loader did adjust its `.got.plt` at step 5.b.ii. though, because it is referenced in the code, we don't know at compile time that it will not be called at runtime)

- Remark 2: we cannot use the same technique (using prepared instructions in the `.plt` and resolve the symbols as we need them) for variables, because we cannot `jmp` to variables. We don't know in what kind of assembly instructions these symbols (addresses) will be used (whereas we know symbols representing functions will always be `jmp`ed to, hence we can introduce intermediate `jmp`s)

- Remark 3: there is a type of relocations which is called indirect. This type of relocations allows to reference some function (stored in the executable itself or in a dependent library) to run to resolve the symbol definition (typical use case is to resolve the best implementation depending on the architecture). In C this is done with `ifunc` keyword (cf. [this example](../playground/part-9/ifunc-nolibc.c)). Basically the loader will run this function which will return an address `A` and update the relocation offset (the symbol reference) with the value `A` (the address of the symbol definition to use during execution). For that code to run without issues, the dynamic loader makes sure to process the direct relocations (the ones for which the dynamic loader can process on its own without jumping back to any of the program's components code) before processing the indirect relocations.

- NB: For regular executable which link to `libc` (ie. not linked with the `-nostartfiles` `-nodefaultlibs` options) the compiler will create some relocations referring to `libc`, typically a reference to `__libc_start_main`. Actually in the example I ran, the relocation for `__libc_start_main` is of type `R_X86_64_GLOB_DAT` which indicates that in the `_start` assembly code generated, `__libc_start_main` is treated as regular data (even though it is the address of a function and as such will eventually be used in a `jmp` instruction) and will end up in the `.got` (not in the `.got.plt` like most functions):
```
0000000000003fc0  0000000100000006 R_X86_64_GLOB_DAT      0000000000000000 __libc_start_main@GLIBC_2.34 + 0
```
  It is intereting to see when we `watch *(offset_of_the_executable + 0x3fc0)` in `gdb`, the updated value in the `.got` will then point to data in a `R-X` segment of `libc` (and not the `RW` or `R` segment which would correspond to areas pointed by the `.data` and `.rodata` sections, like for most `R_X86_64_GLOB_DAT` relocation)

### Full example

- Run:
    ```sh
    cd ../playground/part-11/data-and-function/
    # Check the sections in chimera, and its dependencies, pay attention to the .got and .got.plt locations
    readelf -WS chimera
    readelf -WS libbar.so
    readelf -WS libfoo.so

    # Check relocations for all components
    readelf -Wr chimera
    readelf -Wr libbar.so
    readelf -Wr libfoo.so

    # Launch GDB
    gdb ../playground/part-11/data-and-function/chimera
    ```

#### Breakpoints to set in GDB

- To see which libs are loaded in which order - here `chimera` depends directly both on `libfoo` (for `number`) and `libbar` (for` change_number`):
```
catch syscall mmap
```

- The 1st break point that will be hit: the GOT of `libbar.so` (`libbar` should be mapped at `0x7ffff7fbf000`) is updated to point to `number` in `libfoo`.
```
watch *(0x7ffff7fbf000 + 0x3fe0)
```
Note: The dynamic loader starts by handling the relocations of `libbar`, before dealing with the relocations of the main executable `chimera`. `libfoo` does not have relocations.

- The 2nd break point that will be hit: the first entry of the `GOT.PLT` of `chimera` will be updated to point to the loader (populates the `PLT` fallback option in `chimera`)
```
watch *(0x555555554000 + 0x3ff8)
```

- The 3rd break point that will be hit: the `GOT` of `chimera` will be updated with a reference to `number` inside `libfoo`.
```
watch *(0x555555554000 + 0x3fe0)
```

- The 4th break point that will be hit: the entry for `change_number` in the `GOT.PLT` of chimera will be updated by adding the offset of `chimera` to the current value (as stored in the ELF file)
```
watch *(0x555555554000 + 0x4000)

# Old value = 4118
# New value = 1431654422
# 0x00007ffff7fd93d4 in ?? () from /lib64/ld-linux-x86-64.so.2
# (gdb) p/x 4118
# $4 = 0x1016
# (gdb) p/x 1431654422
# $5 = 0x55555016
```

- The 5th break point which will be hit will be the start of the program
```
break _start
```

- Finally we revisit the 4th watchpoint and see that the the entry for `change_number` in the `GOT.PLT` of `chimera` will be updated again to point to `change_number` in `libbar`

#### Running the gdb debug session

- Use `starti` to get started and use `continue` and `info proc mappings` along the way to see where things are.

## Relocations for static and static-pie executables

- Source:
  - https://sivachandra.github.io/elf-by-example/relocations.html
  - https://stackoverflow.com/questions/17404672/what-does-r-x86-64-irelativ-mean

- Static executables and static Position Independent Executable ELF files can also have relocations even though they don't have an interpreter.

- Static (non PIE) executables ELF files have relocations to support `ifuncs` (ie. the capability of running a function to resolve the relocation address - this is for example used to find the most efficient implementation based on your architecture)

- ELF file of a statically linked PIE will additional have one specific kind of dynamic relocations. These relocations are required to adjust for the load address (a PIE is loaded at a different address everyone time it runs).

- Those relocations are processed by the C runtime (CRT), which is basically the code linked to the executable before we hit the `main` function. In there the call to `__libc_start_main` will resolve the relocations.

- Implementation wise, it seems that `libc` actually depends on `ld.so` to do this (`ld.so` is part of the `glibc` codebase)
  ```
  ldd /lib/x86_64-linux-gnu/libc.so.6
          /lib64/ld-linux-x86-64.so.2 (0x00007f5498301000)
          linux-vdso.so.1 (0x00007f54982ff000)
  ```
  This allow to not duplicate code, and reuse the functionalities already implemented in the dynamic loader which processes all kinds of relocations for dynamically compiled executables and libraries (including indirect relocations).

- Remark: `ld.so`, which does not link to anything, has some relocations which it relocates itself. In practice `ld.so` moves its own code as it is being executed... This is why the `glibc` code can be hard to read. It is written carefully such that some part can be executed before relocations are processed (through the inlining of other functions for example) 

## Shared libraries initializers and finalizers

- Sources: 
  - https://stackoverflow.com/questions/74297227/what-can-be-called-from-fini-function-of-shared-library
  - https://maskray.me/blog/2021-11-07-init-ctors-init-array
  - https://stackoverflow.com/questions/32700494/executing-init-and-fini

- Executables and shared libraries can declare some initialization and finalization code which gets run respectively before the `main` function gets called and after it returns.

- In practice the initalization code can be one or several functions that the linker will place either in the `.init` section (only 1 function) or in the `.init.array` section of the ELF file. This can be done for either executables or libraries. 

- You can mark those by passing the `-init=<function-name>` and `-fini=<function-name>` options to the linker (from `man ld`):
  ```
   -fini=name
       When creating an ELF executable or shared object, call NAME when the executable or shared object is unloaded, by setting DT_FINI to the address of the
       function.  By default, the linker uses "_fini" as the function to call.
       ...
   -init=name
       When  creating  an ELF executable or shared object, call NAME when the executable or shared object is loaded, by setting DT_INIT to the address of the
       function.  By default, the linker uses "_init" as the function to call.
  ```
  However this is fairly manual, and the runtime can ignore `DT_INIT` and `DT_FINI` for some architecture (cf. lower). In C it is better to specify if functions should run before or after `main` through annotations and let `gcc` and `ld` do the work (cf. https://stackoverflow.com/questions/32700494/executing-init-and-fini)

- At runtime, the dynamic linker will call those functions (for the dependencies) and the C runtime will call those of the executable before calling main like so (cf. https://maskray.me/blog/2021-11-07-init-ctors-init-array):
  ```
  If the executable a depends on b.so and c.so (in order), the glibc ld.so and libc behavior is:

  - ld.so runs c.so:DT_INIT. The crtbegin.o fragment of _init calls .ctors
  - ld.so runs c.so:DT_INIT_ARRAY
  - ld.so runs b.so:DT_INIT. The crtbegin.o fragment of _init calls .ctors
  - ld.so runs b.so:DT_INIT_ARRAY
  - libc_nonshared.a runs a:DT_INIT. The crtbegin.o fragment of _init calls .ctors
  - libc_nonshared.a runs a:DT_INIT_ARRAY
  ```

- `.init` and `.fini` were initially introduced and was then later replaced by `.init.array` and `.fini.array`, but both can co-exist (the order in which they are run is the one described above). For some architecture (RISC-V ABI for example), glibc ignores the old `.init` and `.fini` sections and the functions registered there in the ELF file will be ignored (but it will run the ones in `.init.array` and `.fini.array`).

- Each of those functions are passed `argc`, `argv` and `envp` as arguments. The functions can make use of those or not (but the runtime makes them available).

- The finalization code uses the same mechanism. The linker will place some functions in the `.fini` or (better) in the `.fini.array` sections and glibc (either the dynamic loader or the C runtime code - ie. the code inserted after the return of main and the call to exit) will call these functions (again with some nuances according to the architecture's ABI).

- From `man dlopen`:
  ```
   Initialization and finalization functions
       Shared objects may export functions using the __attribute__((constructor)) and __attribute__((destructor)) function attributes.  Constructor functions are
       executed before dlopen() returns, and destructor functions are executed before dlclose() returns.  A shared object may export  multiple  constructors  and
       destructors,  and priorities can be associated with each function to determine the order in which they are executed.  See the gcc info pages (under "Func‐
       tion attributes") for further information.

       An older method of (partially) achieving the same result is via the use of two special symbols recognized by the linker: _init and _fini.   If  a  dynami‐
       cally  loaded  shared  object  exports a routine named _init(), then that code is executed after loading a shared object, before dlopen() returns.  If the
       shared object exports a routine named _fini(), then that routine is called just before the object is unloaded.  In  this  case,  one  must  avoid  linking
       against the system startup files, which contain default versions of these files; this can be done by using the gcc(1) -nostartfiles command-line option.

       Use  of  _init and _fini is now deprecated in favor of the aforementioned constructors and destructors, which among other advantages, permit multiple ini‐
       tialization and finalization functions to be defined.
  ```

## Functionalities of `ld.so`

- Source:
  - https://unix.stackexchange.com/questions/611730/does-dlopen-performs-dynamic-linking-by-invoking-dynamic-linker-ld-linux-so

- `ld.so` (for x86) or `ld-linux.so` (for x86_64) is the dynamic loader or linker. It can parse ELF files and update the memory space of a running program in multiple ways:
  - based on the dynamic section (`NEEDED` and `RUNPATH` keys for instance) it can find shared libraries to load
  - based on the program headers (the segments) it can call `mmap` on the `LOAD` segements of shared libraries (it could theoretically do so for executables but the running executable ELF file is always loaded through `exec`)
  - based on the relocation section it updates the values of the references of some symbols (by updating the `GOT`, `GOT.PLT` and `PLT` tables of the running executables and its dependent libraries)

- `ld.so` exposes its capabilities of loading and closing dynamic libaries through the `libdl` library against which you can link. For example, you can use the `dlopen` function:
  ```
  dlopen is provided by libdl, but behind the scenes, with the GNU C library implementation at least, the latter relies on symbols provided by ld-linux.so to perform the dynamic linking. If dlopen is called from a dynamically-linked program, ld-linux.so is already loaded, so it uses those symbols directly; if it’s called from a statically-linked program, it tries to load ld-linux.so.
  ```

- For more details on the features that `ld-linux.so` provides, check `man dlopen`, `man dlclose`, `man dladdr`.
