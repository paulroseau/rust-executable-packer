# Miscalleneous notes

- NB: For Rust related notes, refer to your private [notes](https://bitbucket.org/paul_roseau/learning-rust/src/main/)

## Function pointers in C

Source: https://www.geeksforgeeks.org/function-pointer-in-c/

To declare a pointer to a function you need to use `()` to force the application of the `*` operator to the name of the function:
```c
int (*foo)(int) = &main;
```

Also note that, unlike normal pointers:
- a function pointer points to code, not data. Typically a function pointer stores the start of executable code.
- using function pointers does not allocate de-allocate memory

A function's name can also be used to get functions' address. For example, the two programs below are equivalent:
```c
##include <stdio.h>
void fun(int a) {
    printf("Value of a is %d\n", a);
}

int main() {
    void (*fun_ptr)(int) = &fun;
    /* The above line is equivalent to the following two
       void (*fun_ptr)(int);
       fun_ptr = &fun;
    */
    (*fun_ptr)(10);
    return 0;
}
```
vs
```c
#include <stdio.h>
void fun(int a) {
    printf("Value of a is %d\n", a);
}

int main() {
    void (*fun_ptr)(int) = fun;  // & removed
    fun_ptr(10);  // * removed
    return 0;
}
```
Also:
```c
int main() {
  // will all print the same thing
  printf("&main is at %p\n", &main);
  printf("main is at %p\n", main);
  printf("*main is at %p\n", *main);
  printf("**main is at %p\n", **main);
}
```

## nm and readelf

- `nm` reads the `.symtab` section of an ELF file, while `readelf -s` reads both the `.symtab` and the `.dynsym` section.

- When you run `strip <elf-file>` it removes what is not necessary at runtime, that is the `.symtab` (which is informational), but it preserves the `.dynsym`. After you `strip`ed an ELF file, `nm` shows no symbols.

- However `nm -D` reads the dynamic symbols.

- It is better to use `readelf` with the `-W` (wide) option.

- Example:
```
❯ nm entry_point
0000000000003de0 d _DYNAMIC
0000000000003fe8 d _GLOBAL_OFFSET_TABLE_
0000000000002000 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
0000000000002220 r __FRAME_END__
0000000000002120 r __GNU_EH_FRAME_HDR
0000000000004048 D __TMC_END__
000000000000037c r __abi_tag
0000000000004048 B __bss_start
                 w __cxa_finalize@GLIBC_2.2.5
0000000000004030 D __data_start
0000000000001140 t __do_global_dtors_aux
0000000000003dd8 d __do_global_dtors_aux_fini_array_entry
0000000000004038 D __dso_handle
                 U __errno_location@GLIBC_2.2.5
0000000000003dd0 d __frame_dummy_init_array_entry
                 w __gmon_start__
                 U __libc_start_main@GLIBC_2.34
0000000000004048 D _edata
0000000000004050 B _end
0000000000001364 T _fini
0000000000001000 T _init
00000000000010a0 T _start
0000000000001189 T add
0000000000004048 b completed.0
0000000000002008 R constant
0000000000004030 W data_start
00000000000010d0 t deregister_tm_clones
0000000000001180 t frame_dummy
                 U free@GLIBC_2.2.5
0000000000004040 D instructions
000000000000119d T main
                 U malloc@GLIBC_2.2.5
                 U mprotect@GLIBC_2.2.5
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
0000000000001100 t register_tm_clones

❯ nm entry_point | grep "U "
                 U __errno_location@GLIBC_2.2.5
                 U __libc_start_main@GLIBC_2.34
                 U free@GLIBC_2.2.5
                 U malloc@GLIBC_2.2.5
                 U mprotect@GLIBC_2.2.5
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
❯ cp entry_point entry_point_stripped && strip entry_point_stripped

❯ nm entry_point_stripped
nm: entry_point_stripped: no symbols

❯ readelf -Ws ./entry_point_stripped

Symbol table '.dynsym' contains 12 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (3)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __errno_location@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5 (2)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@GLIBC_2.2.5 (2)
    10: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    11: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
```

- All the undefined symbols point to symbols to a particular library

## readelf memo

```sh
# show segements (the loader's view)
readelf -Wl /bin/ls

# show sections (the linker's view)
readelf -WS /bin/ls

# show symbols
readelf -Ws /bin/ls

# show relocations
readelf -Wr /bin/ls

# show dynamic section
readelf -Wd /bin/ls
```

## Vec and iterators in Rust

- Rust automatically adds the `.into_iter()` function implicitly when using a `for` loop over a vector.

- `fn into_iter(self)` comes from the implementation of
```rust
impl<T, A: Allocator> IntoIterator for Vec<T, A> {
    ...
}
```

- When using a for loop with a reference to a vector the implementation returns an immutable iterator which does not own the arguments:
  ```rust
  impl<'a, T, A: Allocator> IntoIterator for &'a Vec<T, A> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
  }
  ```

## Closures in Rust

- Closures get implemented through a struct and an implementation of the `FnOnce`, `FnMut` or `Fn` trait. From [Rust reference](https://doc.rust-lang.org/reference/types/closure.html):
```rust
fn f<F : FnOnce() -> String> (g: F) {
    println!("{}", g());
}

let mut s = String::from("foo");
let t = String::from("bar");

f(|| {
    s += &t;
    s
});
// Prints "foobar".
```

generates a closure type roughly like the following:
```rust
struct Closure<'a> {
    s : String,
    t : &'a String,
}

impl<'a> FnOnce<()> for Closure<'a> {
    type Output = String;
    fn call_once(self) -> String {
        self.s += &*self.t;
        self.s
    }
}
```

so that the call to f works as if it were:

```rust
f(Closure{s: s, t: &t});
```

- By default a closure borrows variable immutably. If you want a closure to make use of the `Clone` capability of a variable in the environment it tries to capture, you still need to add the `move` keyword (just like regular functions take ownership or copy a variable when the "plain" variable - not a reference - is passed in the arguments).

- The compiler prefers to capture a closed-over variable by immutable borrow, followed by unique immutable borrow (see below), by mutable borrow, and finally by move. It will pick the first choice of these that is compatible with how the captured variable is used inside the closure body.

## .iter on a Vec

To check, `.iter()` is not defined on `Vec<T>` but on `[T]`. Yet you can use it on a vec... How does the conversion from `Vec<T>` to `[T]` is done?

## Inlining Assembly in C

- `gcc` understands assembly which can be inlined inside a C program following a particular syntax that looks like:
```c
void ftl_print(char *msg) {
    // this is a little ad-hoc "strlen"
    int len = 0;
    while (msg[len]) {
        len++;
    }

    __asm__ (
            " \
            mov      $1, %%rdi \n\t\
            mov      %[msg], %%rsi \n\t\
            mov      %[len], %%edx \n\t\
            mov      $1, %%rax \n\t\
            syscall"
            // outputs
            :
            // inputs
            : [msg] "r" (msg), [len] "r" (len)
            );
}
```

- The complete documentation is [here](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)

## GDB cheatsheet

- While running a `gdb` session you can run:
  - `starti` to start the executable and stop at the entrypoint
  - `info proc mappings` to show the layout of the executable memory
  - `watch *(0x0123)` to stop as soon as the content at address `0x0123` is changed
  - `catch syscall <name-of-syscall>` to stop each time a syscall is made

## Pretty printing in GDB

- In `gdb` you can call a function that is defined in the inferior (the executable you are currently debugging) or in a shared library that the inferior links to.

- You can print the result of such a function following this syntax:
```
(gdb) print (return_type) function(args)
```
For instance if you are debugging a C program and the signature of the function
is `void* f(int i);` you can do:
```
(gdb) print (void*) f(3)
```
and `gdb` will print the returned address (it formats the result based on its
type so in this case it will print like if you had use `x/gx`).

- If the returned type is a complex struct, you can:
  - write an extra C file with the definition of the struct and a dummy variable so the struct gets recorded in the debug information:
  ```c
  typedef struct
  {
    void* a_pointer;
    int an_integer;
    void* some_padding[8];
  } super_complex_struct;

  // dummy variable so the struct gets recorded in the debug information
  super_complex_struct s;
  ```
  - compile the C file with debug information thanks to the `g` option:
  ```sh
  gcc -c -g super-complex-struct.c # use -g
  ```
  - inside your `gdb` session load the symbol from the object file:
  ```
  (gdb) add-symbol-file ./path/to/super-complex-struct.o
  ```
  - if you were debugging a program written in another language than C (because it linked to `libc` for example and you needed to define a C struct for debugging), switch the language type in the `gdb` session:
  ```
  (gdb) set language c
  ```
  - optionally you can tell `gdb` to print structures with in an indented format rather than on 1 line with:
  ```
  (gdb) set print pretty on
  ```
  - then you can print the content in memory from particular address by casting the value of the address to a pointer to the struct you defined, and dereferencing this pointer:
  ```
  # if the rax register holds a valid address, gdb will interpret the bytes in memory located at that address as a super_complex_struct
  (gdb) print *(super_complex_struct *) $rax
  ```

## Threading in Linux

- Sources:
  - http://stffrdhrn.github.io/hardware/embedded/openrisc/2020/01/19/tls.html
  - https://blog.gistre.epita.fr/posts/odric.roux-paris-2023-01-31/
  - https://chao-tic.github.io/blog/2018/12/25/tls#the-initialisation-of-tcb-or-tls
  - https://jhuopsys.github.io/spring2024/lectures/lecture04.pdf
  - https://stackoverflow.com/questions/15983872/difference-between-user-level-and-kernel-supported-threads
  - https://stackoverflow.com/questions/27581747/pthread-vs-kthread-in-linux-kernel-v2-6
  - https://stackoverflow.com/questions/30377020/on-linux-is-tls-set-up-by-the-kernel-or-by-libc-or-other-language-runtime
  - https://stackoverflow.com/questions/43219214/where-is-the-value-of-the-current-stack-pointer-register-stored-before-context-s
  - https://stackoverflow.com/questions/69170267/how-does-the-stack-work-in-multithreaded-programs-using-pthread
  - https://stackoverflow.com/questions/8244073/thread-control-block-in-linux
  - https://linux-kernel-labs.github.io/refs/heads/master/lectures/processes.html
  - https://codebrowser.dev/glibc/glibc/nptl/pthread_create.c.html#__pthread_create_2_1

- At a high level a thread state is made of a set of registers and some memory representing the state of the execution of a series of instruction. A process is the same thing, plus an address space. While threads of the same process all execute the same program at their own pace and can see the state (ie. the memory) of all the other threads, processes can't do that.

- According to this [course](https://linux-kernel-labs.github.io/refs/heads/master/lectures/processes.html), threads and processes are backed by the same struct in the kernel: a `task_struct`. Creating a new process or thread relies in both case on calling the `clone` syscall with different flags to specify what can be shared and what needs to be duplicated (address space, file descriptors, etc.)

- Each `task_struct` joins a queue and is scheduled following a form of pre-emptive multi-tasking. The Kernel keeps setting a timer interrupt which stops the running task each time the timer interrupt fires. When this happens the Kernel interrupt handler code:
  - saves the registers (`$rip` - Program Counter, `$rsp` - top of the stack, etc.) of the interrupted thread in a Kernel internal structure (the `task_struct`)
  - selects another thread (or process) to run and restores the registers of that thread from its own `task_struct` before transfering control to it (ie. setting the `$rip` through a `jmp`)

- NB: The Kernel is actually multi-threaded, ie. there are several threads running just Kernel code. These are referred as kernel threads, and are in practice just like the other user level threads. There is also a `task_struct` for each kernel thread to hold its state of execution. This [answer](https://stackoverflow.com/questions/15983872/difference-between-user-level-and-kernel-supported-threads) explains it really well:
  ```
  User threads and Kernel threads are exactly the same. (You can see by looking in /proc/ and see that the kernel threads are there too.)

  A User thread is one that executes user-space code. But it can call into kernel space at any time. It's still considered a "User" thread, even though it's executing kernel code at elevated security levels.

  A Kernel thread is one that only runs kernel code and isn't associated with a user-space process. These are like "UNIX daemons", except they are kernel-only daemons. So you could say that the kernel is a multi-threaded program. For example, there is a kernel thread for swap. This forces all swap issues to get "serialized" into a single stream.
  ```

- The reason why threads can be advantageous over processes is because swapping between threads within the same process (or in between kernel threads) is less expensive because the cache for the memory addresses does not need to be flushed. It is useful in context when the task at hand is IO bound for example.

- While threads share the same memory they still need to store some data specific to their own execution. In particular each thread needs to have its own:
  - stack: each thread needs some area in memory to write the values of variables local to the functions it is executing (reminder: part of the state of execution is in the registers which are saved by the kernel, the other part lives in the memory assigned to the thread or process, while the Kernel handles the former, we need some memory exclusive to the thread for the latter)
  - Thread Local Storage (TLS): where global variables (accessible accross functions) but local to each thread can be stored - some sort of heap local to the thread

- On Linux, allocating this "dedicated" memory (it is not private, meaning this area of memory is visible by the other threads because it is in the same process's address space) to each thread relies on the cooperation from the Kernel and the `libc`. For x86_64, the `fs` register (which was a segment register introduced a long time ago and kind of lost its reason to be cf. lower) is used to hold the address of the "origin" of this thread local memory area, meaning each time the Kernel swaps threads, it will update the content of the `fs` register with that address pointing to the thread local data of this thread. The `libc` library creates new threads through the `pthread_create` function which:
  - finds a large enough memory area for the TLS, if need be it calls `mmap` to allocate it
  - finds area for the stack
  - initializes a `pthread` struct and writes it inside that memory area at the address `A`. That `pthread` struct holds a lot of information regarding the execution of the thread:
    - its thread ID appointed by the kernel (which is equal to the address where the `pthread` struct starts being written, in other words it holds a reference to itself)
    - the function that the thread is executing (its entrypoint) and its parameters
    - parameters for the scheduler, whether the user provides the thread with its own stack, etc.
  - calls the `clone` syscall with the right flags and passes the `pthread` struct initiated before as one of the arguments of the `clone` syscall
  The result of the call to `clone` with such arguments is that the address `A` (where the `pthread` struct is written) is placed into `fs` and each time the Kernel switches threads that `fs` register will be updated to hold the address `A` of the next thread to run. This allows the `libc` code that deals with threads to refer to variables respectively to the content of `fs` and hence can execute properly for any threads. For instance here is the code to return the ID of any thread (ie. it is always written 16 bytes after the address stored in `fs`):
   ```
   (gdb) disas pthread_self
   Dump of assembler code for function pthread_self:
      0x00007ffff7e6f910 <+0>:     mov    rax,QWORD PTR fs:0x10
      0x00007ffff7e6f919 <+9>:     ret
   End of assembler dump.
   ```

- NB: pthreads (Posix threads) are actually implemented by `/usr/lib/libpthread.so.0`

- The `pthread` struct is also used later on by `libc` when allocating dynamic objects (ie. if we depend on dynamic libraries which include thread local data that need to be allocated in this Thread Local Storage area). When those shared objects are allocated, typically the .GOT table of the running executable is updated by the dynamic loader to hold the offset of the object relatively to the value held in `fs`. The executable segment of the shared object also refers to the `fs` registers. For example here is the code to get the `errno` variable (which is a thread local value in `libc` that our executable is linking against in this example):
  ```
  11a8:       48 8b 05 29 2e 00 00    mov    rax,QWORD PTR [rip+0x2e29]        # 3fd8 <errno@GLIBC_PRIVATE> -> this points to the GOT
  11af:       64 8b 00                mov    eax,DWORD PTR fs:[rax]
  11b2:       89 c6                   mov    esi,eax
  ```
  and here is the relocation to use to update the GOT after the dynamic loader placed `errno` in the Thread Local Storage (it needs to compute its offset between `errno` and `fs` and update the GOT with that value - note that the dynamic loader places `errno` in the Thread Local Storage of each thread, because it is marked as Thread Local data in the compiled ELF file it is defined in):
  ```
  readelf -Wr twothreads | grep 3fd8
  0000000000003fd8  0000000300000012 R_X86_64_TPOFF64       0000000000000000 errno@GLIBC_PRIVATE + 0
  ```

- Note that there are several memory layouts possible for the TLS, but usually the static local data is allocated just above the address `A` stored in `fs` and so is the stack (which grows towards higher addresses), while the `pthread` struct goes from the address stored in `fs` downwards. You can check details in this [output](../playground/part-13/stack-layout-gdb.txt)

- Finally, here we talked mostly about user threads that are created through `pthread_create`, but even when the binary does not spawn threads through `libpthread.so`, `ld.so` (which is part of `libc`) will create one `pthread` struct and put its address into the `fs` register. It does not do so with the `clone` syscall (because the process is already created prior to running `exec` - creating the memory space and jumping to the dynamic loader - hence there is nothing to `clone`), but through the `arch_prctl` syscall. The `arch_prctl` is a simple syscall which allows to read and write to the segment registers, such as `fs`. For this main thread, the stack also lives much further away from the address of the `pthread` struct compared to the threads spawned by the user through `libpthread` for which their local stack is pretty close to the `pthread` struct.

## Why do we need a heap?

- Data that is stored on the stack is always referenced with respect to the value of the stack pointer `rsp`. Once you call another function, a new stack frame is created, ie. the stack pointer is updated to point beyond all the memory used in the current function, the function arguments, return address are placed on the stack (with respect to this newly updated stack point - `rsp`) and we jump.

- Hence we can only refer to data that was passed in the arguments. More importantly data created in one callee function is lost once that callee function returns, because the `rsp` is brought back up (the stack grows down) leaving the memory under it unreferenced. That data used on the stack by this callee function will get overwritten anytime another function is called.

- Finally it is impossible to have data of arbitrary size (ie. which will grow dynsy) mingled in the middle of the stack, because the structure of the stack is fixed at compile time (this is how values on the stack can be referenced respectively to `rsp`).

## `brk` vs `mmap` syscalls

- Sources:
  - https://stackoverflow.com/questions/6988487/what-does-the-brk-system-call-do
  - https://stackoverflow.com/questions/55768549/in-malloc-why-use-brk-at-all-why-not-just-use-mmap

- `brk` is a system call which updates the `program break` address, from the `man` page:
    ```
    brk() and sbrk() change the location of the program break, which defines the end of the process's data segment (i.e., the program break is the first location  after  the  end of the uninitialized data segment). Increasing the program break has the effect of allocating memory to the process; decreasing the break deallocates memory
    ```

- Trick `sbrk(0)` can be used to return the current value (address) of the program break.

- `brk` is therefore used to allocate more memory to a program. If the address passed to `brk` (or the amount of requested memory passed to `sbrk`) goes beyond the current page, new pages are allocated and mapped contiguously.

- You can pass a positive or negative value to `sbrk`, negative will release some memory.

- In `xv6` `sys_brk` also just updates the current process struct `sz` attribute and if need be allocates a new page and maps it contiguously to the current page where the `program break` is pointing to:
```c
uint64 sys_sbrk(void) {
  int addr, n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int growproc(int n) {
  uint sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n)) == 0) {
      return -1;
    }
  } else if(n < 0) {
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}
```

- Note that the "heap" is just another area in virtual memory. It is initialized by `malloc` (for libc application) for the program to make use of this memory such that data written there persists beyond function calls. The Kernel is not aware of any heap, this is a userland concept. In particular if you start an application which does not link to `libc` in `gdb`, you will see that there is no `heap` mapping after `info proc mapping`.

- Typically `brk` is only used by `malloc` or some memory allocator which handles whether the `program break` needs to be pushed up or if there is some space left from deallocated objects it can reuse instead. This is how the "heap" gets grown and shrunk.

- Another way to get more memory is also to use `mmap` which "maps" some pages inside the process virtual address space. `mmap` can map already populated pages (by content of a file, or existing memory of another process for example) but you can also use anonymous mappings to just map some new uninitialized pages in the process virtual memory. `malloc` uses `brk` falls back on `mmap` when a new large amount of memory is needed.

- `mmap` is more modern than `brk`, because it was introduced with virtual memory techniques and larger memory space. The reason why `malloc` still uses `brk`/`sbrk` is mainly for historical reasons (`mmap` is not supported on all platforms). `sbrk` could be more lightweight to use even though there are no clear confirmation of that. [This stackoveflow thread](https://stackoverflow.com/questions/34248854/about-sbrk-and-malloc) seems to say that `malloc` implementations mostly relies on `mmap` now. Also `go`'s memory allocator is fully `mmap` based.

## malloc

- Sources:
  - https://stackoverflow.com/questions/71413587/why-is-malloc-considered-a-library-call-and-not-a-system-call
  - https://stackoverflow.com/questions/2241006/what-are-alternatives-to-malloc-in-c
  - https://stackoverflow.com/questions/10706466/how-does-malloc-work-in-a-multithreaded-environment
  - https://stackoverflow.com/questions/2863519/arena-in-malloc-function
  - [Original Paper by Doug Lea - writer of the first malloc](https://gee.cs.oswego.edu/dl/html/malloc.html)

```
An operating system typically allocates some memory space for a given process, but how the memory is used after that is up to the process. Using the standard library for things like memory allocation insulates your code from the details of any given operating system, which makes your code a lot more portable. A given implementation of malloc might ultimately make a system call to obtain memory, but whether it does or doesn't or does some of the time is an implementation detail.
```

- `malloc` is the default memory allocator on Unix system. It is not a system call and is implemented in C (in the standard libc on Linux). All it does is managing a large chunk of memory efficiently, by dividing it in regions and tracking where allocated chunks of memory live so that the callees does not end up overwriting live data.

- On Unix, `malloc` relies on the `brk` and `mmap` syscalls to allocate new physical pages to "fill up" the virtual memory.

- To keep a pointer on its internal heap data structure, `malloc` most likely uses a global variable to store the address of the heap's head.

- Global variables of an ELF executable or shared library (in this case libc) end up in the `.data` or `.rodata` sections of the ELF file, which are part of segments which get mapped in memory with their own pages with `RW` or `R` permissions. If such an ELF file is static (it does not include a dynamic section, nor an interpreter) then the compiler will hardcode the address of the global variables in the code because the ELF file prescribes where in virtual memory each section will be mapped. If the ELF file is dynamic, the Kernel has mapped load segments in memory and jumped to the interpreter starting point for the the interpreter (`ld.so`) to apply relocations.

- You could technically have multiple memory allocators in one running program. There would be several "heaps" ie. areas of memory managed independently (even though you would need to make sure those areas of memory never overlap, so you would need to initialize those memory allocator with a range of usable addresses). The start of all those heaps could be stored in global variables, if the allocators are not aware of one another, or inside other heaps. You can get creative on how you want to manage your process's memory!

- Understand that a memory allocator is just a function handling an area of free addresses.

- Remark: if your program does not link into `libc`, no page with the description `heap` will be allocated (you can check this in `gdb`), the OS is completely unaware of the heap, it is a user level concept.

### Multi-threaded environments

- `malloc` uses a data structure which allows to allocate memory independently for many threads.

- From https://stackoverflow.com/questions/10706466/how-does-malloc-work-in-a-multithreaded-environment:
  ```
  glibc 2.15 operates multiple allocation arenas. Each arena has its own lock. When a thread needs to allocate memory, malloc() picks an arena, locks it, and allocates memory from it.
  ```

- https://stackoverflow.com/questions/2863519/arena-in-malloc-function details how `malloc` manages to allocate memory without locking (by trying successively each arena until it finds one that is not locked):
  ```
  In malloc(), a test is made to see if the mutex for current target arena for the current thread is free (trylock). If so then the arena is now locked and the allocation proceeds. If the mutex is busy then each remaining arena is tried in turn and used if the mutex is not busy. In the event that no arena can be locked without blocking, a fresh new arena is created. This arena by definition is not already locked, so the allocation can now proceed without blocking. Lastly, the ID of the arena last used by a thread is retained in thread local storage, and subsequently used as the first arena to try when malloc() is next called by that thread. Therefore all calls to malloc() will proceed without blocking.
  ```
