# Miscalleneous notes

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
    /* The above line is equivalent of following two 
       void (*fun_ptr)(int); 
       fun_ptr = &fun;  
    */
    (*fun_ptr)(10); 
    return 0; 
} 
```
vs
```c
##include <stdio.h> 
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

## Note on the "extern" keyword in Rust

- Source: https://www.reddit.com/r/rust/comments/17f78mb/what_is_extern_system/

- `extern` is the keyword Rust uses to select calling convention. A calling convention defines how a function is called: where are its arguments (on the stack? in registers? A mix?), in which register or stack location is stored the return address etc. When linking to external code (ie. code you don't compile yourself) it is important to tell the compiler which calling convention the code you link to uses so it can generate the proper binary: place the return address, arguments, etc. in the right registers/memory address (on the stack); store the registers that are caller saved on the stack (ie. which the callee - the called function - could alter), etc.

- So actually `extern` is a linkage modifier that tells the compiler to link to a non-Rust function and generate code for calls using the calling convention appropriate for the ABIs of the operating system. For example `extern "C"` tells Rust to use the calling convention commonly used by C compilers for normal libraries. `extern "system"` picks the convention used by system libraries. On Unix, this is equivalent to `extern "C"`, but on Windows, the calling convention used by system libraries is different from the one used by common C libraries. (The reason for this is that these system libraries tried to maintain compatibility with pre-C code, but their ABI couldn't handle important C features like variadic functions.)

## Functions that never returns in Rust

- A function that "returns" translates actually to machine code that will store the return address (the next location of the PC) inside a register prior to updating the PC. From your notes on Computer Architecture, this translates to the `jalr` instructions from the RISC-V ABI, which we can pseudo-implement in hardware wiring (bluespec) as:
  ```
  jalr rd, 0(rs1)
  // performs
  R[rd] <- pc + 4; // saves the old PC in rd
  pc <- R[rs1] & ~0x01
  ```

- You might not want a function to return, basically making it a `goto`, that is you want the compiler to generate a `jalr x0, 0(rs1)`. To do so in Rust you can use the following syntax (example from the `jmp` function):
```rust
unsafe fn jmp(addr: *const u8) -> ! {
    // spread across two lines for readability
    type EntryPoint = unsafe extern "C" fn() -> !; // the ! indicates no return
    let entry_point: EntryPoint = std::mem::transmute(addr);
    entry_point();
}
...

fn main() -> Result<(), AnyError> {
    ...
    if (...) {
      return Ok(())
    }

    unsafe { jmp(addr) }
    // no need to add code here, Rust understands we will never return, this will compile
}
```

## Move values in Rust

- When returning a value from inside a function, think that you are actually "moving" the value. You can think that the bytes pointed to by their address in memory (some address inside the callee's stack frame) are now referred to by an address in the caller's stack frame AND are copied to some other location on the heap!

- In practice the bytes on the heap might not be copied (the address in the caller's stack frame could be updated to the address that was in the callee's stack frame. However the compiler does not assume that this minimal address manipulation occurs. This probably gives flexibility to the memory deallocator which should kick in (prior/after?) returning: it could be more beneficial to copy wipe out the memory pointed by variables local to the callee's scope and copy the bytes of the moved variable to some other location to compact the heap, or not.

- Hence this does not compile, because Rust can see that `res.slice_of_vec` is assigned a value `&res.vec[2..3]` which is equal to an address that won't be valid outside of the stack frame of `make_container`.
```rust
struct Container<'a> {
    vec: Vec<u8>,
    slice_of_vec: Option<&'a [u8]>,
}

fn test() 
    let make_container = || {
        let vec = vec![1, 2, 3, 4, 5];
        let mut res = Container { // <- here res's address is on the stack frame of the make_container closure
            vec,
            slice_of_vec: None,
        };
        res.slice_of_vec = Some(&res.vec[2..3]); // <- slice_of_vec is set here to an address in that stack frame (a new address 0xabc because we are using a reference, but that new address points to the same bytes as res.vec address does, however the compiler does not know that...)
        res // <- moving res out !
    };

    let a = make_container(); // res bytes are now pointed to by another address, the address of a (which owns them). Also at this point a.slice_of_vec (which is worth 0xabc) is equal to an address that is no longer considered valid, even though it is still pointing to the same bytes as before (the compiler does not see that, it just sees that the reference points to data that was moved and hence could have been copied elsewhere on the heap).
```

## Panic handler and execption handler personality

- Sources:
  - the Rust book: https://doc.rust-lang.org/book/ch09-01-unrecoverable-errors-with-panic.html
  - https://rustc-dev-guide.rust-lang.org/panic-implementation.html
  - LLVM documentation on exception handling: https://llvm.org/docs/ExceptionHandling.html
  - https://nrc.github.io/error-docs/intro.html
  - source code of rustc: 
    - https://github.com/rust-lang/rust/tree/master/library/panic_abort
    - https://github.com/rust-lang/rust/tree/master/library/panic_unwind

- Supporting "exceptions" for a language refers to the ability to "throw" a result in a function that can be "caught"/"handled" at some higher level (ie. some intermediate stack frame):
```
function a {
  try {
      x();
  } catch {
    exception(E) => print("Error");
  }
}

function x {
  y();
}

function y {
  if (z()) {
    return 1;
  } else {
    throw E("Z is wrong"); <- this will be caught in a, not in x
  }
}
```

- For that you need 2 things:
  1. a search phase: to be able to walk up the stack and check for each calling function if the exception object you threw should be handled there
  2. once the level at which the execption should be caught is identified, the handler needs to run and all the allocated memory in the intermediate stack frames (between where the exception was thrown and the the stack frame where the exception is handled) needs to be released

- One difficulty is that intermediate stack frames can come from other "modules" (ie. another executable, or dynamic library that the linker or the dynamic loader included in the process).

- In Rust, `panic` is implemented as a macro, in `library/core/src/panic.rs` which maps to implementations in `library/core/src/panicking.rs` which itself relies on externally defined implementations (symbol `panic_impl`). These implementations are part of other crates in Rust and can be chosen at build time by specifying this in the `Cargo.toml`. There are 2 implementations, `panic_abort` which calls the `abort` intrinsic function to abort the process, and `panic_unwind` which "unwinds" the stack.

- NB: The intrinsics functions are implemented in `library/core/src/intrinsics.rs` which features just signatures. Those are contained in an `extern "rust_intrinsics"` block which probably instructs the compiler to generate the appropriate binary code with respect to which CPU is used (this is where the compiler probably relies on LLVM representation for those elementary operations: `abort`, `size_of`, `transmute`, inserting barriers to prevent reordering of CPU instructions, etc.)

- `panic_unwind` relies under the hood on platform specific (Linux, Windows) logic, because every platform has their own convention with respect to storing unwinding information for executables. From the documentation (here `module` refers to a binary object - executable, dynamic library):
```
Each module has its own frame unwind info section (usually ".eh_frame"), an unwinder needs to know about all of them in order for unwinding to be able to cross module boundaries.

On some platforms, like Linux, this is achieved by dynamically enumerating currently loaded modules via the dl_iterate_phdr() API and finding all .eh_frame sections.

Others, like Windows, require modules to actively register their unwind info sections by calling __register_frame_info() API at startup. In the latter case it is essential that there is only one copy of the unwinder runtime in the process. This is usually achieved by linking to the dynamic version of the unwind runtime.

Currently Rust uses unwind runtime provided by libgcc.
```

- `libgcc` is a library that `gcc` always assumes it can link the compiled executable to. The code in `libgcc` contains shared code that would be ineficient to inline everywhere as well as auxiliary helper routines and runtime support. Most of the routines in `libgcc` handle arithmetic operations that the target processor cannot perform directly (eg. multiplication). In particular, `libgcc` also includes code to unwind the stack (function `__gnu_unwind_frame`), and Rust binds to it (cf. lower).

- On Linux, the ELF format specifies the sections (`.eh_frame` and `.eh_frame_hdr`) which can be used to register information necessary to unwind the stack. This is the data that the `__gnu_unwind_frame` function in `libgcc` reads.

- Indeed, producing a backtrace is a common operation while debugging. The traditional way of doing it is to code every function like this:
```asm
pushl	%ebp
movl	%esp, %ebp
...
popl	%ebp
ret
```
The debugger can then easily fetch the old stack pointer and keep unwinding. This scheme is simple to use and simple to code, even with hand written assembly. However it requires `ebp` to be dedicated as a frame pointer and the unwind info is encoded as executable code. Also not enough information is encoded. When moving up the stack, it would be good to know how to restore registers other than the stack pointer (to further debug precisely). It would also be good to know what was the source language, so that this info could be used for exception handling. This is where the `.eh_frame` comes in. When `gcc` compiles some `C` code for example it stores debugging information or exception handling information there.

- You can customize the panicking behaviour with the `#[panic_handler]` annotation on a function of type `fn(&PanicInfo) -> !`. This is necessary for applications that don't include `libstd` (`#![no_std]` applications) because `libstd` depends on the `panic_abort` and the `panic_unwind` crate, but `libcore` does not. (`#![no_std]` applications don't even have a standard output defined)

- `eh_personality` is a function that can then be linked into the `.eh_frame` which handles exceptions thrown in that binary object (dynamically linked library typically have their own `.eh_frame` section). A default implementation for `eh_personality` is defined in the rust `libstd`. However it is not in `libcore`, so for `no_std` rust apps (which rely only on `libcore`) you need to define one. [libcore doc](https://doc.rust-lang.org/core/)) details that `libcore` expects to find the following symbols: 
  - `memcpy`, `memmove`, `memset`, `memcmp`, `bcmp`, `strlen`: you need to provide your own implementation for those or you can use the [compiler-builtin crates](https://crates.io/crates/compiler_builtins) which enables the rust compiler to generate those functions for you. In the general case, applications depend on `libstd` which depends on `libc` which provides implementation for all these symbols (so they can be resolved)
  - `rust_begin_panic`: this function allows to pass the panic message parameter, it requires the client code to define their own `panic_impl` function. The client code does so by using the `panic_handler` annotation on a function which follows the expected signature. Check the source code in `library/core/src/panicking.rs`:
  ```rust
    // First we define the two main entry points that all panics go through.
    // In the end both are just convenience wrappers around `panic_impl`.

    pub const fn panic_fmt(fmt: fmt::Arguments<'_>) -> ! {
    // ...
        // Note from you: 
        // if we decide to abort on panic this is the code that gets run but
        // you still need to provide a panic_handler for this function to compile
        // though (even though it will never get called)
        if cfg!(feature = "panic_immediate_abort") {
            super::intrinsics::abort()
        }

        // NOTE This function never crosses the FFI boundary; it's a Rust-to-Rust call
        // that gets resolved to the `#[panic_handler]` function.
        extern "Rust" {
            #[lang = "panic_impl"]
            fn panic_impl(pi: &PanicInfo<'_>) -> !;
        }

        let pi = PanicInfo::new(
            fmt,
            Location::caller(),
            /* can_unwind */ true,
            /* force_no_backtrace */ false,
        );

        // SAFETY: `panic_impl` is defined in safe Rust code and thus is safe to call.
        unsafe { panic_impl(&pi) }
    // ...
    }

    pub const fn panic_nounwind_fmt(fmt: fmt::Arguments<'_>, force_no_backtrace: bool) -> ! {
        // Note from you: implementation is similar with another pi argument
        // ...
    }
  ```
  - `rust_eh_personality`: needs to be defined by specifying the `eh_personality` annotation. In the `library/std/src/sys/personality` several implementation are defined. In particular in `gcc.rs` an implementation that eventually relies on:
  ```rust
    // defined in libgcc
    extern "C" {
        fn __gnu_unwind_frame(
            exception_object: *mut uw::_Unwind_Exception,
            context: *mut uw::_Unwind_Context,
        ) -> uw::_Unwind_Reason_Code;
    }
  ```
  which is defined in `libgcc` which `gcc` always relies on (and `gcc` is used when compiling Rust `libstd`)

## no_mangle annotation

- Mangling is when a compiler changes the name we’ve given a function to a different name that contains more information for other parts of the compilation process to consume but is less human readable. Every programming language compiler mangles names slightly differently, so for a Rust function to be callable by other languages, we must disable the Rust compiler's name mangling.

- From [this question](https://stackoverflow.com/questions/1041866/what-is-the-effect-of-extern-c-in-c) on StackOverflow (about `extern` in C++, the same reasoning applies for Rust):
```
Since C++ has overloading of function names and C does not, the C++ compiler cannot just use the function name as a unique id to link to, so it mangles the name by adding information about the arguments. A C compiler does not need to mangle the name since you cannot overload function names in C. When you state that a function has extern "C" linkage in C++, the C++ compiler does not add argument/parameter type information to the name used for linkage.
```

## Const generics

- You can parametrize a type by a reified value of another type (integer, bool or character). For example `[A; 3]` represents fixed size array of length 3 holding values of type `A`. If you want to write some code which applies to all fixed size arrays you would write:
```rust
fn function<A, const N: usize>(array: [A; N]) {
    // ...
}
```

- When defining generic behaviour over types that require evaluation at build time you can use the `const` keyword in your type parameter. Here is another more involved example from https://practice.course.rs/generics-traits/const-generics.html:
```rust
##![allow(incomplete_features)]
##![feature(generic_const_exprs)]

fn check_size<T>(val: T)
where
    Assert<{ core::mem::size_of::<T>() < 768 }>: IsTrue,
{}

fn main() {
    check_size([0u8; 767]); 
    check_size([0i32; 191]);
    check_size(["hello你好"; 47]); // &str is a string reference, containing a pointer and string length in it, so it takes two word long, in x86-64, 1 word = 8 bytes
    check_size([(); 31].map(|_| "hello你好".to_string()));  // String is a smart pointer struct, it has three fields: pointer, length and capacity, each takes 8 bytes
    check_size(['中'; 191]); // A char takes 4 bytes in Rust
}

pub enum Assert<const CHECK: bool> {}

pub trait IsTrue {}

impl IsTrue for Assert<true> {}
```

- What can go behind a `const T: ???` can be either a literal (an integer, bool or char), or an expression which evaluates to such literal. I believe this expression will be evaluated at runtime.

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

- Note that the "heap" is just another area in virtual memory. It is initialized by `malloc` (for libc application) for the program to make use of this memory such that data written there persists beyond function calls. The Kernel is not aware of any heap, this a userland concept. In particular if you start an application which does not link to `libc` in `gdb`, you will see that there is no `heap` mapping after `info proc mapping`.

- Typically `brk` is only used by `malloc` or some memory allocator which handles whether the `program break` needs to be pushed up or if there is some space left from deallocated objects it can reuse instead. This is how the "heap" gets grown and shrunk.

- Another way to get more memory is also to use `mmap` which "maps" some pages inside the process virtual address space. `mmap` can map already populated pages (by content of a file, or existing memory of another process for example) but you can also use anonymous mappings to just map some new uninitialized pages in the process virtual memory. `malloc` uses `brk` falls back on `mmap` when a new large amount of memory is needed.

- `mmap` is more modern than `brk`, because it was introduced with virtual memory techniques and larger memory space. The reason why `malloc` still uses `brk`/`sbrk` is mainly for historical reasons (`mmap` is not supported on all platforms). `sbrk` could be more lightweight to use even though there are no clear confirmation of that. [This stackoveflow thread](https://stackoverflow.com/questions/34248854/about-sbrk-and-malloc) seems to say that `malloc` implementations mostly relies on `mmap` now. Also `go`'s memory allocator is fully `mmap` based.

## malloc

- Sources:
  - https://stackoverflow.com/questions/2241006/what-are-alternatives-to-malloc-in-c
  - https://stackoverflow.com/questions/10706466/how-does-malloc-work-in-a-multithreaded-environment
  - https://stackoverflow.com/questions/2863519/arena-in-malloc-function
  - [Original Paper by Doug Lea - writer of the first malloc](https://gee.cs.oswego.edu/dl/html/malloc.html)

- `malloc` is the default memory allocator on Unix system (implemented in libc on Linux). All it does is managing a large chunk of memory efficiently, by dividing it in regions and tracking where allocated chunks of memory live so that the callees does not end up overwriting live data.

- On Unix, `malloc` relies on `brk` and `mmap` to allocate pages to "fill up" the memory.

- To keep a pointer on its internal heap data strcture, `malloc` most likely uses a global variable to store the address of the heap's head.

- Global variables of an ELF executable or shared library (in this case libc) end up in the `.data` or `.rodata` sections of the ELF file, which are part of segments which get mapped in memory with their own pages with `RW` or `R` permissions. If such an ELF file is static (it does not include a dynamic section, nor an interpreter) then the compiler will hardcode the address of the global variables in the code because the ELF files prescribes where in virtual memory each section will be mapped. If the ELF file is dynamic, the Kernel has mapped load segments in memory and jumped to the interpreter starting point for the the interpreter (`ld.so`) to apply relocations.

- You could technically have multiple memory allocators in one running program. There would be several "heaps" ie. areas of memory managed independently (even though you would need to make sure those areas of memory never overlap, so you would need to initialize those memory allocator with a range of usable addresses). The start of all those heaps could be stored in global variables if the allocators are not aware of one another, or inside other heaps. You can get creative on how you want to manage your process's memory!

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

## Symbols in an ELF file

- Sources:
  - https://www.youtube.com/watch?v=6XVUIeAaROU
  - https://www.youtube.com/watch?v=E804eTETaQs
  - https://intezer.com/blog/malware-analysis/executable-linkable-format-101-part-2-symbols
  - https://www.cita.utoronto.ca/~merz/intel_c10b/main_cls/mergedProjects/bldaps_cls/cppug_ccl/bldaps_global_symbols_cl.htm

- Symbols are an intermediary representation used by the linker to map variables and function definitions (in C or other programming languages) to assembly addresses.

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
  - calls the `init` function (which is in the `.init` section of your ELF file)
  - calls `main` with the appropriate arguments
  - calls the finalizers (probably function pointers in an array) registered initially
  - calls `exit` with the return value from `main` as a result code

- NB: `init` and `fini` can be useful for setting up profiling. There are dedicated sections in ELF for those functions which live inside a `LOAD` segment with `R-X` permissions

- If you compile a simple static executable (run `make` in `../playground/part-14/hello-world-twice`) you will see they are ~1MB large while the dynamic version is ~10KB large. That is because when compiling with `gcc -static` all the libraries are included in the resulting binary.

- As such the pros and cons of using static compilation:
  - the resulting binary will always run on any machine with the same CPU architecture (eg. x86_64) and Kernel (functions in `libc.so` call syscalls in the end, if you were on windows you would have needed to link against `libc.dll`)
  - the resulting binary is very large, compiling all binaries like this will end up duplicating a lot of the same bytes on disk
  - the resulting binary is very large, running a lot of those binaries will end up duplicating a lot of the same data in memory
  - the use of more memory impairs the benefits of caching (TLB, etc.) because the cache needs to swap in and out many memory addresses and ends up making the applications slower!

- Using dynamic executable allows not only to have smaller executable on disk but also to share all the `R-X` and `R--` sections of shared libraries, maximizing the cache hits!

- With static executable, all the `.text` and `.data` sections of all libraries get mashed up in one big `.text` section and `.data` section at linking time. At load time, we can therefore make use of absolute address to reference any data or function.

- With a dynamic executable, the libraries are `mmap` one after the other at different addresses at load time. (Note: the area for mapped libraries is usually in between the heap and the stack, and grows up just like the heap).

### Dynamic linking building blocks

- Quote:  "Any problem in CS can be solved by adding a level of indirection"

- Dynamic linking relies on the following concepts to add levels of indirection:
  - Global Offset Table (or GOT)
  - Procedure Linkage Table (or PLT)
  - relocation entries
  Those data structure all live inside the built executable or shared object.

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
  - we incur a slow down the first time we try to call the `function@plt`, because we then go through the 3 assembly instructions for that entry in the `.plt`, which takes us to the area just before the first `.plt` entry that points to the loader which then resolves the function and then call it
  - all the other times, the very first assembly instruction at `function@plt` takes us to `function`
  - if the function is never called we will never resolve it (the loader did adjust its `.got.plt` at step 5.b.ii. though, because it is referenced in the code, we don't know at compile time that it will not be called at runtime)

- Remark 2: we cannot use the same technique (using prepared instructions in the `.plt` and resolve the symbols as we need them) for variables, because we cannot `jmp` to variables. We don't know in what kind of assembly instructions these symbols (addresses) will be used (whereas we know symbols representing functions will always be `jmp`ed to, hence we can introduce intermediate `jmp`s)

- Note: For regular executable which link to `libc` (ie. not linked with the `-nostartfiles` `-nodefaultlibs` options) the compiler will create some relocations referring to `libc`, typically a reference to `__libc_start_main`. Actually in the example I ran, the relocation for `__libc_start_main` is of type `R_X86_64_GLOB_DAT` which indicates that in the `_start` assembly code generated, `__libc_start_main` is treated as regular data (even though it will eventually be `jmp`ed to) and will end up in the `.got` (not in the `.got.plt` like most functions):
```
0000000000003fc0  0000000100000006 R_X86_64_GLOB_DAT      0000000000000000 __libc_start_main@GLIBC_2.34 + 0
```
It intereting to see when we `watch *(offset_of_the_executable + 0x3fc0)` in `gdb`, the value in the `.got` will then point to data in a `R-X` segment of `libc` (and not the `RW` or `R` segment which would correspond to areas pointed by the `.data` and `.rodata` sections, like for most `R_X86_64_GLOB_DAT` relocation)

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

- what are the relocations for these guys?
- they have no interp but relocations, what is the deal with that? How are those relocations processed without a relocator. (`ld.so` is one of those and relocates itself for instance, is it the case for all static `.o`)
- indirect relocations vs direct relocations (ifunc)
- indirect relocations (ifunc) needs to be processed after direct relocations

## Functionalities of `ld.so`

- List all the main functionalities implemented by `ld.so`: `dladdr`, `dlstart`, `dlopen`, `dlclose`, `dl_load_lock` and explain why `libc` would need to link against `ld.so`.


## Shared libraries initializers and finalizers

- called with argc, argv, envp -> who does that again? probaby __libc_start_main for an executable, but for dynamic libraries?
