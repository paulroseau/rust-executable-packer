# Function pointers in C

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
#include <stdio.h> 
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

# nm and readelf

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

# Vec and iterators in Rust

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

# Closures in Rust

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

- By default a closure borrows variable immutably. If you want a closure to make use of the `Clone` capability of a variable in the environment it tries to capture, you still need to add the `move` keyword (just like regular functions take ownership or copy a variable when the "plain" variable (not a reference is passed in the arguments).

- The compiler prefers to capture a closed-over variable by immutable borrow, followed by unique immutable borrow (see below), by mutable borrow, and finally by move. It will pick the first choice of these that is compatible with how the captured variable is used inside the closure body.

# .iter on a Vec

To check, `.iter()` is not defined on `Vec<T>` but on `[T]`. Yet you can use it on a vec... How does the conversion from `Vec<T>` to `[T]` is done?

# Inlining Assembly in C

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

# Note on the "extern" keyword

- Source: https://www.reddit.com/r/rust/comments/17f78mb/what_is_extern_system/

- `extern` is the keyword Rust uses to select calling convention. A calling convention defines how a function is called: where are its arguments (on the stack? in registers? A mix?), in which register or stack location is stored the return address etc. When linking to external code (ie. code you don't compile yourself) it is important to tell the compiler which calling convention the code you link to uses so it can generate the proper binary: place the return address, arguments, etc. in the right registers/memory address (on the stack); store the registers that are caller saved on the stack (ie. which the callee - the called function - could alter), etc.

- So actually `extern` is a linkage modifier that tells the compiler to link to a non-Rust function and generate code for calls using the calling convention appropriate for the ABIs of the operating system. For example `extern "C"` tells Rust to use the calling convention commonly used by C compilers for normal libraries. `extern "system"` picks the convention used by system libraries. On Unix, this is equivalent to `extern "C"`, but on Windows, the calling convention used by system libraries is different from the one used by common C libraries. (The reason for this is that these system libraries tried to maintain compatibility with pre-C code, but their ABI couldn't handle important C features like variadic functions.)

# Functions that never returns

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

# Move values

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

# Panic handler and execption handler personality

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

# no_mangle annotation

- Mangling is when a compiler changes the name we’ve given a function to a different name that contains more information for other parts of the compilation process to consume but is less human readable. Every programming language compiler mangles names slightly differently, so for a Rust function to be callable by other languages, we must disable the Rust compiler's name mangling.

- From [this question](https://stackoverflow.com/questions/1041866/what-is-the-effect-of-extern-c-in-c) on StackOverflow (about `extern` in C++, the same reasoning applies for Rust):
```
Since C++ has overloading of function names and C does not, the C++ compiler cannot just use the function name as a unique id to link to, so it mangles the name by adding information about the arguments. A C compiler does not need to mangle the name since you cannot overload function names in C. When you state that a function has extern "C" linkage in C++, the C++ compiler does not add argument/parameter type information to the name used for linkage.
```

# Const generics

- You can parametrize a type by a reified value of another type (integer, bool or character). For example `[A; 3]` represents fixed size array of length 3 holding values of type `A`. If you want to write some code which applies to all fixed size arrays you would write:
```rust
fn function<A, const N: usize>(array: [A; N]) {
    // ...
}
```

- When defining generic behaviour over types that require evaluation at build time you can use the `const` keyword in your type parameter. Here is another more involved example from https://practice.course.rs/generics-traits/const-generics.html:
```rust
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

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
