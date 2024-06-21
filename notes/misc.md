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
