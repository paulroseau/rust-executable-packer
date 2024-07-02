#![no_std]
#![no_main]
#![feature(naked_functions, lang_items)]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::arch::asm;

mod support;
use support::*;

#[lang = "eh_personality"]
fn eh_personality() {}

#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() {
    asm!(
        "mov rdi, rsp",
        "call main",
        options(noreturn)
    )
}

#[no_mangle]
unsafe fn main(stack_top: *const u8) {
    let argc = *(stack_top as *const u64);

    print(&[
        PrintArg::String(b"received "),
        PrintArg::Number(argc as usize),
        PrintArg::String(b" arguments:\n"),
    ]);

    let argv = stack_top.add(8) as *const (*const u8);
    let args = core::slice::from_raw_parts(argv, argc as usize);

    // from_raw_parts returns a &'a [T], so into_iter() yields &T
    // also the size of the data here is size_of::<*const u8>(), which is worth 8 (8 bytes)
    // size_of::<u64>() is also 8 cf. https://doc.rust-lang.org/core/mem/fn.size_of.html (size_of is implemented through compiler intrinsics)
    for &arg in args {
        let arg = core::slice::from_raw_parts(arg, strlen(arg));
        println!(b"- ", arg);
    }

    const ALLOWED_ENV_VARS: [&[u8]; 3] = [b"USER=", b"SHELL=", b"LANG="];
    fn is_env_var_allowed(env_var: &[u8]) -> bool {
        for prefix in &ALLOWED_ENV_VARS {
            if env_var.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    println!(b"environment variables:");

    // pointer.add(nb) moves the pointer by nb x size_of::<T> where the pointer is of type *T
    let mut env_pointer = argv.add(argc as usize + 1);
    let mut filtered_count = 0;

    while !(*env_pointer).is_null() {
        let env_string = *env_pointer;
        let env_string = core::slice::from_raw_parts(env_string, strlen(env_string));
        // START of simpler version because of failing compiler_builtins
        println!(b"- ", env_string);
        env_pointer = env_pointer.add(1);
    }
    // END
    
    // To make use of `starts_with` which relies on memcpy you need to:
    // 1. Replace the above section by the following commented lines
    // 2. Uncomment the compiler_builtins line in the Cargo.toml
    // 3. Troubleshoot why the compilation of `compiler_builtins` currently fails with
    //    failed to run custom build command for `compiler_builtins v0.1.113`
    
        // if is_env_var_allowed(env_string) {
            // println!(b"- ", env_string);
            // env_pointer = env_pointer.add(1);
        // } else {
        //     filtered_count += 1;
        // }
    // }
    // println!(b"(+ ", filtered, b" redacted environment variables)");

    println!(b"auxiliary vectors:");
    // a mutable pointer pointing to read-only AuxiliaryVector
    let mut auxiliary_vector_pointer = env_pointer.add(1) as *const AuxiliaryVector;

    let null_auxiliary_vector = AuxiliaryVector { typ: 0, value: 0 };

    while *auxiliary_vector_pointer != null_auxiliary_vector {
        // cannot use a variable here because this is creating another pointer to the same bytes
        // pointed by auxiliary_vector_pointer and hence the rustc cannot guarantee we
        // won't make a mistake by accessing those bytes through *auxiliary_vector_pointer. So we can't do:
        // let auxiliary_vector = *auxiliary_vector_pointer;
        // and we need to always refer to this data through *auxiliary_vector_pointer
        println!(b"- ", (*auxiliary_vector_pointer).name(), b": ", (*auxiliary_vector_pointer).formatted_value());
        // above cast to *const AuxiliaryVector is important
        // here, otherwise increment would be by 8 bytes only
        auxiliary_vector_pointer = auxiliary_vector_pointer.add(1);
    }

    exit(0);
}

#[derive(PartialEq)]
struct AuxiliaryVector {
    typ: u64,
    value: u64,
}

impl AuxiliaryVector {
    fn name(&self) -> &[u8] {
        match self.typ {
            2 => b"AT_EXECFD",
            3 => b"AT_PHDR",
            4 => b"AT_PHENT",
            5 => b"AT_PHNUM",
            6 => b"AT_PAGESZ",
            7 => b"AT_BASE",
            8 => b"AT_FLAGS",
            9 => b"AT_ENTRY",
            11 => b"AT_UID",
            12 => b"AT_EUID",
            13 => b"AT_GID",
            14 => b"AT_EGID",
            15 => b"AT_PLATFORM",
            16 => b"AT_HWCAP",
            17 => b"AT_CLKTCK",
            23 => b"AT_SECURE",
            24 => b"AT_BASE_PLATFORM",
            25 => b"AT_RANDOM",
            26 => b"AT_HWCAP2",
            31 => b"AT_EXECFN",
            32 => b"AT_SYSINFO",
            33 => b"AT_SYSINFO_EHDR",
            _ => b"??",
        }
    }

    fn formatted_value(&self) -> PrintArg<'_> {
        match self.typ {
            3 | 7 | 9 | 16 | 25 | 26 | 33 => PrintArg::Hex(self.value as usize),
            31 | 15 => {
                let string = unsafe {
                    let pointer = self.value as *const u8;
                    core::slice::from_raw_parts(pointer, strlen(pointer))
                };
                PrintArg::String(string)
            }
            _ => PrintArg::Number(self.value as usize)
        }
    }
}
