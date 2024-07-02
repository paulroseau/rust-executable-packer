use core::arch::asm;

pub const STDOUT_FILE_DESCRIPTOR: u32 = 1;

#[macro_export]
macro_rules! println {
   ($($arg:expr),+)  => {
       print!(
           $($arg),
           +,
           b"\n"
       )
   }
}

#[macro_export]
macro_rules! print {
    ($($arg:expr),+) => {
        print(&[
            $($arg.into()),
            +
        ])
    };
}

pub unsafe fn write(fd: u32, buffer: *const u8, count: usize) {
    let syscall_number: u64 = 1;
    asm!(
        "syscall",
        inout("rax") syscall_number => _, // <- not just in because the function needs to know rax is used by the syscall (actually to return the result)
        in("rdi") fd,
        in("rsi") buffer,
        in("rdx") count,
        lateout("rcx") _, // <- is not preserved across the syscall
        lateout("r11") _, // <- is not preserved across the syscall
        options(nostack)
    );
}

pub unsafe fn exit(code: i32) -> ! {
    let syscall_number: u64 = 60;
    asm!(
        "syscall",
        in("rax") syscall_number,
        in("rdi") code,
        options(noreturn)
    )
}

pub enum PrintArg<'a> {
    String(&'a [u8]),
    Number(usize),
    Hex(usize),
}

impl<'a> From<usize> for PrintArg<'a> {
    fn from(n: usize) -> Self {
        PrintArg::Number(n)
    }
}

impl<'a> From<&'a [u8]> for PrintArg<'a> {
    fn from(s: &'a [u8]) -> Self {
        PrintArg::String(s)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for PrintArg<'a> {
    fn from(s: &'a [u8; N]) -> Self {
        PrintArg::String(s.as_ref())
    }
}

pub fn print(args: &[PrintArg]) {
    // args is a slice, so arg is a reference &PrintArg
    for arg in args {
        match arg {
            PrintArg::String(s) => print_string(s),
            PrintArg::Number(n) => print_number(*n),
            PrintArg::Hex(n) => {
                print_string(b"0x");
                print_hex(*n);
            },
        }
    }
}

pub fn print_string(string: &[u8]) {
    unsafe {
        write(STDOUT_FILE_DESCRIPTOR, string.as_ptr(), string.len());
    }
}

pub fn print_number(number: usize) {
    if number > 9 {
        print_number(number / 10); // we don't have an allocator (so we can't use Vec) so we use recursion to make use of the stack instead of the heap
    }
    let char = b'0' + (number % 10) as u8; // b'0' gives you the ASCII byte representation of the character '0', which is 48, all the other digits follow (49 is '1', 50 is '2', etc.)
    print_string(&[char]);
}

pub fn print_hex(number: usize) {
    if number > 16 {
        print_hex(number / 16); // we don't have an allocator (so we can't use Vec) so we use recursion to make use of the stack instead of the heap
    }
    let remainder = (number % 16) as u8;
    let char = match remainder {
        0..=9 => b'0' + remainder, // b'0' gives you the ASCII byte representation of the character '0', which is 48, all the other digits follow (49 is '1', 50 is '2', etc.)
        _ => b'a' + remainder - 10, // same reasoning but using `a` as the base ASCII reference
    };
    print_string(&[char]);
}

// unsafe because we derefrence a raw pointer
pub unsafe fn strlen(mut string: *const u8) -> usize {
    let mut count: usize = 0;
    while *string != b'\0' {
        count += 1;
        string = string.add(1);
    }
    count
}
