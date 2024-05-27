use std::{env, error::Error, fs, io::Write, process::{Command, Stdio}};

use delf::SegmentType;
use mmap::{MemoryMap, MapOption};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk <FILE>");

    println!("Analyzsing {:?}", input_path);
    let input = fs::read(&input_path)?;

    let file =
        match delf::File::parse_or_print_error(&input[..]) {
            Some(file) => file,
            None => std::process::exit(1),
        };

    println!("{:#?}", file);

    println!("Disassembling {:?}", input_path);
    let entry_point_program_header = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("no segment containing entrypoint found");

    // the entry_point is not necessarily the start of the section pointed to by the program header
    // data (offset -> offset + memsize)
    ndisasm(&entry_point_program_header.data[..], file.entry_point)?;

    // we'll need to hold onto our "mmap::MemoryMap", because dropping them
    // unmaps them!
    let mut mappings = Vec::new();

    // we're only interested in "Load" segments
    for program_header in file
        .program_headers
        .iter()
        .filter(|ph| ph.segment_type == SegmentType::Load)
    {
        let _ = pause(&(format!("map segment @ {:?} with {:?}", program_header.mem_range(), program_header.flags)));

        // note: mmap-ing would fail if the segments weren't aligned on pages,
        // but luckily, that is the case in the file already. That is not a coincidence.
        let mem_range = program_header.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        // `as` is the "cast" operator, and `_` is a placeholder to force rustc
        // to infer the type based on other hints (here, the left-hand-side declaration)
        let addr: *mut u8 = mem_range.start.0 as _;

        // at first, we want the memory area to be writable, so we can copy to it.
        // we'll set the right permissions later
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        let _ = pause("copy data");
        let destination = unsafe { std::slice::from_raw_parts_mut(addr, program_header.data.len()) };
        destination.copy_from_slice(&program_header.data[..]);

        let _ = pause("changing protection");
        let protection = program_header.flags.iter().fold(
            Protection::NONE,
            |acc, flag| match flag {
                delf::SegmentFlag::Read => acc | Protection::READ,
                delf::SegmentFlag::Write => acc | Protection::WRITE,
                delf::SegmentFlag::Execute => acc | Protection::EXECUTE,
            }
        );

        unsafe { 
            protect(destination.as_ptr(), destination.len(), protection)?; 
        }

        mappings.push(map);
    }

    let _ = pause("jump to entry_point in heap");
    unsafe {
        // casting pointer a u64 into a pointer on a u8. Contrarily to before we know there are
        // some valid byes at address file.entry_point.0, because we mapped the program header
        // there
        jmp(file.entry_point.0 as _);
    }

    Ok(())
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}...", reason);
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).map(|_| ())?;
    Ok(())
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o") // from origin
        .arg(format!("{}", origin))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;

    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() -> () = std::mem::transmute(addr);
    fn_ptr();
}
