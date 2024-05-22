use std::{env, error::Error, fs, io::Write, process::{Command, Stdio}};

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
    // data (offset -> offset + memsize), cf. (1)
    ndisasm(&entry_point_program_header.data[..], file.entry_point)?; 

    // let status = Command::new(&input_path).status()?;
    // if !status.success() {
    //     return Err("process did not exit successfully".into());
    // }

    println!("Executing {:?} in memory...", input_path);

    let code = &entry_point_program_header.data; // shadowing the program_header struct by the vec8
    unsafe {
        protect(code.as_ptr(), code.len(), Protection::READ_WRITE_EXECUTE)?;
    }

    // (1)
    let entry_point_offset = file.entry_point - entry_point_program_header.virtual_address;
    let entry_point = unsafe { code.as_ptr().add(entry_point_offset.into()) };

    println!("        code @ {:?}", code.as_ptr());
    println!("entry offset @ {:?}", entry_point_offset);
    println!(" entry point @ {:?}", entry_point);

    unsafe {
        jmp(entry_point);
    }

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
