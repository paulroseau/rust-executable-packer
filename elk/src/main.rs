use core::panic;
use std::{
    env,
    error::Error,
    fs,
    io::Write,
    process::{Command, Stdio}
};

use delf::{SegmentContent, SegmentType};
use mmap::{MemoryMap, MapOption};
use region::{protect, Protection};

mod process;

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk <FILE>");

    println!("Analyzing {:?}", input_path);
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
    ndisasm(&entry_point_program_header.data[..], entry_point_program_header.segment_offset)?;

    println!("Dynamic entries");
    if let Some(dynamic_program_header) = file.program_header_for_type(SegmentType::Dynamic) {
        if let SegmentContent::Dynamic(ref entries) = dynamic_program_header.content {
            for entry in entries {
                println!("- {:?}", entry);
                match entry.tag {
                    delf::DynamicTag::Needed | delf::DynamicTag::RunPath => {
                        println!("  => {:?}", file.get_string(entry.addr)?);
                    }
                    _ => {}
                }
            }
        }
    }
    println!("");

    println!("Relocation table");
    let relocation_table = file.relocation_table().unwrap_or_else(|e| {
        println!("Could not find relocation table: {:?}", e);
        Default::default() // resolves to empty Vec
    });

    println!("Found {} relocation entries", relocation_table.len());
    for relocation_entry in relocation_table.iter() {
        println!("- {:?}", relocation_entry);
        if let Some(program_header) = file.program_header_for_load_segment_at(relocation_entry.offset) {
            println!("  for program_header: {:?}", program_header);
        }
    }
    println!("");


    println!("Section headers");
    for section_header in file.section_headers.iter() {
        println!("{:?}", section_header);
    }
    println!("");

    print!("Symbols");
    let symbols = file.read_symbols().unwrap();
    println!(
        "Symbol table @ {:?} contains {} entries",
        file.dynamic_entry(delf::DynamicTag::SymTab).unwrap(),
        symbols.len(),
    );
    for (num, symbol) in symbols.iter().enumerate() {
         println!(
            "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
            format!("{}", num),
            format!("{:?}", symbol.value),
            format!("{:?}", symbol.size),
            format!("{:?}", symbol.symbol_type),
            format!("{:?}", symbol.bind),
            format!("{:?}", symbol.shndx),
            format!("{}", file.get_string(symbol.name).unwrap_or_default()),
        );

        if file.get_string(symbol.name).unwrap_or_default() == "message" {
            let slice = file.slice_at(symbol.value).expect("There should be a symbol");
            let slice = &slice[..symbol.size as usize];
            println!("message = {:?}", String::from_utf8_lossy(slice));
        }
    }

    // we'll need to hold onto our "mmap::MemoryMap", because dropping them
    // unmaps them!
    let mut mappings = Vec::new();

    let base = 0x400000_usize;

    // we're only interested in "Load" segments
    for program_header in file
        .program_headers
        .iter()
        .filter(|ph| ph.segment_type == SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        let _ = pause(&(format!("Mapping segment @ {:?} with {:?}", program_header.mem_range(), program_header.flags)));

        // note: mmap-ing would fail if the segments weren't aligned on pages,
        // but luckily, that is the case in the file already. That is not a coincidence.
        let mem_range = program_header.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        // `as` is the "cast" operator, and `_` is a placeholder to force rustc
        // to infer the type based on other hints (here, the left-hand-side declaration)
        let start = base + mem_range.start.0 as usize;
        let aligned_start = align_lower(start);
        let padding = start - aligned_start;
        let len = len + padding; // shadowing

        let addr: *mut u8 = aligned_start as _;
        println!("Addr: {:?}, Padding: {:08x}", addr, padding);

        // at first, we want the memory area to be writable, so we can copy to it.
        // we'll set the right permissions later
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        let _ = pause("Copying data from file buffer (heap) to mapped memory");
        // destination is start (addr + padding) not addr, otherwise we would not respect the
        // mapping and copy over the padding
        let destination = unsafe { std::slice::from_raw_parts_mut(start as _, program_header.data.len()) };
        destination.copy_from_slice(&program_header.data[..]);

        println!("Applying relocations (if any)...");
        for relocation_entry in relocation_table.iter() {
            if mem_range.contains(&(relocation_entry.offset)) {
                let offset_into_segment = relocation_entry.offset.0 - mem_range.start.0;
                let relocation_address: *mut u64 = (start as u64 + offset_into_segment) as _;
                println!(
                    "Applying {:?} relocation @ {:?} from segment start {:?} = {:?}",
                    relocation_entry.relocation_type,
                    offset_into_segment,
                    start,
                    relocation_address,
                );

                match relocation_entry.relocation_type {
                    delf::RelocationType::Known(delf::KnownRelocationType::Relative) => {
                        let relocation_value = base as u64 + relocation_entry.addend.0;
                        println!("Replacing with value {:?}", relocation_value);
                        unsafe {
                            std::ptr::write_unaligned(relocation_address, relocation_value as _);
                        }
                    }
                    delf::RelocationType::Known(relocation_type) => {
                        panic!("Unsupported relocation type {:?}", relocation_type);
                    }
                    delf::RelocationType::Unknown(relocation_type) => {
                        println!("Unsupported relocation type {:?}", relocation_type);
                    }
                }
            }
        }

        let _ = pause("Changing protection of page");
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

    let _ = pause("Jumping to entry_point in heap");
    unsafe {
        // casting pointer a u64 into a pointer on a u8. Contrarily to before we know there are
        // some valid byes at address file.entry_point.0, because we mapped the program header
        // there
        jmp((file.entry_point.0 as usize + base) as _);
    }

    Ok(())
}

fn align_lower(addr: usize) -> usize {
    addr & !0xfff
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("{}", reason);
    // println!("Press Enter to continue...");
    // let mut s = String::new();
    // std::io::stdin().read_line(&mut s).map(|_| ())?;
    Ok(())
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o") // since we pass a chunk of bytes, we want to show their real address in the file (-o <origin> instructs where the address column should start from
        .arg(format!("{}", origin.0))
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
