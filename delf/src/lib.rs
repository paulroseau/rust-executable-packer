mod parse;

use derive_more::{ Add, Sub };
use derive_try_from_primitive::TryFromPrimitive;
use nom::{combinator::{map, verify}, error::context, number::complete::{ le_u16, le_u32, le_u64}};
use enumflags2::BitFlags;

// Program Header types for parsing

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
}
impl_parse_for_enum!(SegmentType, le_u32);

#[enumflags2::bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}
impl_parse_for_enumflag!(SegmentFlag, le_u32);

#[cfg(test)]
mod test_segment_flag {
    use super::SegmentFlag;

    #[test]
    fn try_bit_flag() {
        let valid_flags_integer: u32 = 6;

        let valid_flags = enumflags2::BitFlags::<SegmentFlag>::from_bits(valid_flags_integer).unwrap();
        assert_eq!(valid_flags, SegmentFlag::Write | SegmentFlag:: Read);
        assert_eq!(valid_flags.bits(), valid_flags_integer);

        assert!(enumflags2::BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0,
    Rel = 1,
    Exec = 2,
    Dyn = 3,
    Core = 4
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

// impl Machine {
//     // TODO implement this with a macro!
//     pub fn parse(input: parse::Input) -> parse::Result<Self> {
//         context(
//             "Machine",
//             map_res(le_u16, |x| Machine::try_from(x).map_err(|_| ErrorKind::Alt)), // I believe the map_err is useless here
//         )(input)
//     }
// }

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);

#[cfg(test)]
mod tests {
    #[test]
    fn type_to_u16() {
        use super::Type;

        assert_eq!(Type::Rel as u16, 1);
        assert_eq!(Type::Core as u16, 0x4);
    }

    #[test]
    fn u16_to_type() {
        use super::Type;

        assert_eq!(Type::try_from(1), Ok(super::Type::Rel));
        assert_eq!(Type::try_from(10), Err(10));
    }

    #[test]
    fn try_enums() {
        use super::Machine;

        assert_eq!(Machine::X86 as u16, 0x03);
        assert_eq!(Machine::try_from(0x3e), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0x00), Err(0));
    }
}

pub struct HexDump<'a>(&'a [u8]);

use core::panic;
use std::{fmt::{self, Debug}, ops::{Add, Range}};

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

// Into <u64> will be automatically derived thanks to the blanket implementation in the std library
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl Addr {
    pub fn parse(input: parse::Input) -> parse::Result<Self> {
        map(le_u64, From::from)(input)
    }
}

pub struct ProgramHeader {
    pub segment_type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub virtual_address: Addr,
    pub physical_address: Addr,
    pub file_size: Addr,
    pub memory_size: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
}

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
       self.offset..(self.offset + self.file_size)
    }

    pub fn mem_range(&self) -> Range<Addr> {
       self.virtual_address..(self.virtual_address + self.memory_size)
    }
    
    fn parse<'a>(full_input: parse::Input<'_>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::sequence::tuple;
        let (i, (segment_type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;
        let address_parser = Addr::parse;

        let (i, (offset, virtual_address, physical_address, file_size, memory_size, align)) = tuple(
            (address_parser, address_parser, address_parser, address_parser, address_parser, address_parser)
        )(i)?;

        let res = Self {
            segment_type,
            flags,
            offset,
            virtual_address,
            physical_address,
            file_size,
            memory_size,
            align,
            // `to_vec()` turns a slice into an owned Vec (this works because u8 is Clone+Copy)
            data: full_input[offset.into()..][..file_size.into()].to_vec(),
        };
        Ok((i, res))
    }
}

impl Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X"),
            ]
                .iter()
                .map(|&(flag, letter)| {
                    if self.flags.contains(flag) {
                        letter
                    } else {
                        "."
                    }
                })
                .collect::<Vec<_>>()
                .join(""),
            self.segment_type
        )
    }
}

#[derive(Debug)]
pub struct File {
    pub tpe: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            sequence::tuple,
        };

        let full_input = i;

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endiannenss", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8_usize)),
        ))(i)?;

        let (i, (tpe, machine)) = tuple((
            // context("Type", map(le_u16, |x| Type::try_from(x).unwrap())),
            // context("Machine", map(le_u16, |x| Machine::try_from(x).unwrap())),
            Type::parse,
            Machine::parse,
        ))(i)?;

        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;

        let (i, entry_point) = Addr::parse(i)?;

        let (i, (program_header_offset, section_header_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, header_size)) = tuple((le_u32, le_u16))(i)?;

        let u16_as_usize = map(le_u16, |x| x as usize);
        let (i, (program_header_size, program_header_count)) = tuple((&u16_as_usize, &u16_as_usize))(i)?;
        let (i, (section_header_size, section_header_count, section_header_index)) = tuple((&u16_as_usize, &u16_as_usize, &u16_as_usize))(i)?;

        let program_headers_bytes = (&full_input[program_header_offset.into()..]).chunks(program_header_size);
        let mut program_headers = Vec::new();
        for bytes in program_headers_bytes.take(program_header_count) {
            let (_, program_header) = ProgramHeader::parse(full_input, bytes)?;
            program_headers.push(program_header);
        }

        let res = Self { tpe, machine, entry_point, program_headers };

        Ok((i, res))
    }

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        use nom::Offset;

        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    let offset = i.offset(input); // need to import nom::Offset to have the method in scope
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("Unexpected error"),
        }
    }
}
