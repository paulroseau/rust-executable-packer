mod parse;

use core::panic;
use derive_more::{ Add, Sub };
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::BitFlags;
use nom::{
    bits, 
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::{context, ErrorKind},
    multi::{many_m_n, many_till},
    number::{complete::{ le_u8, le_u16, le_u32, le_u64}},
    sequence::tuple 
};
use std::{
    fmt::{self, Debug, Write}, ops::{Add, Range}
};


#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
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
impl_parse_for_enum!(Type, le_u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}
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

// Into<u64> will be automatically derived thanks to the blanket implementation in the std library
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

// Represents the following struct:
// typedef struct {
//   Elf64_Sxword d_tag;
//   union {
//       Elf64_Xword d_val;
//       Elf64_Addr d_ptr;
//   } d_un;
// } Elf64_Dyn;
// NB: we use Addr for both case of d_un (int or pointer)
#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

#[derive(TryFromPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    Flags = 30,
    RunPath = 0x1d,
    LoOs = 0x60000000,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelaCount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    HiOs = 0x6fffffff,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
}
impl_parse_for_enum!(DynamicTag, le_u64);

pub enum SegmentContent {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

impl SymBind {
    pub fn parse(i: parse::BitInput) -> parse::BitResult<Option<Self>> {
        map(nom::bits::complete::take(4_usize), |bits: u8| Self::try_from(bits).ok())(i)
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
}

impl SymType {
    pub fn parse(i: parse::BitInput) -> parse::BitResult<Option<Self>> {
        map(nom::bits::complete::take(4_usize), |bits: u8| Self::try_from(bits).ok())(i)
    }
}

#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
        
    }
}

impl Debug for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(Debug)]
pub struct Symbol {
    pub name: Addr,
    pub bind: Option<SymBind>,
    pub symbol_type: Option<SymType>,
    pub shndx: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl Symbol {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (name, (bind, symbol_type), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits::bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;

        let res = Self {
          name,
          bind,
          symbol_type,
          shndx,
          value,
          size,
        };

        Ok((i, res))
    }
}

pub struct ProgramHeader {
    pub segment_type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub segment_offset: Addr,
    pub virtual_address: Addr,
    pub physical_address: Addr,
    pub segment_size: Addr,
    pub memory_size: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
    pub content: SegmentContent
}

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
       self.segment_offset..(self.segment_offset + self.segment_size)
    }

    pub fn mem_range(&self) -> Range<Addr> {
       self.virtual_address..(self.virtual_address + self.memory_size)
    }
    
    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        let (i, (segment_type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let (_i, (segment_offset, virtual_address, physical_address, segment_size, memory_size, align)) = tuple(
            (Addr::parse, Addr::parse, Addr::parse, Addr::parse, Addr::parse, Addr::parse)
        )(i)?;

        let slice = &full_input[segment_offset.into()..][..segment_size.into()];

        let (i, content) = match segment_type {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |entry| entry.tag == DynamicTag::Null)
                ),
                |(entries, _last)| SegmentContent::Dynamic(entries)
            )(slice)?,
            _ => (slice, SegmentContent::Unknown)
        };

        let res = Self {
            segment_type,
            flags,
            segment_offset,
            virtual_address,
            physical_address,
            segment_size,
            memory_size,
            align,
            // `to_vec()` turns a slice into an owned Vec (this works because u8 is Clone+Copy)
            data: slice.to_vec(),
            content
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
pub struct SectionHeader {
    pub name: Addr,
    pub section_type: u32,
    pub flags: u64,
    pub address: Addr,
    pub offset: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub align: Addr,
    pub entry_size: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (name, section_type, flags, address, offset, size, link, info, align, entry_size,)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            le_u32,
            le_u64,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            le_u32,
            le_u32,
            Addr::parse,
            Addr::parse,
        ))(i)?;

        let res = Self { 
            name,
            section_type,
            flags,
            address,
            offset,
            size,
            link,
            info,
            align,
            entry_size,
         };

        Ok((i, res))
    }
}

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub relocation_type: RelocationType,
    pub symbol: u32,
    pub addend: Addr
}

impl Rela {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(
            tuple((Addr::parse, RelocationType::parse, le_u32, Addr::parse)), 
            |(offset, relocation_type, symbol, addend)| Rela {
                offset,
                relocation_type,
                symbol,
                addend
            }
        )(i)
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KnownRelocationType {
    _64 = 1,
    Copy = 5,
    GlobalDat = 6,
    JumpSlot = 7,
    Relative = 8,
}
impl_parse_for_enum!(KnownRelocationType, le_u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Known(KnownRelocationType),
    Unknown(u32),
}

impl RelocationType {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
       // `alt` tries several parsers one by one, until one succeeds
       alt((
            map(KnownRelocationType::parse, Self::Known),
            map(le_u32, Self::Unknown),
       ))(i) 
    }
}

#[derive(Debug)]
pub struct File {
    pub tpe: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
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
        let (i, (_flags, _header_size)) = tuple((le_u32, le_u16))(i)?;

        let u16_as_usize = map(le_u16, |x| x as usize);
        let (i, (program_header_size, program_header_count)) = tuple((&u16_as_usize, &u16_as_usize))(i)?;
        let (i, (section_header_size, section_header_count, section_header_index)) = tuple((&u16_as_usize, &u16_as_usize, &u16_as_usize))(i)?;

        let program_headers_bytes = (&full_input[program_header_offset.into()..]).chunks(program_header_size);
        let mut program_headers = Vec::new();
        for bytes in program_headers_bytes.take(program_header_count) {
            let (_, program_header) = ProgramHeader::parse(full_input, bytes)?;
            program_headers.push(program_header);
        }

        let section_headers_bytes = (&full_input[section_header_offset.into()..]).chunks(section_header_size);
        let mut section_headers = Vec::new();
        for bytes in section_headers_bytes.take(section_header_count) {
            let (_, section_header) = SectionHeader::parse(bytes)?;
            section_headers.push(section_header);
        }

        let res = Self { tpe, machine, entry_point, program_headers, section_headers };

        Ok((i, res))
    }

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        use nom::Offset;

        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.0.errors {
                    let offset = i.offset(input); // need to import nom::Offset to have the method in scope
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("Unexpected error"),
        }
    }

    pub fn relocation_table(&self) -> Result<Vec<Rela>, ReadRelaError> {
        let addr = self.dynamic_entry(DynamicTag::Rela).ok_or(ReadRelaError::RelaNotFound)?;
        let len = self.dynamic_entry(DynamicTag::RelaSz).ok_or(ReadRelaError::RelaSzNotFound)?;
        let ent = self.dynamic_entry(DynamicTag::RelaEnt).ok_or(ReadRelaError::RelaEntNotFound)?;

        let slice = self.slice_at(addr).ok_or(ReadRelaError::RelaSegmentNotFound)?;
        let program_header = &slice[..len.into()];

        let n = (len.0 / ent.0) as usize;

        match many_m_n(n, n, Rela::parse)(program_header) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err) | nom::Err::Error(err)) =>
                Err(ReadRelaError::ParsingError(
                    err.0.errors
                        .into_iter()
                        .map(|(_, error_kind)| error_kind)
                        .collect::<Vec<_>>()
                )),
            _ => unreachable!(),
        }
    }

    pub fn program_header_for_type(&self, segment_type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers
          .iter()
          .find(|program_header| program_header.segment_type == segment_type)
    }

    pub fn program_header_for_load_segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
          .iter()
          .filter(|program_header| program_header.segment_type == SegmentType::Load)
          .find(|program_header| program_header.mem_range().contains(&addr))
    }

    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        let program_header = self.program_header_for_type(SegmentType::Dynamic)?;
        match program_header {
          ProgramHeader { content: SegmentContent::Dynamic(entries), .. } => Some(&entries[..]),
          _ => None,
        }
    }

    pub fn dynamic_entries<'a>(self: &'a Self, tag: DynamicTag) -> impl Iterator<Item = Addr> + 'a {
        self
          .dynamic_table()
          .unwrap_or_default()
          .iter()
          .filter(move |entry| entry.tag == tag) // we need to move tag, so it gets copied inside the scope of this function, such that when we actually iterate we are sure it is still valid, otherwise we would need to change the signature to tag: 'a &DynamicTag. We didn't have this issue before because we only returned Option<T> which is eager, while the iterator is not evaluated straight away
          .map(|entry| entry.addr)
    }

    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    pub fn slice_at(&self, addr: Addr) -> Option<&[u8]> {
        self
          .program_header_for_load_segment_at(addr)
          .map(|ph| &ph.data[(addr - ph.segment_offset).into()..])
    }

    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        let str_tab_address = 
          self
            .dynamic_entry(DynamicTag::StrTab)
            .ok_or(GetStringError::StrTabNotFound)?;

        let slice = 
          self
            .slice_at(str_tab_address + offset)
            .ok_or(GetStringError::StrTabSegmentNotFound)?;

        // Strings are null-terminated, so we (lazily) split the slice into
        // slices separated by '\0' and take the first item
        let string =
          slice
            .split(|&c| c == 0)
            .next()
            .ok_or(GetStringError::StringNotFound)?;

        Ok(String::from_utf8_lossy(string).into())
    }

    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        self
          .dynamic_entries(tag)
          .filter_map(|address| self.get_string(address).ok())
    }

    pub fn section_header_starting_at(&self, address: Addr) -> Option<&SectionHeader> {
        self
            .section_headers
            .iter()
            .find(|section_header| section_header.address == address)
    }

    pub fn read_symbols(&self) -> Result<Vec<Symbol>, ReadSymbolError> {
        let symbol_table_address = 
          self
            .dynamic_entry(DynamicTag::SymTab)
            .ok_or(ReadSymbolError::SymTabNotFound)?;

        let symbol_table_section_header =
          self
            .section_header_starting_at(symbol_table_address)
            .ok_or(ReadSymbolError::SymTabSectionHeaderNotFound)?;

        let i = 
          self
            .slice_at(symbol_table_section_header.address)
            .ok_or(ReadSymbolError::SymTabSegmentNotFound)?;

        let n = (symbol_table_section_header.size.0 / symbol_table_section_header.entry_size.0) as usize;

        match many_m_n(n, n, Symbol::parse)(i) {
            Ok((_, symbols)) => Ok(symbols),
            Err(nom::Err::Error(err)) | Err(nom::Err::Error(err)) => 
                Err(ReadSymbolError::ParsingError(
                    err.0.errors
                        .into_iter()
                        .map(|(_, error_kind)| error_kind)
                        .collect::<Vec<_>>()
                )),
            _ => unreachable!(),
        }
    }
}

// The section header for SymTab points to data in one of the Load segment
// ProgramHeader of type Dynamic contains a SymTab entry
// SymTab entry points to 1 SectionHeader
// This SectionHeader points to data inside a Load segment (that segment is also pointed to by a program header of type Load)
#[derive(Debug, thiserror::Error)]
pub enum ReadSymbolError {
    #[error("SymTab dynamic entry not found")]
    SymTabNotFound,
    #[error("SymTab section header not found")]
    SymTabSectionHeaderNotFound,
    #[error("Symbol table segment not found")]
    SymTabSegmentNotFound,
    #[error("Symbol parsing error")]
    ParsingError(Vec<nom::error::VerboseErrorKind>)
}

#[derive(Debug, thiserror::Error)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("String Table not found")]
    StrTabSegmentNotFound,
    #[error("String not found in String Table")]
    StringNotFound,
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("Rela dynamic entry not found")]
    RelaNotFound,
    #[error("RelaSz dynamic entry not found")]
    RelaSzNotFound,
    #[error("RelaEnt dynamic entry not found")]
    RelaEntNotFound,
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error")]
    ParsingError(Vec<nom::error::VerboseErrorKind>)
}
