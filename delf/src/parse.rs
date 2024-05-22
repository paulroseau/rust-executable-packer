pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(input: parse::Input) -> parse::Result<Self> {
                use nom::{
                    combinator::map_res,
                    error::context,
                    number::complete::$number_parser
                };
                let parser = map_res($number_parser, |x| $type::try_from(x));
                context(stringify!($type), parser)(input)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_enumflag {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: parse::Input) -> parse::Result<enumflags2::BitFlags<Self>> {
                use nom::{
                    combinator::map_res,
                    error::context,
                    number::complete::$number_parser,
                };

                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}
