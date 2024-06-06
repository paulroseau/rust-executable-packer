use nom::{
    error::{ParseError, VerboseError, VerboseErrorKind}, 
    ErrorConvert
};

// We will need to implement ErrorConvert<VerboseError<I>> for VerboseError<(I, usize)>
// in particular ErrorConvert<VerboseError<Input>> for VerboseError<BitInput> (cf. type aliases lower)
// Unfortunately both the ErrorConvert<T> trait and the VerboseError type are defined outside
// this crate so we need to define a dummy Error type which wraps around VerboseError

pub struct Error<T>(pub VerboseError<T>);

// Error needs to implement the ParseError trait, too bad VerboseError had already a default implementation
impl<I> nom::error::ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self(VerboseError::from_error_kind(input, kind))
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.0.errors.push((input, VerboseErrorKind::Nom(kind)));
        other
    }
}

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, Error<Input<'a>>>;

pub type BitInput<'a> = (&'a [u8], usize); // we can only slice at the byte level, we need to add an offset to locate the bit of interest inside the byte
pub type BitResult<'a, O> = nom::IResult<BitInput<'a>, O, Error<BitInput<'a>>>;

impl<'a> ErrorConvert<Error<Input<'a>>> for Error<BitInput<'a>> {
  fn convert(self) -> Error<Input<'a>> {
     let errors =
        self
          .0
          .errors
          .into_iter()
          .map(|((byte, _offset), verbose_error_kind)| (byte, verbose_error_kind))
          .collect();
    Error(VerboseError { errors })
  }
}

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
