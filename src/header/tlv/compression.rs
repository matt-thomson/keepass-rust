use read;
use Error;

use super::Tlv;

use std::io::Read;

#[derive(Debug)]
pub enum CompressionType {
    None,
    Gzip
}

pub fn read_compression_flags(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, 4)
        .and_then(|_| read::read_u32(reader))
        .and_then(match_compression_flags)
        .map(|flag| Tlv::Compression(flag))
}

fn match_compression_flags(flags: u32) -> Result<CompressionType, Error> {
    match flags {
        0 => Ok(CompressionType::None),
        1 => Ok(CompressionType::Gzip),
        _ => Err(Error::UnknownCompressionType(flags))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use Error;
    use header::tlv::Tlv;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn should_read_compression_flags() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(1).unwrap();

        let result = read_compression_flags(&mut &bytes[..], 4);

        match result {
            Ok(Tlv::Compression(CompressionType::Gzip)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];

        let result = read_compression_flags(&mut &bytes[..], 3);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_unknown_compression_type() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(2).unwrap();

        let result = read_compression_flags(&mut &bytes[..], 4);

        match result {
            Err(Error::UnknownCompressionType(2)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
