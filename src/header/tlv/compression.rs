use bytes;
use Error;

use header::CompressionType;
use header::tlv::Tlv;

use std::io::Read;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    try!(super::check_tlv_length(length, 4));

    let flags = try!(bytes::read_u32(reader));
    let compression_type = try!(match_compression_flags(flags));

    Ok(Tlv::Compression(compression_type))
}

fn match_compression_flags(flags: u32) -> Result<CompressionType, Error> {
    match flags {
        0 => Ok(CompressionType::None),
        1 => Ok(CompressionType::Gzip),
        _ => Err(Error::UnknownCompressionType(flags)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::CompressionType;
    use header::tlv::Tlv;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn should_read_tlv() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(1).unwrap();

        let result = read_tlv(&mut &bytes[..], 4);

        match result {
            Ok(Tlv::Compression(CompressionType::Gzip)) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];

        let result = read_tlv(&mut &bytes[..], 3);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }

    #[test]
    fn should_return_error_if_unknown_compression_type() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(2).unwrap();

        let result = read_tlv(&mut &bytes[..], 4);

        match result {
            Err(Error::UnknownCompressionType(2)) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }
}
