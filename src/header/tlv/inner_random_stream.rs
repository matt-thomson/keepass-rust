use read;
use Error;

use header::InnerRandomStreamType;
use header::tlv::Tlv;

use std::io::Read;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, 4)
        .and_then(|_| read::read_u32(reader))
        .and_then(match_stream_id)
        .map(|stream| Tlv::InnerRandomStream(stream))
}

fn match_stream_id(stream_id: u32) -> Result<InnerRandomStreamType, Error> {
    match stream_id {
        0 => Ok(InnerRandomStreamType::None),
        1 => Ok(InnerRandomStreamType::Rc4),
        2 => Ok(InnerRandomStreamType::Salsa20),
        _ => Err(Error::UnknownInnerRandomStreamType(stream_id))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::InnerRandomStreamType;
    use header::tlv::Tlv;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn should_read_tlv() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(1).unwrap();

        let result = read_tlv(&mut &bytes[..], 4);

        match result {
            Ok(Tlv::InnerRandomStream(InnerRandomStreamType::Rc4)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];

        let result = read_tlv(&mut &bytes[..], 3);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_unknown_compression_type() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(3).unwrap();

        let result = read_tlv(&mut &bytes[..], 4);

        match result {
            Err(Error::UnknownInnerRandomStreamType(3)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
