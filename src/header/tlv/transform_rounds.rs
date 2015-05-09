use bytes;
use Error;

use header::tlv::Tlv;

use std::io::Read;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, 8)
        .and_then(|_| bytes::read_u64(reader))
        .map(|rounds| Tlv::TransformRounds(rounds))
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn should_read_tlv() {
        let mut bytes = vec![];
        bytes.write_u64::<LittleEndian>(1234).unwrap();

        let result = read_tlv(&mut &bytes[..], 8);

        match result {
            Ok(Tlv::TransformRounds(rounds)) => assert_eq!(rounds, 1234),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];

        let result = read_tlv(&mut &bytes[..], 7);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
