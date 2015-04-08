use Error;

use header::tlv::Tlv;

use std::io::Read;

const STREAM_START_BYTES_LENGTH: usize = 32;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, STREAM_START_BYTES_LENGTH as u16)
        .and_then(|_| read_array!(reader, STREAM_START_BYTES_LENGTH))
        .map(|seed| Tlv::StreamStartBytes(seed))
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    #[test]
    fn should_read_tlv() {
        let bytes = [1; 32];
        let result = read_tlv(&mut &bytes[..], 32);

        match result {
            Ok(Tlv::StreamStartBytes(seed)) => assert_eq!(seed, bytes),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = [];
        let result = read_tlv(&mut &bytes[..], 31);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
