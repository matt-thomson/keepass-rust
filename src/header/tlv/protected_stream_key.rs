use Error;

use header::tlv::Tlv;

use std::io::Read;

const PROTECTED_STREAM_KEY_LENGTH: usize = 32;

pub fn read_protected_stream_key(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, PROTECTED_STREAM_KEY_LENGTH as u16)
        .and_then(|_| read_array!(reader, PROTECTED_STREAM_KEY_LENGTH))
        .map(|seed| Tlv::ProtectedStreamKey(seed))
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    #[test]
    fn should_read_protected_stream_key() {
        let bytes = [1; 32];
        let result = read_protected_stream_key(&mut &bytes[..], 32);

        match result {
            Ok(Tlv::ProtectedStreamKey(seed)) => assert_eq!(seed, bytes),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = [];
        let result = read_protected_stream_key(&mut &bytes[..], 31);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
