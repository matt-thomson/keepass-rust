use Error;

use header::tlv::Tlv;

use std::io::Read;

const IV_LENGTH: usize = 16;

pub fn read_encryption_iv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, IV_LENGTH as u16)
        .and_then(|_| read_array!(reader, IV_LENGTH))
        .map(|iv| Tlv::EncryptionIv(iv))
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    #[test]
    fn should_read_encryption_iv() {
        let bytes = [1; 16];
        let result = read_encryption_iv(&mut &bytes[..], 16);

        match result {
            Ok(Tlv::EncryptionIv(iv)) => assert_eq!(iv, bytes),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];
        let result = read_encryption_iv(&mut &bytes[..], 15);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
