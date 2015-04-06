use Error;

use header::tlv::Tlv;

use std::io::Read;

const IV_LENGTH: usize = 16;

pub fn read_encryption_iv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, IV_LENGTH as u16)
        .and_then(|_| read_iv(reader))
        .map(|iv| Tlv::EncryptionIv(iv))
}

fn read_iv(reader: &mut Read) -> Result<[u8; IV_LENGTH], Error> {
    let mut buf = [0; IV_LENGTH];
    reader.read(&mut buf)
        .map_err(|e| Error::Io(e))
        .and_then(check_bytes_read)
        .map(|_| buf)
}

fn check_bytes_read(bytes_read: usize) -> Result<(), Error> {
    if bytes_read == IV_LENGTH { Ok(()) } else { Err(Error::UnexpectedEOF) }
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

    #[test]
    fn should_return_error_if_wrong_number_of_bytes_read() {
        let bytes = [1; 15];
        let result = read_encryption_iv(&mut &bytes[..], 16);

        match result {
            Err(Error::UnexpectedEOF) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
