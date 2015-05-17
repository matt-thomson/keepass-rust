use bytes;
use Error;

use header::CipherType;
use header::tlv::Tlv;

use std::io::Read;

const AES_UUID_1: u64 = 0x504371BFE6F2C131;
const AES_UUID_2: u64 = 0xFF5AFC6A210558BE;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    try!(super::check_tlv_length(length, 16));

    let uuid1 = try!(bytes::read_u64(reader));
    let uuid2 = try!(bytes::read_u64(reader));
    let cipher_type = try!(match_cipher_type(uuid1, uuid2));

    Ok(Tlv::Cipher(cipher_type))
}

fn match_cipher_type(uuid1: u64, uuid2: u64) -> Result<CipherType, Error> {
    match (uuid1, uuid2) {
        (AES_UUID_1, AES_UUID_2) => Ok(CipherType::Aes),
        _ => Err(Error::UnknownCipherType(uuid1, uuid2))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::CipherType;
    use header::tlv::Tlv;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn should_read() {
        let mut bytes = vec![];
        bytes.write_u64::<LittleEndian>(super::AES_UUID_1).unwrap();
        bytes.write_u64::<LittleEndian>(super::AES_UUID_2).unwrap();

        let result = read_tlv(&mut &bytes[..], 16);

        match result {
            Ok(Tlv::Cipher(CipherType::Aes)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = vec![];

        let result = read_tlv(&mut &bytes[..], 15);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_unknown_cipher_type() {
        let uuid1 = super::AES_UUID_1 + 1;
        let uuid2 = super::AES_UUID_2 + 1;

        let mut bytes = vec![];
        bytes.write_u64::<LittleEndian>(uuid1).unwrap();
        bytes.write_u64::<LittleEndian>(uuid2).unwrap();

        let result = read_tlv(&mut &bytes[..], 16);

        match result {
            Err(Error::UnknownCipherType(u1, u2)) => {
                assert_eq!(u1, uuid1);
                assert_eq!(u2, uuid2);
            },
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
