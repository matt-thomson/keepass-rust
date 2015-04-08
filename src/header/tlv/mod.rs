mod cipher;
mod compression;
mod iv;
mod master_seed;
mod protected_stream_key;
mod transform_rounds;
mod transform_seed;

use read;
use Error;

use header::{CipherType, CompressionType};

use std::io::Read;

#[derive(Debug)]
pub enum Tlv {
    EndOfHeader,
    Cipher(CipherType),
    Compression(CompressionType),
    MasterSeed([u8; 32]),
    TransformSeed([u8; 32]),
    TransformRounds(u64),
    EncryptionIv([u8; 16]),
    ProtectedStreamKey([u8; 32])
}

pub struct HeaderReader<'a> {
    reader: &'a mut Read,
    errored: bool
}

pub fn tlvs<'a>(reader: &'a mut Read) -> HeaderReader<'a> {
    HeaderReader { reader: reader, errored: false }
}

impl <'a> Iterator for HeaderReader<'a> {
    type Item = Result<Tlv, Error>;

    fn next(&mut self) -> Option<Result<Tlv, Error>> {
        if self.errored { None } else {
            let result = read_type_length(self.reader)
                .and_then(|(tlv_type, length)| read_tlv(self.reader, tlv_type, length));

            match result {
                Ok(Tlv::EndOfHeader) => None,
                Ok(_) => Some(result),
                Err(_) => { self.errored = true; Some(result) }
            }
        }
    }
}

fn read_type_length(reader: &mut Read) -> Result<(u8, u16), Error> {
    read::read_u8(reader)
        .and_then(|tlv_type| read::read_u16(reader).map(|length| (tlv_type, length)))
}

fn read_tlv(reader: &mut Read, tlv_type: u8, length: u16) -> Result<Tlv, Error> {
    match tlv_type {
        0 => Ok(Tlv::EndOfHeader),
        2 => cipher::read_tlv(reader, length),
        3 => compression::read_tlv(reader, length),
        4 => master_seed::read_tlv(reader, length),
        5 => transform_seed::read_tlv(reader, length),
        6 => transform_rounds::read_tlv(reader, length),
        7 => iv::read_tlv(reader, length),
        8 => protected_stream_key::read_tlv(reader, length),
        _ => Err(Error::UnknownTlv(tlv_type))
    }
}

fn check_tlv_length(length: u16, expected: u16) -> Result<(), Error> {
    if length == expected { Ok(()) } else { Err(Error::InvalidTlvSize) }
}

#[cfg(test)]
mod test {
    use super::*;
    use header::{CipherType, CompressionType};

    use std::io::Write;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    pub fn should_read_type_and_length() {
        let bytes = vec![10, 20, 30];

        let (tlv_type, length) = super::read_type_length(&mut &bytes[..]).unwrap();

        assert_eq!(tlv_type, 10);
        assert_eq!(length, 0x1E14);
    }

    #[test]
    pub fn should_iterate_through_tlvs() {
        let mut bytes = vec![];
        bytes.write_u8(3).unwrap();
        bytes.write_u16::<LittleEndian>(4).unwrap();
        bytes.write(&vec![1, 0, 0, 0]).unwrap();

        bytes.write_u8(2).unwrap();
        bytes.write_u16::<LittleEndian>(16).unwrap();
        bytes.write_u64::<LittleEndian>(0x504371BFE6F2C131).unwrap();
        bytes.write_u64::<LittleEndian>(0xFF5AFC6A210558BE).unwrap();

        bytes.write_u8(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();

        let reader = &mut &bytes[..];

        let tlvs = super::tlvs(reader).collect::<Vec<_>>();
        assert_eq!(tlvs.len(), 2);

        match tlvs[0] {
            Ok(Tlv::Compression(CompressionType::Gzip)) => (),
            _ => panic!("Invalid result: {:#?}", tlvs[0])
        }

        match tlvs[1] {
            Ok(Tlv::Cipher(CipherType::Aes)) => (),
            _ => panic!("Invalid result: {:#?}", tlvs[0])
        }
    }
}
