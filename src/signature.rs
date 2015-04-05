use read;
use {Error, FileType};

use std::io::Read;

const SIGNATURE_FILE: u32 = 0x9AA2D903;
const SIGNATURE_KEEPASS1: u32 = 0xB54BFB65;
const SIGNATURE_KEEPASS2_PRE_RELEASE: u32  = 0xB54BFB66;
const SIGNATURE_KEEPASS2: u32  = 0xB54BFB67;

pub fn read_file_type(reader: &mut Read) -> Result<FileType, Error> {
    read::read_u32(reader)
        .and_then(check_file_signature)
        .and_then(|_| read::read_u32(reader))
        .and_then(match_file_type)
}

fn check_file_signature(sig: u32) -> Result<(), Error> {
    if sig == SIGNATURE_FILE { Ok(()) } else { Err(Error::InvalidSignature(sig)) }
}

fn match_file_type(file_type: u32) -> Result<FileType, Error> {
    match file_type {
            SIGNATURE_KEEPASS1 => Ok(FileType::KeePass1),
            SIGNATURE_KEEPASS2_PRE_RELEASE => Ok(FileType::KeePass2PreRelease),
            SIGNATURE_KEEPASS2 => Ok(FileType::KeePass2),
            _ => Err(Error::InvalidFileType(file_type))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use {Error, FileType};

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    pub fn should_return_file_type() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_FILE).unwrap();
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_KEEPASS2).unwrap();

        let result = read_file_type(&mut &bytes[..]);

        match result {
            Ok(FileType::KeePass2) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_wrong_signature() {
        let signature = super::SIGNATURE_FILE + 1;

        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(signature).unwrap();

        let result = read_file_type(&mut &bytes[..]);

        match result {
            Err(Error::InvalidSignature(s)) => assert_eq!(s, signature),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_invalid_type() {
        let file_type = super::SIGNATURE_KEEPASS2 + 1;

        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_FILE).unwrap();
        bytes.write_u32::<LittleEndian>(file_type).unwrap();

        let result = read_file_type(&mut &bytes[..]);

        match result {
            Err(Error::InvalidFileType(t)) => assert_eq!(t, file_type),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
