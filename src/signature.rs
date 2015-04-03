use super::{Error, FileType};

use std::io::Read;

const SIGNATURE_FILE: u32 = 0x9AA2D903;
const SIGNATURE_KEEPASS1: u32 = 0xB54BFB65;
const SIGNATURE_KEEPASS2_PRE_RELEASE: u32  = 0xB54BFB66;
const SIGNATURE_KEEPASS2: u32  = 0xB54BFB67;

pub fn get_file_type(reader: &mut Read) -> Result<FileType, Error> {
    super::read_u32(reader)
        .and_then(check_file_signature)
        .and_then(|_| super::read_u32(reader))
        .and_then(match_file_type)
}

fn check_file_signature(sig: u32) -> Result<(), Error> {
    if sig == SIGNATURE_FILE { Ok(()) } else { Err(Error::InvalidSignature) }
}

fn match_file_type(sig: u32) -> Result<FileType, Error> {
    match sig {
            SIGNATURE_KEEPASS1 => Ok(FileType::KeePass1),
            SIGNATURE_KEEPASS2_PRE_RELEASE => Ok(FileType::KeePass2PreRelease),
            SIGNATURE_KEEPASS2 => Ok(FileType::KeePass2),
            _ => Err(Error::InvalidFileType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Error, FileType};

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    pub fn should_return_file_() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_FILE).unwrap();
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_KEEPASS2).unwrap();

        let result = get_file_type(&mut &bytes[..]);

        match result {
            Ok(FileType::KeePass2) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_wrong_signature() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_FILE + 1).unwrap();

        let result = get_file_type(&mut &bytes[..]);

        match result {
            Err(Error::InvalidSignature) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_invalid_type() {
        let mut bytes = vec![];
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_FILE).unwrap();
        bytes.write_u32::<LittleEndian>(super::SIGNATURE_KEEPASS2 + 1).unwrap();

        let result = get_file_type(&mut &bytes[..]);

        match result {
            Err(Error::InvalidFileType) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
