use std::fs;
use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

extern crate byteorder;

const SIGNATURE_FILE: u32 = 0x9AA2D903;
const SIGNATURE_KEEPASS1: u32 = 0xB54BFB65;
const SIGNATURE_KEEPASS2_PRE_RELEASE: u32  = 0xB54BFB66;
const SIGNATURE_KEEPASS2: u32  = 0xB54BFB67;

#[derive(Debug)]
pub enum Error {
    ByteOrder(byteorder::Error),
    Io(io::Error),

    InvalidSignature,
    InvalidFileType
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2
}

pub fn read(path: &str) -> Result<FileType, Error> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(Error::Io(e))
    };

    Ok(())
        .and_then(|_| check_file_signature(&mut file))
        .and_then(|_| get_file_type(&mut file))
}

fn check_file_signature(reader: &mut io::Read) -> Result<(), Error> {
    read_u32(reader)
        .and_then(|sig| if sig == SIGNATURE_FILE { Ok(()) } else { Err(Error::InvalidSignature) })
}

fn get_file_type(reader: &mut io::Read) -> Result<FileType, Error> {
    read_u32(reader)
        .and_then(|sig| match sig {
            SIGNATURE_KEEPASS1 => Ok(FileType::KeePass1),
            SIGNATURE_KEEPASS2_PRE_RELEASE => Ok(FileType::KeePass2PreRelease),
            SIGNATURE_KEEPASS2 => Ok(FileType::KeePass2),
            _ => Err(Error::InvalidFileType)
        })
}

fn read_u32(reader: &mut io::Read) -> Result<u32, Error> {
    reader.read_u32::<LittleEndian>().map_err(|e| Error::ByteOrder(e))
}

#[test]
fn should_read_database() {
    let result = read("data/test.kdbx").unwrap();
    assert_eq!(result, FileType::KeePass2);
}
