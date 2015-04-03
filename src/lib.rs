extern crate byteorder;

mod signature;

use std::fs;
use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Debug)]
pub enum Error {
    ByteOrder(byteorder::Error),
    Io(io::Error),

    InvalidSignature,
    InvalidFileType
}

#[derive(Debug)]
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

    Ok(()).and_then(|_| signature::get_file_type(&mut file))
}

fn read_u32(reader: &mut io::Read) -> Result<u32, Error> {
    reader.read_u32::<LittleEndian>().map_err(|e| Error::ByteOrder(e))
}

#[test]
fn should_read_database() {
    let result = read("data/test.kdbx").unwrap();

    match result {
        FileType::KeePass2 => (),
        _ => panic!("Invalid result: {:#?}", result)
    }
}
