extern crate byteorder;

mod header;
mod read;
mod signature;

use std::fs;
use std::io;

#[derive(Debug)]
pub enum Error {
    ByteOrder(byteorder::Error),
    Io(io::Error),

    InvalidSignature(u32),
    InvalidFileType(u32),
    UnsupportedFileType(FileType),
    UnknownTlv(u8)
}

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2
}

pub fn read(path: &str) -> Result<header::Header, Error> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(Error::Io(e))
    };

    signature::read_file_type(&mut file)
        .and_then(|file_type| header::read_header(file_type, &mut file))
}
