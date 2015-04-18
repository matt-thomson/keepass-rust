extern crate byteorder;
extern crate crypto;

#[macro_use] mod macros;

mod header;
mod read;
mod signature;

use std::fs;
use std::io;

#[derive(Debug)]
pub enum Error {
    UnexpectedEOF,
    Io(io::Error),

    InvalidSignature(u32),
    InvalidFileType(u32),
    UnsupportedFileType(FileType),
    UnknownTlv(u8),
    InvalidTlvSize,

    UnknownCipherType(u64, u64),
    UnknownCompressionType(u32),
    UnknownInnerRandomStreamType(u32),

    MissingCompressionType,
    MissingCipherType,
    MissingMasterSeed,
    MissingTransformSeed,
    MissingTransformRounds,
    MissingEncryptionIv,
    MissingProtectedStreamKey,
    MissingStreamStartBytes,
    MissingInnerRandomStream
}

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2
}

pub fn read(path: &str, passphrase: &str) -> Result<[u8; 32], Error> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(Error::Io(e))
    };

    signature::read_file_type(&mut file)
        .and_then(|file_type| header::read_header(file_type, &mut file))
        .and_then(|header| header.master_key(passphrase))
}
