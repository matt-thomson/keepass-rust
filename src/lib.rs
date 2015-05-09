extern crate byteorder;
extern crate crypto;

#[macro_use] mod macros;

mod bytes;
mod decrypt;
mod header;
mod signature;

use crypto::symmetriccipher;

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
    MissingInnerRandomStream,

    Cipher(symmetriccipher::SymmetricCipherError),

    IncorrectStartBytes
}

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2
}

pub fn read(path: &str, passphrase: &str) -> Result<(), Error> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(Error::Io(e))
    };

    let header = match signature::read_file_type(&mut file)
        .and_then(|file_type| header::read_header(file_type, &mut file)) {
        Ok(h) => h,
        Err(e) => return Err(e)
    };

    header.master_key(passphrase)
        .and_then(|key| decrypt::check_key(&key, &header.encryption_iv(), &header.stream_start_bytes(), &mut file))
}
