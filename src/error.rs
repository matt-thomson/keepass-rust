use FileType;

use std;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;

use crypto::symmetriccipher;

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

    IncorrectStartBytes,
    IncorrectBlockId,
    IncorrectBlockHash
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "KeePass error"
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        formatter.write_str("KeePass error")
    }
}
