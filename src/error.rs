use FileType;

use std;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::Error as IoError;
use std::string::FromUtf8Error;

use crypto::symmetriccipher::SymmetricCipherError;
use rustc_serialize::base64::FromBase64Error;
use xml::reader::Error as XmlError;

#[derive(Debug)]
pub enum Error {
    UnexpectedEOF,
    Io(IoError),

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

    Cipher(SymmetricCipherError),

    IncorrectStartBytes,
    IncorrectBlockId,
    IncorrectBlockHash,

    Xml(XmlError),

    MissingKey,

    Base64(FromBase64Error),
    Utf8(FromUtf8Error),
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
