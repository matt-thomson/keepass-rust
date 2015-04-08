mod builder;
mod tlv;

use read;
use {Error, FileType};

use self::builder::HeaderBuilder;

use std::io::Read;

#[derive(Debug, PartialEq)]
pub enum CipherType {
    Aes
}

#[derive(Debug, PartialEq)]
pub enum CompressionType {
    None,
    Gzip
}

#[derive(Debug)]
pub struct Header {
    pub version: u32,
    pub cipher: CipherType,
    pub compression: CompressionType,
    pub master_seed: [u8; 32],
    pub transform_seed: [u8; 32],
    pub transform_rounds: u64,
    pub encryption_iv: [u8; 16]
}

pub fn read_header(file_type: FileType, reader: &mut Read) -> Result<Header, Error> {
    check_file_type(file_type)
        .and_then(|_| read_version(reader))
        .and_then(|version| handle_tlvs(reader, version))
}

fn check_file_type(file_type: FileType) -> Result<(), Error> {
    match file_type {
        FileType::KeePass2 => Ok(()),
        _ => Err(Error::UnsupportedFileType(file_type))
    }
}

fn read_version(reader: &mut Read) -> Result<u32, Error> {
    read::read_u32(reader)
}

fn handle_tlvs(reader: &mut Read, version: u32) -> Result<Header, Error> {
    let mut builder = HeaderBuilder::new(version);

    for tlv in tlv::tlvs(reader) {
        match tlv {
            Ok(t) => builder.apply(t),
            Err(e) => return Err(e)
        }
    }

    builder.build()
}

#[cfg(test)]
mod test {
    use {Error, FileType};

    #[test]
    pub fn should_return_error_if_wrong_file_type() {
        let result = super::read_header(FileType::KeePass1, &mut &vec![][..]);

        match result {
            Err(Error::UnsupportedFileType(FileType::KeePass1)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
