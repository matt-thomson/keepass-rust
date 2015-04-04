mod tlv;

use super::read;
use super::{Error, FileType};

use std::io::Read;

#[derive(Debug)]
pub struct Header {
    pub version: u32
}

pub fn read_header(file_type: FileType, reader: &mut Read) -> Result<Header, Error> {
    check_file_type(file_type).and_then(|_| read_version(reader))
}

fn check_file_type(file_type: FileType) -> Result<(), Error> {
    match file_type {
        FileType::KeePass2 => Ok(()),
        _ => Err(Error::UnsupportedFileType(file_type))
    }
}

fn read_version(reader: &mut Read) -> Result<Header, Error> {
    read::read_u32(reader).map(|version| Header { version: version })
}

#[cfg(test)]
mod tests {
    use super::super::{Error, FileType};

    #[test]
    pub fn should_return_error_if_wrong_file_type() {
        let result = super::read_header(FileType::KeePass1, &mut &vec![][..]);

        match result {
            Err(Error::UnsupportedFileType(FileType::KeePass1)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
