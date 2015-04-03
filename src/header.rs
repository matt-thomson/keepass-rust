use super::read;
use super::{Error, FileType};

use std::io::Read;

#[derive(Debug)]
pub struct Header {
    pub version: u32
}

pub fn read_header(file_type: FileType, reader: &mut Read) -> Result<Header, Error> {
    let mut header = check_file_type(file_type).and_then(|_| read_version(reader));

    while header.is_ok() {
        let (field_type, field_length) = read_type_length(reader).unwrap();

        match field_type {
            _ => header = Err(Error::UnknownTlv(field_type))
        }
    }

    header
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

fn read_type_length(reader: &mut Read) -> Result<(u8, u16), Error> {
    let field_type = read::read_u8(reader);
    let field_length = read::read_u16(reader);

    match (field_type, field_length) {
        (Ok(t), Ok(l)) => Ok((t, l)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Error, FileType};

    #[test]
    pub fn should_read_type_and_length() {
        let bytes = vec![10, 20, 30];

        let (field_type, field_length) = super::read_type_length(&mut &bytes[..]).unwrap();

        assert_eq!(field_type, 10);
        assert_eq!(field_length, 0x1E14);
    }

    #[test]
    pub fn should_return_error_if_wrong_file_type() {
        let result = super::read_header(FileType::KeePass1, &mut &vec![][..]);

        match result {
            Err(Error::UnsupportedFileType(FileType::KeePass1)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
