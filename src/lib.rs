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

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    pub fn should_read_u32() {
        let bytes = vec![10, 20, 30, 40];
        let result = super::read_u32(&mut &bytes[..]).unwrap();

        assert_eq!(result, 0x281E140A);
    }

    #[test]
    pub fn should_return_error_if_u32_can_not_be_read() {
        let bytes = vec![10, 20, 30];
        let result = super::read_u32(&mut &bytes[..]);

        match result {
            Err(Error::ByteOrder(_)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
