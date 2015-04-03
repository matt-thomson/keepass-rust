use super::{Error};

use byteorder::{LittleEndian, ReadBytesExt};

use std::io::Read;

pub fn read_u8(reader: &mut Read) -> Result<u8, Error> {
    reader.read_u8().map_err(|e| Error::ByteOrder(e))
}

pub fn read_u16(reader: &mut Read) -> Result<u16, Error> {
    reader.read_u16::<LittleEndian>().map_err(|e| Error::ByteOrder(e))
}

pub fn read_u32(reader: &mut Read) -> Result<u32, Error> {
    reader.read_u32::<LittleEndian>().map_err(|e| Error::ByteOrder(e))
}

#[cfg(test)]
mod tests {
    use super::super::Error;

    #[test]
    pub fn should_read_u8() {
        let bytes = vec![10];
        let result = super::read_u8(&mut &bytes[..]).unwrap();

        assert_eq!(result, 0x0A);
    }

    #[test]
    pub fn should_return_error_if_u8_can_not_be_read() {
        let bytes = vec![];
        let result = super::read_u8(&mut &bytes[..]);

        match result {
            Err(Error::ByteOrder(_)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_read_u16() {
        let bytes = vec![10, 20];
        let result = super::read_u16(&mut &bytes[..]).unwrap();

        assert_eq!(result, 0x140A);
    }

    #[test]
    pub fn should_return_error_if_u16_can_not_be_read() {
        let bytes = vec![10];
        let result = super::read_u16(&mut &bytes[..]);

        match result {
            Err(Error::ByteOrder(_)) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

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
