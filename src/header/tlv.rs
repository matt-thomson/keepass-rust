use super::super::read;
use super::super::Error;

use std::io::Read;

pub struct Tlv {
    tlv_type: u8,
    value: Vec<u8>
}

pub struct HeaderReader<'a> {
    reader: &'a mut Read
}

pub fn tlvs<'a>(reader: &'a mut Read) -> HeaderReader<'a> {
    HeaderReader { reader: reader }
}

impl <'a> Iterator for HeaderReader<'a> {
    type Item = Result<Tlv, Error>;

    fn next(&mut self) -> Option<Result<Tlv, Error>> {
        let result = read_type_length(self.reader)
            .and_then(|(tlv_type, length)| read_tlv(self.reader, tlv_type, length));

        match result {
            Ok(tlv) => if tlv.tlv_type == 0 { None } else { Some(Ok(tlv)) },
            Err(e) => Some(Err(e))
        }
    }
}

fn read_type_length(reader: &mut Read) -> Result<(u8, u16), Error> {
    let tlv_type = read::read_u8(reader);
    let length = read::read_u16(reader);

    match (tlv_type, length) {
        (Ok(t), Ok(l)) => Ok((t, l)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e)
    }
}

fn read_tlv(reader: &mut Read, tlv_type: u8, length: u16) -> Result<Tlv, Error> {
    let mut value = vec![];

    reader.take(length as u64).read_to_end(&mut value)
        .map_err(|e| Error::Io(e))
        .and_then(|bytes_read| if bytes_read as u16 == length {
            Ok(Tlv { tlv_type: tlv_type, value: value })
        } else {
            Err(Error::UnexpectedEOF)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    pub fn should_read_type_and_length() {
        let bytes = vec![10, 20, 30];

        let (tlv_type, length) = super::read_type_length(&mut &bytes[..]).unwrap();

        assert_eq!(tlv_type, 10);
        assert_eq!(length, 0x1E14);
    }

    #[test]
    pub fn should_iterate_through_tlvs() {
        let mut bytes = vec![];
        bytes.write_u8(2).unwrap();
        bytes.write_u16::<LittleEndian>(4).unwrap();
        bytes.write(&vec![1, 2, 3, 4]).unwrap();

        bytes.write_u8(3).unwrap();
        bytes.write_u16::<LittleEndian>(2).unwrap();
        bytes.write(&vec![5, 6]).unwrap();

        bytes.write_u8(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();

        let reader = &mut &bytes[..];

        let mut tlvs = super::tlvs(reader).collect::<Vec<_>>();
        assert_eq!(tlvs.len(), 2);

        let ref mut tlv = tlvs.as_mut()[0].as_mut().ok().unwrap();
        assert_eq!(tlv.tlv_type, 2);
        assert_eq!(tlv.value, vec![1, 2, 3, 4]);
    }
}
