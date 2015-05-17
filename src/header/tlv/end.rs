use Error;

use header::tlv::Tlv;

use std::io::Read;

const END_OF_HEADER_LENGTH: usize = 4;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    try!(super::check_tlv_length(length, END_OF_HEADER_LENGTH as u16));
    try!(read_array!(reader, END_OF_HEADER_LENGTH));

    Ok(Tlv::EndOfHeader)
}
