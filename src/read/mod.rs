mod aes;
mod block;
mod xml;

use {Database, Error};

use std::io::{Cursor, Read};

use self::block::BlockReader;

pub fn read(key: &[u8; 32],
            iv: &[u8; 16],
            expected: &[u8; 32],
            reader: &mut Read)
            -> Result<Database, Error> {
    let mut stream = Cursor::new(try!(aes::decrypt(reader, key, iv)));

    let result = try!(read_array!(&mut stream, 32));
    try!(check_key(&result, expected));

    let mut block_reader = BlockReader::new(&mut stream);
    xml::read(&mut block_reader)
}

fn check_key(result: &[u8; 32], expected: &[u8; 32]) -> Result<(), Error> {
    if expected == result {
        Ok(())
    } else {
        Err(Error::IncorrectStartBytes)
    }
}
