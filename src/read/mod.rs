mod aes;
mod block;
mod xml;

use {Database, Error};
use header::Header;

use std::io::{Cursor, Read};

use self::block::BlockReader;

pub fn read(reader: &mut Read, header: &Header, passphrase: &str) -> Result<Database, Error> {
    let key = try!(header.master_key(passphrase));
    let mut stream = Cursor::new(try!(aes::decrypt(reader, &key, &header.encryption_iv())));

    let result = try!(read_array!(&mut stream, 32));
    try!(check_key(&result, &header.stream_start_bytes()));

    let block_reader = BlockReader::new(Box::new(stream));
    let mut decompressed = try!(header.decompress(Box::new(block_reader)));
    xml::read(&mut decompressed, &mut *header.protected_stream())
}

fn check_key(result: &[u8; 32], expected: &[u8; 32]) -> Result<(), Error> {
    if expected == result {
        Ok(())
    } else {
        Err(Error::IncorrectStartBytes)
    }
}
