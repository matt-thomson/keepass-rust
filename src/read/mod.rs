mod aes;
mod block;

use Error;

use std::io::Read;

use self::aes::AesReader;
use self::block::BlockReader;

pub fn read(key: &[u8; 32],
            iv: &[u8; 16],
            expected: &[u8; 32],
            reader: &mut Read) -> Result<String, Error> {
    let mut stream = AesReader::new(reader, key, iv);

    read_array!(&mut stream, 32)
        .and_then(|result| check_key(&result, expected))
        .map(|_| BlockReader::new(&mut stream))
        .and_then(|mut read| read_all(&mut read))
}

fn check_key(result: &[u8; 32], expected: &[u8; 32]) -> Result<(), Error> {
    if expected == result { Ok(()) } else { Err(Error::IncorrectStartBytes) }
}

fn read_all(read: &mut Read) -> Result<String, Error> {
    let mut buf = "".to_string();
    read.read_to_string(&mut buf)
        .map_err(|e| Error::Io(e))
        .map(|_| buf)
}
