use Error;

use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};

use std::io::Read;

pub fn check_key(key: &[u8; 32],
                 iv: &[u8; 16],
                 expected: &[u8; 32],
                 reader: &mut Read) -> Result<(), Error> {
    let mut decryptor = aes::cbc_decryptor(KeySize::KeySize256, key, iv, NoPadding);
    let bytes = read_array!(reader, 32).unwrap();

    let mut read_buffer = RefReadBuffer::new(&bytes);
    let mut buffer = [0; 32];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)
        .map_err(|e| Error::Cipher(e))
        .and_then(|_| read_array!(write_buffer.take_read_buffer().take_remaining(), 32))
        .and_then(|result| check(&result, expected))
}

fn check(result: &[u8; 32], expected: &[u8; 32]) -> Result<(), Error> {
    if expected == result { Ok(()) } else { Err(Error::IncorrectStartBytes) }
}
