use std::io::Read;

use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::Decryptor;

use Error;

pub fn decrypt(reader: &mut Read, key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let mut decryptor = aes::cbc_decryptor(KeySize::KeySize256, key, iv, NoPadding);

    let mut in_buffer = vec![];
    reader.read_to_end(&mut in_buffer);

    let mut final_result = vec![];
    let mut read_buffer = RefReadBuffer::new(&in_buffer);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
