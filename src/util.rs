use Error;

use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::Decryptor;

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(input);

    let mut buf = [0; 32];
    hasher.result(&mut buf);

    buf
}

pub fn decrypt(decryptor: &mut Decryptor, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut final_result = vec![];
    let mut read_buffer = RefReadBuffer::new(value);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor
                              .decrypt(&mut read_buffer, &mut write_buffer, true)
                              .map_err(|e| Error::Cipher(e)));
        final_result.extend(write_buffer.take_read_buffer()
                                        .take_remaining()
                                        .iter()
                                        .map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
