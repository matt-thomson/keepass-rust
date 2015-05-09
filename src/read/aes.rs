use std::io::{Read, Result};

use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::Decryptor;

pub struct AesStream<'a> {
    delegate: &'a mut Read,
    decryptor: Box<Decryptor>
}

impl <'a> AesStream<'a> {
    pub fn new(delegate: &'a mut Read, key: &[u8; 32], iv: &[u8; 16]) -> AesStream<'a> {
        let decryptor = aes::cbc_decryptor(KeySize::KeySize256, key, iv, NoPadding);

        AesStream { delegate: delegate, decryptor: decryptor }
    }
}

impl <'a> Read for AesStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut in_buffer = vec![0; buf.len()];
        let bytes_read = self.delegate.read(&mut in_buffer);

        let mut read_buffer = RefReadBuffer::new(&in_buffer);
        let mut write_buffer = RefWriteBuffer::new(buf);

        self.decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        bytes_read
    }
}
