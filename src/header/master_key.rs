use Error;

use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::Encryptor;

use std::io::Read;

pub fn key(transform_seed: &[u8; 32],
           transform_rounds: u64,
           master_seed: &[u8; 32],
           passphrase: &str) -> Result<[u8; 32], Error> {
    transform_key(&composite_key(passphrase), transform_seed, transform_rounds)
        .map(|k| make_master_key(&k, &master_seed))
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(input);

    let mut buf = [0; 32];
    hasher.result(&mut buf);

    buf
}

fn composite_key(passphrase: &str) -> [u8; 32] {
    let mut hasher1 = Sha256::new();
    hasher1.input_str(passphrase);

    let mut buf1 = [0; 32];
    hasher1.result(&mut buf1);

    sha256(&buf1)
}

fn transform_key(key: &[u8; 32], seed: &[u8; 32], rounds: u64) -> Result<[u8; 32], Error> {
    let mut result = Ok(*key);

    for _ in 0..rounds {
        result = result.and_then(|r| encrypt(&r, &seed));
    }

    result.map(|r| sha256(&r))
}

fn encrypt(key: &[u8; 32], seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut encryptor = aes::ecb_encryptor(KeySize::KeySize256, seed, NoPadding);

    let mut read_buffer = RefReadBuffer::new(key);
    let mut buffer = [0; 32];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).ok().unwrap();

    match result {
        BufferResult::BufferUnderflow => println!("under!"),
        BufferResult::BufferOverflow => println!("over!")
    }

    read_array!(write_buffer.take_read_buffer().take_remaining(), 32)
}

fn make_master_key(key: &[u8; 32], master_seed: &[u8; 32]) -> [u8; 32] {
    let mut buffer = vec![];
    buffer.extend(master_seed.iter().cloned());
    buffer.extend(key.iter().cloned());

    sha256(&buffer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_generate_composite_key() {
        let composite_key = super::composite_key("hunter2");
        assert_eq!(&composite_key[0..8], &[0xa3, 0xe2, 0x7a, 0xb2, 0x94, 0x8b, 0x68, 0x0e]);
    }

    #[test]
    fn should_transform_key() {
        let composite_key = super::composite_key("hunter2");
        let seed = [1; 32];
        let transformed_key = super::transform_key(&composite_key, &seed, 6000).unwrap();

        assert_eq!(&transformed_key[0..8], &[0xf3, 0x62, 0x30, 0x40, 0x15, 0xd8, 0xd1, 0x69]);
    }

    #[test]
    fn should_generate_master_key() {
        let master_key = super::key(&[1; 32], 6000, &[2; 32], "hunter2").unwrap();
        assert_eq!(&master_key[0..8], &[0x4e, 0x39, 0xfb, 0xa3, 0xda, 0xd7, 0xc4, 0xde]);
    }
}