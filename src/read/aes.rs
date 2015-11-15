use util;

use std::io::Read;

use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;

use Error;

pub fn decrypt(reader: &mut Read, key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let mut decryptor = aes::cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding);

    let mut in_buffer = vec![];
    try!(reader.read_to_end(&mut in_buffer).map_err(|e| Error::Io(e)));

    let result = try!(util::decrypt(&mut *decryptor, &in_buffer));
    Ok(result)
}
