use Error;

use super::ProtectedStream;
use util::{decrypt, sha256};

use crypto::salsa20::Salsa20 as SalsaDecryptor;
use rustc_serialize::base64::FromBase64;

const IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

struct Salsa20 {
    decryptor: SalsaDecryptor,
}

impl Salsa20 {
    pub fn new(key: &[u8; 32]) -> Salsa20 {
        Salsa20 { decryptor: SalsaDecryptor::new(&sha256(key), &IV) }
    }
}

impl ProtectedStream for Salsa20 {
    fn decrypt(&mut self, value: &str) -> Result<String, Error> {
        let in_buffer = try!(value.from_base64().map_err(|e| Error::Base64(e)));
        let result = try!(decrypt(&mut self.decryptor, &in_buffer));

        Ok(try!(String::from_utf8(result).map_err(|e| Error::Utf8(e))))
    }
}

#[cfg(test)]
mod tests {
    use super::Salsa20;
    use protected::ProtectedStream;

    #[test]
    fn should_decrypt_password() {
        let key = [0xE4, 0x70, 0xC4, 0xEF, 0x95, 0x61, 0x22, 0xDF, 0x2C, 0x0D, 0xD1, 0x42, 0x4A,
                   0x24, 0xE6, 0x87, 0x79, 0x29, 0xB9, 0xAD, 0x47, 0x9C, 0x0E, 0xA5, 0xA0, 0x5D,
                   0xB1, 0x27, 0x7A, 0xDF, 0xBD, 0xCD];

        let mut salsa20 = Salsa20::new(&key);
        let result = salsa20.decrypt("9crW5hp7SQ==").unwrap();
        assert_eq!(result, "hunter2");
    }
}
