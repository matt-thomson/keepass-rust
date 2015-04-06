use super::{CipherType, CompressionType, Header};
use super::tlv::Tlv;

use Error;

pub struct HeaderBuilder {
    version: u32,
    cipher: Option<CipherType>,
    compression: Option<CompressionType>,
    encryption_iv: Option<[u8; 16]>
}

impl HeaderBuilder {
    pub fn new(version: u32) -> HeaderBuilder {
        HeaderBuilder {
            version: version,
            cipher: None,
            compression: None,
            encryption_iv: None
        }
    }

    pub fn apply(&mut self, tlv: Tlv) {
        match tlv {
            Tlv::EndOfHeader => unreachable!(),
            Tlv::Cipher(cipher) => self.cipher = Some(cipher),
            Tlv::Compression(compression) => self.compression = Some(compression),
            Tlv::EncryptionIv(iv) => self.encryption_iv = Some(iv)
        }
    }

    pub fn build(self) -> Result<Header, Error> {
        match (self.cipher, self.compression, self.encryption_iv) {
            (None, _, _) => Err(Error::MissingCipherType),
            (_, None, _) => Err(Error::MissingCompressionType),
            (_, _, None) => Err(Error::MissingEncryptionIv),
            (Some(cipher), Some(compression), Some(iv)) => Ok(Header {
                version: self.version,
                cipher: cipher,
                compression: compression,
                encryption_iv: iv
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::{CipherType, CompressionType};
    use header::tlv::Tlv;

    #[test]
    pub fn should_build_header() {
        let version = 0x01020304;
        let iv = [1; 16];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::EncryptionIv(iv));

        let result = builder.build().unwrap();

        assert_eq!(result.version, version);
        assert_eq!(result.cipher, CipherType::Aes);
        assert_eq!(result.compression, CompressionType::Gzip);
        assert_eq!(result.encryption_iv, iv);
    }

    #[test]
    pub fn should_return_error_if_no_cipher() {
        let version = 0x01020304;

        let builder = HeaderBuilder::new(version);
        let result = builder.build();

        match result {
            Err(Error::MissingCipherType) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_compression() {
        let version = 0x01020304;

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));

        let result = builder.build();

        match result {
            Err(Error::MissingCompressionType) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_encryption_iv() {
        let version = 0x01020304;

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));

        let result = builder.build();

        match result {
            Err(Error::MissingEncryptionIv) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
