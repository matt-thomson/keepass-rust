use super::{CipherType, CompressionType, Header};
use super::tlv::Tlv;

use Error;

pub struct HeaderBuilder {
    version: u32,
    cipher: Option<CipherType>,
    compression: Option<CompressionType>
}

impl HeaderBuilder {
    pub fn new(version: u32) -> HeaderBuilder {
        HeaderBuilder {
            version: version,
            cipher: None,
            compression: None
        }
    }

    pub fn apply(&mut self, tlv: Tlv) {
        match tlv {
            Tlv::EndOfHeader => unreachable!(),
            Tlv::Cipher(cipher) => self.cipher = Some(cipher),
            Tlv::Compression(compression) => self.compression = Some(compression)
        }
    }

    pub fn build(self) -> Result<Header, Error> {
        match (self.cipher, self.compression) {
            (None, _) => Err(Error::MissingCipherType),
            (_, None) => Err(Error::MissingCompressionType),
            (Some(cipher), Some(compression)) => Ok(Header {
                version: self.version,
                cipher: cipher,
                compression: compression
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

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));

        let result = builder.build().unwrap();

        assert_eq!(result.version, version);
        assert_eq!(result.cipher, CipherType::Aes);
        assert_eq!(result.compression, CompressionType::Gzip)
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
}
