use super::{CipherType, CompressionType, Header};
use super::tlv::Tlv;

use Error;

pub struct HeaderBuilder {
    version: u32,
    cipher: Option<CipherType>,
    compression: Option<CompressionType>,
    master_seed: Option<[u8; 32]>,
    transform_seed: Option<[u8; 32]>,
    transform_rounds: Option<u64>,
    encryption_iv: Option<[u8; 16]>,
    protected_stream_key: Option<[u8; 32]>,
    stream_start_bytes: Option<[u8; 32]>
}

impl HeaderBuilder {
    pub fn new(version: u32) -> HeaderBuilder {
        HeaderBuilder {
            version: version,
            cipher: None,
            compression: None,
            master_seed: None,
            transform_seed: None,
            transform_rounds: None,
            encryption_iv: None,
            protected_stream_key: None,
            stream_start_bytes: None
        }
    }

    pub fn apply(&mut self, tlv: Tlv) {
        match tlv {
            Tlv::EndOfHeader => unreachable!(),
            Tlv::Cipher(cipher) => self.cipher = Some(cipher),
            Tlv::Compression(compression) => self.compression = Some(compression),
            Tlv::MasterSeed(seed) => self.master_seed = Some(seed),
            Tlv::TransformSeed(seed) => self.transform_seed = Some(seed),
            Tlv::TransformRounds(rounds) => self.transform_rounds = Some(rounds),
            Tlv::EncryptionIv(iv) => self.encryption_iv = Some(iv),
            Tlv::ProtectedStreamKey(key) => self.protected_stream_key = Some(key),
            Tlv::StreamStartBytes(bytes) => self.stream_start_bytes = Some(bytes)
        }
    }

    pub fn build(self) -> Result<Header, Error> {
        if self.cipher.is_none() { Err(Error::MissingCipherType) }
        else if self.compression.is_none() { Err(Error::MissingCompressionType) }
        else if self.master_seed.is_none() { Err(Error::MissingMasterSeed) }
        else if self.transform_seed.is_none() { Err(Error::MissingTransformSeed) }
        else if self.transform_rounds.is_none() { Err(Error::MissingTransformRounds) }
        else if self.encryption_iv.is_none() { Err(Error::MissingEncryptionIv) }
        else if self.protected_stream_key.is_none() { Err(Error::MissingProtectedStreamKey) }
        else if self.stream_start_bytes.is_none() { Err(Error::MissingStreamStartBytes) }
        else {
            Ok(Header {
                version: self.version,
                cipher: self.cipher.unwrap(),
                compression: self.compression.unwrap(),
                master_seed: self.master_seed.unwrap(),
                transform_seed: self.transform_seed.unwrap(),
                transform_rounds: self.transform_rounds.unwrap(),
                encryption_iv: self.encryption_iv.unwrap(),
                protected_stream_key: self.protected_stream_key.unwrap(),
                stream_start_bytes: self.stream_start_bytes.unwrap()
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
        let master_seed = [1; 32];
        let transform_seed = [2; 32];
        let transform_rounds = 10000;
        let iv = [3; 16];
        let protected_stream_key = [4; 32];
        let stream_start_bytes = [5; 32];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));
        builder.apply(Tlv::TransformSeed(transform_seed));
        builder.apply(Tlv::TransformRounds(transform_rounds));
        builder.apply(Tlv::EncryptionIv(iv));
        builder.apply(Tlv::ProtectedStreamKey(protected_stream_key));
        builder.apply(Tlv::StreamStartBytes(stream_start_bytes));

        let result = builder.build().unwrap();

        assert_eq!(result.version, version);
        assert_eq!(result.cipher, CipherType::Aes);
        assert_eq!(result.compression, CompressionType::Gzip);
        assert_eq!(result.master_seed, master_seed);
        assert_eq!(result.transform_seed, transform_seed);
        assert_eq!(result.transform_rounds, 10000);
        assert_eq!(result.encryption_iv, iv);
        assert_eq!(result.protected_stream_key, protected_stream_key);
        assert_eq!(result.stream_start_bytes, stream_start_bytes);
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
    pub fn should_return_error_if_no_master_seed() {
        let version = 0x01020304;

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));

        let result = builder.build();

        match result {
            Err(Error::MissingMasterSeed) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_transform_seed() {
        let version = 0x01020304;
        let master_seed = [1; 32];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));

        let result = builder.build();

        match result {
            Err(Error::MissingTransformSeed) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_transform_rounds() {
        let version = 0x01020304;
        let master_seed = [1; 32];
        let transform_seed = [2; 32];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));
        builder.apply(Tlv::TransformSeed(transform_seed));

        let result = builder.build();

        match result {
            Err(Error::MissingTransformRounds) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_encryption_iv() {
        let version = 0x01020304;
        let master_seed = [1; 32];
        let transform_seed = [2; 32];
        let transform_rounds = 10000;

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));
        builder.apply(Tlv::TransformSeed(transform_seed));
        builder.apply(Tlv::TransformRounds(transform_rounds));

        let result = builder.build();

        match result {
            Err(Error::MissingEncryptionIv) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_protected_stream_key() {
        let version = 0x01020304;
        let master_seed = [1; 32];
        let transform_seed = [2; 32];
        let transform_rounds = 10000;
        let iv = [3; 16];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));
        builder.apply(Tlv::TransformSeed(transform_seed));
        builder.apply(Tlv::TransformRounds(transform_rounds));
        builder.apply(Tlv::EncryptionIv(iv));

        let result = builder.build();

        match result {
            Err(Error::MissingProtectedStreamKey) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    pub fn should_return_error_if_no_stream_start_bytes() {
        let version = 0x01020304;
        let master_seed = [1; 32];
        let transform_seed = [2; 32];
        let transform_rounds = 10000;
        let iv = [3; 16];
        let protected_stream_key = [4; 32];

        let mut builder = HeaderBuilder::new(version);
        builder.apply(Tlv::Cipher(CipherType::Aes));
        builder.apply(Tlv::Compression(CompressionType::Gzip));
        builder.apply(Tlv::MasterSeed(master_seed));
        builder.apply(Tlv::TransformSeed(transform_seed));
        builder.apply(Tlv::TransformRounds(transform_rounds));
        builder.apply(Tlv::EncryptionIv(iv));
        builder.apply(Tlv::ProtectedStreamKey(protected_stream_key));

        let result = builder.build();

        match result {
            Err(Error::MissingStreamStartBytes) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
