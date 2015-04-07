extern crate keepass;

use keepass::header::{CipherType, CompressionType};

#[test]
#[ignore]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx").unwrap();

    assert_eq!(result.version, 0x00030001);
    assert_eq!(result.cipher, CipherType::Aes);
    assert_eq!(result.compression, CompressionType::None);
    assert_eq!(result.encryption_iv.len(), 16);
}
