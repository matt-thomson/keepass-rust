mod aes;

use Error;

use std::io::Read;

use self::aes::AesReader;

pub fn check_key(key: &[u8; 32],
                 iv: &[u8; 16],
                 expected: &[u8; 32],
                 reader: &mut Read) -> Result<(), Error> {
    let mut stream = AesReader::new(reader, key, iv);

    read_array!(&mut stream, 32)
        .and_then(|result| check(&result, expected))
}

fn check(result: &[u8; 32], expected: &[u8; 32]) -> Result<(), Error> {
    if expected == result { Ok(()) } else { Err(Error::IncorrectStartBytes) }
}
