extern crate byteorder;
extern crate crypto;

#[macro_use] mod macros;

mod bytes;
mod error;
mod header;
mod read;
mod signature;

use std::fs::File;
use std::path::Path;

pub use error::Error;

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2
}

pub fn read<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<String, Error> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(Error::Io(e))
    };

    let header = match signature::read_file_type(&mut file)
        .and_then(|file_type| header::read_header(file_type, &mut file)) {
        Ok(h) => h,
        Err(e) => return Err(e)
    };

    header.master_key(passphrase)
        .and_then(|key| read::read(&key, &header.encryption_iv(), &header.stream_start_bytes(), &mut file))
}
