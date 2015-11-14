extern crate byteorder;
extern crate crypto;
extern crate xml;

#[macro_use]mod macros;

mod bytes;
mod database;
mod error;
mod header;
mod read;
mod signature;

use std::fs::File;
use std::path::Path;

pub use database::Database;
pub use error::Error;

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2,
}

pub fn read<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<(), Error> {
    let mut file = try!(File::open(path).map_err(|e| Error::Io(e)));

    let file_type = try!(signature::read_file_type(&mut file));
    let header = try!(header::read_header(file_type, &mut file));

    let master_key = try!(header.master_key(passphrase));
    read::read(&master_key,
               &header.encryption_iv(),
               &header.stream_start_bytes(),
               &mut file)
}
