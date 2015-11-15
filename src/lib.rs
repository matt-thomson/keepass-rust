extern crate byteorder;
extern crate crypto;
extern crate flate2;
extern crate rustc_serialize;
extern crate xml;

#[macro_use]mod macros;

mod bytes;
mod database;
mod decompress;
mod error;
mod header;
mod protected;
mod read;
mod signature;
mod util;

use std::fs::File;
use std::path::Path;

pub use database::{Database, DatabaseEntry};
pub use error::Error;

#[derive(Debug)]
pub enum FileType {
    KeePass1,
    KeePass2PreRelease,
    KeePass2,
}

pub fn read<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Database, Error> {
    let mut file = try!(File::open(path).map_err(|e| Error::Io(e)));

    let file_type = try!(signature::read_file_type(&mut file));
    let header = try!(header::read_header(file_type, &mut file));

    read::read(&mut file, &header, passphrase)
}
