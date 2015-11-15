use Error;
use std::io::Read;

use flate2::read::GzDecoder;

pub fn none(read: Box<Read>) -> Result<Box<Read>, Error> {
    Ok(read)
}

pub fn gzip(read: Box<Read>) -> Result<Box<Read>, Error> {
    Ok(Box::new(try!(GzDecoder::new(read).map_err(|e| Error::Io(e)))))
}
