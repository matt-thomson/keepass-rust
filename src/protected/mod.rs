mod none;
mod salsa20;

use Error;

use self::none::None;
use self::salsa20::Salsa20;

pub trait ProtectedStream {
    fn decrypt(&mut self, value: &str) -> Result<String, Error>;
}

impl ProtectedStream {
    pub fn none() -> Box<ProtectedStream> {
        Box::new(None)
    }

    pub fn rc4(_key: &[u8; 32]) -> Box<ProtectedStream> {
        panic!("Not implemented");
    }

    pub fn salsa20(key: &[u8; 32]) -> Box<ProtectedStream> {
        Box::new(Salsa20::new(key))
    }
}
