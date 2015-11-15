use Error;

use super::ProtectedStream;

pub struct None;

impl ProtectedStream for None {
    fn decrypt(&mut self, value: &str) -> Result<String, Error> {
        Ok(value.to_string())
    }
}
