mod salsa20;

use Error;

trait ProtectedStream {
    fn decrypt(&mut self, value: &str) -> Result<String, Error>;
}
