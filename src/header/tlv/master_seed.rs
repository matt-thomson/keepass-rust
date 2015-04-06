use Error;

use header::tlv::Tlv;

use std::io::Read;

const MASTER_SEED_LENGTH: usize = 32;

pub fn read_master_seed(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    super::check_tlv_length(length, MASTER_SEED_LENGTH as u16)
        .and_then(|_| read_seed(reader))
        .map(|seed| Tlv::MasterSeed(seed))
}

fn read_seed(reader: &mut Read) -> Result<[u8; MASTER_SEED_LENGTH], Error> {
    let mut buf = [0; MASTER_SEED_LENGTH];
    reader.read(&mut buf)
        .map_err(|e| Error::Io(e))
        .and_then(check_bytes_read)
        .map(|_| buf)
}

fn check_bytes_read(bytes_read: usize) -> Result<(), Error> {
    if bytes_read == MASTER_SEED_LENGTH { Ok(()) } else { Err(Error::UnexpectedEOF) }
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    #[test]
    fn should_read_master_seed() {
        let bytes = [1; 32];
        let result = read_master_seed(&mut &bytes[..], 32);

        match result {
            Ok(Tlv::MasterSeed(seed)) => assert_eq!(seed, bytes),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = [];
        let result = read_master_seed(&mut &bytes[..], 31);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_number_of_bytes_read() {
        let bytes = [1; 31];
        let result = read_master_seed(&mut &bytes[..], 32);

        match result {
            Err(Error::UnexpectedEOF) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
