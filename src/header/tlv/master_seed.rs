use Error;

use header::tlv::Tlv;

use std::io::Read;

const MASTER_SEED_LENGTH: usize = 32;

pub fn read_tlv(reader: &mut Read, length: u16) -> Result<Tlv, Error> {
    try!(super::check_tlv_length(length, MASTER_SEED_LENGTH as u16));

    let seed = try!(read_array!(reader, MASTER_SEED_LENGTH));
    Ok(Tlv::MasterSeed(seed))
}

#[cfg(test)]
mod test {
    use super::*;

    use Error;
    use header::tlv::Tlv;

    #[test]
    fn should_read_tlv() {
        let bytes = [1; 32];
        let result = read_tlv(&mut &bytes[..], 32);

        match result {
            Ok(Tlv::MasterSeed(seed)) => assert_eq!(seed, bytes),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }

    #[test]
    fn should_return_error_if_wrong_length() {
        let bytes = [];
        let result = read_tlv(&mut &bytes[..], 31);

        match result {
            Err(Error::InvalidTlvSize) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
