macro_rules! read_array {
    ($reader:expr, $size: expr) => ({
        use Error;

        use std::io::Read;

        let mut buf = [0; $size];
        $reader.read(&mut buf)
            .map_err(|e| Error::Io(e))
            .and_then(|bytes| if bytes == $size { Ok(buf) } else { Err(Error::UnexpectedEOF) })
            .map(|_| buf)
    });
}

#[cfg(test)]
mod test {
    use Error;

    #[test]
    fn should_read_to_array() {
        let bytes = [1, 2, 3, 4, 5, 6, 7];
        let reader = &mut &bytes[..];

        let result = read_array!(reader, 5);

        assert_eq!(result.unwrap(), [1, 2, 3, 4, 5]);
        assert_eq!(*reader, [6, 7]);
    }

    #[test]
    fn should_return_error_if_not_enough_bytes() {
        let bytes = [1, 2, 3, 4];
        let reader = &mut &bytes[..];

        let result = read_array!(reader, 5);

        match result {
            Err(Error::UnexpectedEOF) => (),
            _ => panic!("Invalid result: {:#?}", result)
        }
    }
}
