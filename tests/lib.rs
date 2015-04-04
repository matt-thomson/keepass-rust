extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx").unwrap();

    assert_eq!(result.version, 0x00030001);
}