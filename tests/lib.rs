extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx", "hunter2");
    assert_eq!(&result.unwrap()[0..8], &[0xdd, 0xad, 0x78, 0x89, 0x6d, 0xc9, 0x6c, 0x70]);
}
