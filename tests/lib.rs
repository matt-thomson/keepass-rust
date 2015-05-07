extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx", "hunter2");
    assert!(result.is_ok());
}
