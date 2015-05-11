extern crate keepass;

#[test]
#[ignore]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx", "hunter2");

    println!("{:?}", result);
    assert!(result.is_ok());
}
