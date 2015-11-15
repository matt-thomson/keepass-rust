extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx", "hunter2");
    assert!(result.is_ok());

    let database = result.unwrap();
    let entry = database.find("http://example.com").unwrap();

    assert_eq!(entry.title().as_ref().unwrap(), "http://example.com");
    assert_eq!(entry.username().as_ref().unwrap(), "joe.bloggs");
    assert_eq!(entry.password().as_ref().unwrap(), "hunter2");
}
