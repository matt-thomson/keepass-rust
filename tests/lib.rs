extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx", "hunter2");
    assert!(result.is_ok());

    let database = result.unwrap();
    let entry = database.find("http://example.com");

    assert!(entry.is_some());

    assert_eq!(entry.unwrap().title(), "http://example.com");
    assert_eq!(entry.unwrap().username(), "joe.bloggs");
    assert_eq!(entry.unwrap().password(), "9crW5hp7SQ==");
}
