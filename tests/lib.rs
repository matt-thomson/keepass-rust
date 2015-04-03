extern crate keepass;

#[test]
fn should_read_database() {
    let result = keepass::read("data/test.kdbx").unwrap();

    match result {
        keepass::FileType::KeePass2 => (),
        _ => panic!("Invalid result: {:#?}", result)
    }
}
