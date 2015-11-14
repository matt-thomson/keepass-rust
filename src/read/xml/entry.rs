use {DatabaseEntry, Error};

use xml::reader::XmlEvent;

pub fn read(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>) -> Result<DatabaseEntry, Error> {
    let mut title = None;
    let mut username = None;
    let mut password = None;

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::StartElement { name, .. })) => {
                if name.local_name == "String" {
                    let kv = try!(super::kv::read(iterator));
                    match &kv.key[..] {
                        "Title" => title = kv.value,
                        "UserName" => username = kv.value,
                        "Password" => password = kv.value,
                        _ => {}
                    }
                }
            }

            Some(Err(e)) => return Err(e),
            None => break,
            _ => {}
        }
    }

    Ok(DatabaseEntry::new(&try!(title.ok_or(Error::MissingTitle))[..],
                          &try!(username.ok_or(Error::MissingUsername))[..],
                          &try!(password.ok_or(Error::MissingPassword))[..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    use Error;

    use std::fs::File;
    use xml::reader::EventReader;

    #[test]
    fn should_read_entry() {
        let file = File::open("data/xml/entry/valid.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let entry = super::read(&mut iterator).unwrap();

        assert_eq!(entry.title(), "http://example.com");
        assert_eq!(entry.username(), "joe.bloggs");
        assert_eq!(entry.password(), "9crW5hp7SQ==");
    }

    #[test]
    fn should_return_error_on_missing_title() {
        let file = File::open("data/xml/entry/no_title.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let result = super::read(&mut iterator);

        match result {
            Err(Error::MissingTitle) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }

    #[test]
    fn should_return_error_on_missing_username() {
        let file = File::open("data/xml/entry/no_username.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let result = super::read(&mut iterator);

        match result {
            Err(Error::MissingUsername) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }

    #[test]
    fn should_return_error_on_missing_password() {
        let file = File::open("data/xml/entry/no_password.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let result = super::read(&mut iterator);

        match result {
            Err(Error::MissingPassword) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }
}
