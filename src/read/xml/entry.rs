use {DatabaseEntry, Error};
use protected::ProtectedStream;

use xml::reader::XmlEvent;

pub fn read(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>,
            protected: &mut ProtectedStream)
            -> Result<DatabaseEntry, Error> {
    let mut title = None;
    let mut username = None;
    let mut password = None;

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::StartElement { name, .. })) => {
                if name.local_name == "String" {
                    let kv = try!(super::kv::read(iterator, protected));
                    match &kv.key[..] {
                        "Title" => title = kv.value,
                        "UserName" => username = kv.value,
                        "Password" => password = kv.value,
                        _ => {}
                    }
                }
            }
            Some(Ok(XmlEvent::EndElement { name, .. })) => {
                if name.local_name == "Entry" {
                    break;
                }
            }

            Some(Err(e)) => return Err(e),
            None => break,
            _ => {}
        }
    }

    Ok(DatabaseEntry::new(title, username, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protected::ProtectedStream;

    use Error;

    use std::fs::File;
    use xml::reader::EventReader;

    #[test]
    fn should_read_entry() {
        let file = File::open("data/xml/entry/valid.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let mut protected = ProtectedStream::none();
        let entry = super::read(&mut iterator, &mut *protected).unwrap();

        assert!(entry.title().is_some());
        assert_eq!(entry.title().as_ref().unwrap(), "http://example.com");

        assert!(entry.username().is_some());
        assert_eq!(entry.username().as_ref().unwrap(), "joe.bloggs");

        assert!(entry.password().is_some());
        assert_eq!(entry.password().as_ref().unwrap(), "9crW5hp7SQ==");
    }

    #[test]
    fn should_handle_missing_values() {
        let file = File::open("data/xml/entry/no_values.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let mut protected = ProtectedStream::none();
        let entry = super::read(&mut iterator, &mut *protected).unwrap();

        assert!(entry.title().is_none());
        assert!(entry.username().is_none());
        assert!(entry.password().is_none());
    }
}
