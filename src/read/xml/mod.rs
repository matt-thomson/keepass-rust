mod entry;
mod kv;

use {Database, Error};
use protected::ProtectedStream;

use std::io::Read;

use xml::reader::{EventReader, XmlEvent};

pub fn read(reader: &mut Read, protected: &mut ProtectedStream) -> Result<Database, Error> {
    let event_reader = EventReader::new(reader);
    let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));

    let mut database = Database::new();

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::StartElement { name, .. })) => {
                match &name.local_name[..] {
                    "Entry" => database.add(try!(entry::read(&mut iterator, protected))),
                    _ => {}
                }
            }

            Some(Err(e)) => return Err(e),
            None => break,

            _ => {}
        }
    }

    Ok(database)
}

fn read_chars(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>,
              element: &str)
              -> Result<Option<String>, Error> {
    let mut result = None;

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::Characters(chars))) => result = Some(chars),
            Some(Ok(XmlEvent::EndElement { name, .. })) => {
                if name.local_name == element {
                    break;
                }
            }

            Some(Err(e)) => return Err(e),
            None => break,
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protected::ProtectedStream;

    use std::fs::File;

    #[test]
    fn should_read_xml() {
        let mut file = File::open("data/xml/example.xml").unwrap();
        let mut protected = ProtectedStream::none();
        let database = super::read(&mut file, &mut *protected).unwrap();

        let entry = database.find("http://example.com");
        assert!(entry.is_some());

        assert_eq!(entry.unwrap().title(), "http://example.com");
        assert_eq!(entry.unwrap().username().as_ref().unwrap(), "joe.bloggs");
        assert_eq!(entry.unwrap().password().as_ref().unwrap(), "9crW5hp7SQ==");
    }
}
