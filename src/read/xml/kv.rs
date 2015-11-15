use Error;
use protected::ProtectedStream;

use xml::attribute::OwnedAttribute;
use xml::reader::XmlEvent;

#[derive(Debug)]
pub struct KeyValue {
    pub key: String,
    pub value: Option<String>,
}

pub fn read(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>,
            protected: &mut ProtectedStream)
            -> Result<KeyValue, Error> {
    let mut key = None;
    let mut value = None;

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::StartElement { name, attributes, .. })) => {
                match &name.local_name[..] {
                    "Key" => key = try!(super::read_chars(iterator, "Key")),
                    "Value" => value = try!(read_value(iterator, protected, &attributes[..])),
                    _ => {}
                }
            }
            Some(Ok(XmlEvent::EndElement { name, .. })) => {
                if name.local_name == "String" {
                    break;
                }
            }

            Some(Err(e)) => return Err(e),
            None => break,
            _ => {}
        }
    }

    Ok(KeyValue {
        key: try!(key.ok_or(Error::MissingKey)),
        value: value,
    })
}

fn read_value(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>,
              protected: &mut ProtectedStream,
              attributes: &[OwnedAttribute])
              -> Result<Option<String>, Error> {
    let mut is_protected = false;

    for attribute in attributes {
        if attribute.name.local_name == "Protected" && attribute.value == "True" {
            is_protected = true;
        }
    }

    match try!(super::read_chars(iterator, "Value")) {
        Some(value) => {
            if is_protected {
                Ok(Some(try!(protected.decrypt(&value))))
            } else {
                Ok(Some(value))
            }
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use Error;
    use protected::ProtectedStream;

    use std::fs::File;
    use xml::reader::EventReader;

    const KEY: [u8; 32] = [0xE4, 0x70, 0xC4, 0xEF, 0x95, 0x61, 0x22, 0xDF, 0x2C, 0x0D, 0xD1, 0x42,
                           0x4A, 0x24, 0xE6, 0x87, 0x79, 0x29, 0xB9, 0xAD, 0x47, 0x9C, 0x0E, 0xA5,
                           0xA0, 0x5D, 0xB1, 0x27, 0x7A, 0xDF, 0xBD, 0xCD];

    #[test]
    fn should_read_kv() {
        let file = File::open("data/xml/kv/present.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));

        let mut protected = ProtectedStream::salsa20(&KEY);
        let kv = super::read(&mut iterator, &mut *protected).unwrap();

        assert_eq!(kv.key, "Foo");

        assert!(kv.value.is_some());
        assert_eq!(kv.value.unwrap(), "http://example.com/foo");
    }

    #[test]
    fn should_handle_missing_value() {
        let file = File::open("data/xml/kv/no_value.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));

        let mut protected = ProtectedStream::salsa20(&KEY);
        let kv = super::read(&mut iterator, &mut *protected).unwrap();

        assert_eq!(kv.key, "Foo");

        assert!(kv.value.is_none());
    }

    #[test]
    fn should_return_error_on_missing_key() {
        let file = File::open("data/xml/kv/no_key.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));

        let mut protected = ProtectedStream::salsa20(&KEY);
        let result = super::read(&mut iterator, &mut *protected);

        match result {
            Err(Error::MissingKey) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }

    #[test]
    fn should_handle_protected_value() {
        let file = File::open("data/xml/kv/protected.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));

        let mut protected = ProtectedStream::salsa20(&KEY);
        let kv = super::read(&mut iterator, &mut *protected).unwrap();

        assert_eq!(kv.key, "Password");

        assert!(kv.value.is_some());
        assert_eq!(kv.value.unwrap(), "hunter2");
    }
}
