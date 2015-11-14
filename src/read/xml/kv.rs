use Error;

use xml::reader::XmlEvent;

#[derive(Debug)]
pub struct KeyValue {
    pub key: String,
    pub value: Option<String>,
}

pub fn read(iterator: &mut Iterator<Item = Result<XmlEvent, Error>>) -> Result<KeyValue, Error> {
    let mut key = None;
    let mut value = None;

    loop {
        match iterator.next() {
            Some(Ok(XmlEvent::StartElement { name, .. })) => {
                match &name.local_name[..] {
                    "Key" => key = try!(super::read_chars(iterator, "Key")),
                    "Value" => value = try!(super::read_chars(iterator, "Value")),
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

#[cfg(test)]
mod tests {
    use super::*;

    use Error;

    use std::fs::File;
    use xml::reader::EventReader;

    #[test]
    fn should_read_kv() {
        let file = File::open("data/xml/kv/present.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let kv = super::read(&mut iterator).unwrap();

        assert_eq!(kv.key, "Foo");

        assert!(kv.value.is_some());
        assert_eq!(kv.value.unwrap(), "http://example.com/foo");
    }

    #[test]
    fn should_handle_missing_value() {
        let file = File::open("data/xml/kv/no_value.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let kv = super::read(&mut iterator).unwrap();

        assert_eq!(kv.key, "Foo");

        assert!(kv.value.is_none());
    }

    #[test]
    fn should_return_error_on_missing_key() {
        let file = File::open("data/xml/kv/no_key.xml").unwrap();
        let event_reader = EventReader::new(file);
        let mut iterator = event_reader.into_iter().map(|result| result.map_err(|e| Error::Xml(e)));
        let result = super::read(&mut iterator);

        match result {
            Err(Error::MissingKey) => (),
            _ => panic!("Invalid result: {:#?}", result),
        }
    }
}
