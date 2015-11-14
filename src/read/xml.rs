use Error;

use std::io::Read;

use xml::reader::EventReader;

pub fn read(reader: &mut Read) -> Result<(), Error> {
    let event_reader = EventReader::new(reader);

    for e in event_reader {
        println!("{:?}", e);
    }

    Ok(())
}
