use Error;

use std::io::Read;

use xml::reader::EventReader;

pub fn read(reader: &mut Read) -> Result<(), Error> {
    let mut event_reader = EventReader::new(reader);

    for e in event_reader.events() {
        println!("{:?}", e);
    }

    Ok(())
}
