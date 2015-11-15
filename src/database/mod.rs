mod entry;

pub use self::entry::DatabaseEntry;

#[derive(Debug)]
pub struct Database {
    entries: Vec<DatabaseEntry>,
}

impl Database {
    pub fn new() -> Database {
        Database { entries: vec![] }
    }

    pub fn add(&mut self, entry: DatabaseEntry) {
        self.entries.push(entry);
    }

    pub fn find(&self, title: &str) -> Option<&DatabaseEntry> {
        self.entries.iter().find(|entry| entry.matches_title(title))
    }
}

#[cfg(test)]
mod tests {
    use {Database, DatabaseEntry};

    #[test]
    fn should_create_and_find_entry() {
        let mut database = Database::new();

        database.add(DatabaseEntry::new(Some("http://example.com/foo".to_string()),
                                        Some("tom".to_string()),
                                        Some("hunter1".to_string())));
        database.add(DatabaseEntry::new(Some("http://example.com/bar".to_string()),
                                        Some("dick".to_string()),
                                        Some("hunter2".to_string())));
        database.add(DatabaseEntry::new(Some("http://example.com/baz".to_string()),
                                        Some("harry".to_string()),
                                        Some("hunter3".to_string())));

        let entry = database.find("http://example.com/bar");
        assert!(entry.is_some());

        assert_eq!(entry.unwrap().title().as_ref().unwrap(), "http://example.com/bar");
        assert_eq!(entry.unwrap().username().as_ref().unwrap(), "dick");
        assert_eq!(entry.unwrap().password().as_ref().unwrap(), "hunter2");
    }
}
