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
        self.entries.iter().find(|entry| entry.title() == title)
    }
}

#[cfg(test)]
mod tests {
    use {Database, DatabaseEntry};

    #[test]
    fn should_create_and_find_entry() {
        let mut database = Database::new();

        database.add(DatabaseEntry::new("http://example.com/foo", "tom", "hunter1"));
        database.add(DatabaseEntry::new("http://example.com/bar", "dick", "hunter2"));
        database.add(DatabaseEntry::new("http://example.com/baz", "harry", "hunter3"));

        let entry = database.find("http://example.com/bar");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().title(), "http://example.com/bar");
        assert_eq!(entry.unwrap().username(), "dick");
        assert_eq!(entry.unwrap().password(), "hunter2");
    }
}
