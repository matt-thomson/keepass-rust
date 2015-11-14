mod entry;

use self::entry::DatabaseEntry;

pub struct Database {
    entries: Vec<DatabaseEntry>,
}

impl Database {
    pub fn new() -> Database {
        Database { entries: vec![] }
    }

    pub fn add(&mut self, title: &str, username: &str, password: &str) {
        let entry = DatabaseEntry::new(title, username, password);
        self.entries.push(entry);
    }

    pub fn find(&self, title: &str) -> Option<&DatabaseEntry> {
        self.entries.iter().find(|entry| entry.title() == title)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;

    #[test]
    fn should_create_and_find_entry() {
        let mut database = Database::new();

        database.add("http://example.com/foo", "tom", "hunter1");
        database.add("http://example.com/bar", "dick", "hunter2");
        database.add("http://example.com/baz", "harry", "hunter3");

        let entry = database.find("http://example.com/bar");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().title(), "http://example.com/bar");
        assert_eq!(entry.unwrap().username(), "dick");
        assert_eq!(entry.unwrap().password(), "hunter2");
    }
}
