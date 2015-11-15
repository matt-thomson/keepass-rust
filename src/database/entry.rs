#[derive(Debug)]
pub struct DatabaseEntry {
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

impl DatabaseEntry {
    pub fn new(title: Option<String>,
               username: Option<String>,
               password: Option<String>)
               -> DatabaseEntry {
        DatabaseEntry {
            title: title,
            username: username,
            password: password,
        }
    }

    pub fn title(&self) -> &Option<String> {
        &self.title
    }

    pub fn username(&self) -> &Option<String> {
        &self.username
    }

    pub fn password(&self) -> &Option<String> {
        &self.password
    }

    pub fn matches_title(&self, title: &str) -> bool {
        match self.title {
            Some(ref t) => title == t,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseEntry;

    #[test]
    fn should_create_entry() {
        let entry = DatabaseEntry::new(Some("http://example.com".to_string()),
                                       Some("bob".to_string()),
                                       Some("hunter2".to_string()));

        assert!(entry.title().is_some());
        assert_eq!(entry.title().as_ref().unwrap(), "http://example.com");

        assert!(entry.username().is_some());
        assert_eq!(entry.username().as_ref().unwrap(), "bob");

        assert!(entry.password().is_some());
        assert_eq!(entry.password().as_ref().unwrap(), "hunter2");
    }
}
