#[derive(Debug)]
pub struct DatabaseEntry {
    title: String,
    username: Option<String>,
    password: Option<String>,
}

impl DatabaseEntry {
    pub fn new(title: &str, username: Option<String>, password: Option<String>) -> DatabaseEntry {
        DatabaseEntry {
            title: title.to_string(),
            username: username,
            password: password,
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn username(&self) -> &Option<String> {
        &self.username
    }

    pub fn password(&self) -> &Option<String> {
        &self.password
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseEntry;

    #[test]
    fn should_create_entry() {
        let entry = DatabaseEntry::new("http://example.com",
                                       Some("bob".to_string()),
                                       Some("hunter2".to_string()));
        assert_eq!(entry.title(), "http://example.com");

        assert!(entry.username().is_some());
        assert_eq!(entry.username().as_ref().unwrap(), "bob");

        assert!(entry.password().is_some());
        assert_eq!(entry.password().as_ref().unwrap(), "hunter2");
    }
}
