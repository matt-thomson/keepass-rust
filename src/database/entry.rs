pub struct DatabaseEntry {
    title: String,
    username: String,
    password: String,
}

impl DatabaseEntry {
    pub fn new(title: &str, username: &str, password: &str) -> DatabaseEntry {
        DatabaseEntry {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseEntry;

    #[test]
    fn should_create_entry() {
        let entry = DatabaseEntry::new("http://example.com", "bob", "hunter2");
        assert_eq!(entry.title(), "http://example.com");
        assert_eq!(entry.username(), "bob");
        assert_eq!(entry.password(), "hunter2");
    }
}
