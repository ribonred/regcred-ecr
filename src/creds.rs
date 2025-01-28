use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub access: String,
    pub secret: String,
    pub session: Option<String>,
    pub region: String,
}

impl Config {
    pub(crate) fn new() -> Self {
        Config {
            access: "changeme".to_string(),
            secret: "changeme".to_string(),
            region: "changeme-northeast-1".to_string(),
            session: Option::from(
                "changeme"
                    .to_string()),
            // or None if not using session, can comment out the line above and uncomment the line below
            // session: None,
        }
    }
}