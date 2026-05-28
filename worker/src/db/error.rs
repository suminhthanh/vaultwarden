use std::fmt;

#[allow(dead_code)]
#[derive(Debug)]
pub enum DbError {
    NotFound,
    Worker(String),
    Decode(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::Worker(msg) => write!(f, "worker error: {msg}"),
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<worker::Error> for DbError {
    fn from(err: worker::Error) -> Self {
        Self::Worker(err.to_string())
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        Self::Decode(err.to_string())
    }
}

pub type DbResult<T> = Result<T, DbError>;
