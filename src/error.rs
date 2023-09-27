use std::time::Duration;

/// Errors that can be returned by the API
#[derive(Debug)]
pub enum Error {
    /// Networking problems, source will be a std::io::Error
    NetworkError { source: std::io::Error },

    /// The Duration specified was not long enough
    DurationTooShort { minimum: Duration },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError { source } => write!(f, "Network error: {}", source),
            Self::DurationTooShort { minimum } => {
                write!(
                    f,
                    "Duration too short. The minimum allowed here is {:?}",
                    minimum
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NetworkError { source } => Some(source),
            Self::DurationTooShort { .. } => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Self::NetworkError { source: e }
    }
}
