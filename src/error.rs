use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Python error: {0}")]
    Python(String),

    #[error("Security violation: {0}")]
    Security(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type AppResult<T> = Result<T, AppError>;
