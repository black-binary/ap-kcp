use std::error::Error as StdError;
use std::fmt;
use std::io::{self, ErrorKind};

#[derive(Debug)]
pub enum KcpError {
    TooManyStreams,
    InvalidSegmentDataSize(usize, usize),
    IoError(io::Error),
    UnsupportCmd(u8),
    Timeout,
    NoResponse,
    Shutdown(String),
    InvalidConfig(String),
}

impl StdError for KcpError {}

impl fmt::Display for KcpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

fn make_io_error<T>(kind: ErrorKind, msg: T) -> io::Error
where
    T: Into<Box<dyn StdError + Send + Sync>>,
{
    io::Error::new(kind, msg)
}

impl From<KcpError> for io::Error {
    fn from(err: KcpError) -> io::Error {
        let kind = match err {
            KcpError::IoError(err) => return err,
            _ => ErrorKind::Other,
        };

        make_io_error(kind, err)
    }
}

impl From<io::Error> for KcpError {
    fn from(err: io::Error) -> KcpError {
        KcpError::IoError(err)
    }
}

/// KCP result
pub type KcpResult<T> = Result<T, KcpError>;
