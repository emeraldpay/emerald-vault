use crate::error::VaultError;
use std::path::Path;
use uuid::Uuid;

/// Migration Results
#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Default)]
pub struct MigrationResult {
    /// Ids of newly created wallets
    pub wallets: Vec<Uuid>,
    /// Log of the migration
    pub logs: Vec<LogMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogMessage {
    Error(String),
    Warning(String),
    Info(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    VaultError(String),
    OtherError(String),
}

pub trait Migrate {
    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError>
    where
        P: AsRef<Path>;
}

impl From<VaultError> for MigrationError {
    fn from(err: VaultError) -> Self {
        MigrationError::VaultError(err.to_string())
    }
}

impl From<String> for MigrationError {
    fn from(err: String) -> Self {
        MigrationError::OtherError(err)
    }
}


impl LogMessage {
    fn get_msg(&self) -> &String {
        match self {
            LogMessage::Error(msg) => msg,
            LogMessage::Warning(msg) => msg,
            LogMessage::Info(msg) => msg,
        }
    }
}

impl MigrationResult {
    /// Add ERROR message into the log
    pub fn error(&mut self, msg: String) {
        self.logs.push(LogMessage::Error(msg))
    }
    /// Add WARN message into the log
    pub fn warn(&mut self, msg: String) {
        self.logs.push(LogMessage::Warning(msg))
    }
    /// Add INFO message into the log
    pub fn info(&mut self, msg: String) {
        self.logs.push(LogMessage::Info(msg))
    }

    /// _Replaces_ list of wallet ids with new list
    pub fn set_wallets(&mut self, wallets: Vec<Uuid>) {
        self.wallets = wallets
    }

    /// Convert logs into a multiline string, suitable to save into a file
    pub fn logs_to_string(&self) -> String {
        let mut buf = String::new();

        self.logs.iter().for_each(|l| {
            match l {
                LogMessage::Error(_) => buf.push_str("ERROR  "),
                LogMessage::Warning(_) => buf.push_str("WARN   "),
                LogMessage::Info(_) => buf.push_str("INFO   "),
            };
            buf.push_str(l.get_msg());
            buf.push('\n');
        });

        buf
    }

    pub fn has_log(&self) -> bool {
        self.logs.iter().any(|l| match l {
            LogMessage::Warning(_) | LogMessage::Error(_) => true,
            LogMessage::Info(_) => false,
        })
    }
}
