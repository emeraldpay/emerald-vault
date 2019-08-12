/// # Simple progress indication
use std::io::{stdout, Write};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::{thread, time};

/// Printing interval in milliseconds
const PRINT_PULSE_MILLISEC: u64 = 500;

/// Progress indication for long running tasks
pub struct ProgressIndicator {
    tx: SyncSender<()>,
}

impl ProgressIndicator {
    /// Start progress indication.
    /// Optional message describes long running task,
    /// if no message provided default `Processing` will be used.
    ///
    /// # Arguments:
    ///
    /// * msg - task description
    ///
    pub fn start(msg: Option<String>) -> Self {
        let (tx, rx) = mpsc::sync_channel(0);
        thread::spawn(move || {
            match msg {
                Some(m) => print!("{}", m),
                None => print!("Processing"),
            };

            loop {
                match rx.try_recv() {
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        print!("\r");
                        stdout().flush().unwrap();
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        print!(".");
                        stdout().flush().unwrap();
                    }
                }
                thread::sleep(time::Duration::from_millis(PRINT_PULSE_MILLISEC));
            }
        });

        ProgressIndicator { tx }
    }

    /// Stop progress indication
    pub fn stop(&self) {
        self.tx.send(()).unwrap();
    }
}
