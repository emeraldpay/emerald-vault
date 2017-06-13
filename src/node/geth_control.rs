use super::{Chain, NodeController};
use super::{merge_vec, timestamp};
use super::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use subprocess::{Popen, PopenConfig, Redirection};

static MAINNET_ARGS: [&str; 3] = ["--chain=mainnet", "--fast", "--cache=1024"];
static TESTNET_ARGS: [&str; 3] = ["--chain=morden", "--fast", "--cache=1024"];

/// Controller for `geth` node
pub struct GethController {
    /// Child process of node
    pc: Popen,

    /// Path to log directory
    log_dir: PathBuf,

    /// Path to client's executable
    client: String,
}

unsafe impl Send for GethController {}
unsafe impl Sync for GethController {}

impl GethController {
    /// Create and launch `geth` controller connected to `testnet`
    ///
    /// # Arguments:
    /// cl_path - path to client executable
    /// log_dir - path to log directory
    pub fn create<P: AsRef<Path>>(cl_path: P, log_path: P) -> Result<Self, Error> {
        if let Some(cl_str) = cl_path.as_ref().to_str() {
            let args = merge_vec::<&str>(&vec![cl_str], &TESTNET_ARGS.to_vec());

            let log = create_log(&log_path)?;
            let ctrl = GethController {
                log_dir: PathBuf::from(log_path.as_ref()),
                client: String::from(cl_str),
                pc: Popen::create(&args,
                                  PopenConfig {
                                      stderr: Redirection::File(log),
                                      ..Default::default()
                                  })?,
            };

            return Ok(ctrl);
        }
        Err(Error::ControllerFault("Invalid path to client executable".to_string()))
    }
}

impl NodeController for GethController {
    fn start(&mut self, c: Chain) -> Result<(), Error> {
        let a = match c {
            Chain::Mainnet => &MAINNET_ARGS,
            Chain::Testnet => &TESTNET_ARGS,
        };

        let args = merge_vec::<&str>(&vec![&self.client], &a.to_vec());
        let log = create_log(&self.log_dir)?;
        self.pc = Popen::create(&args,
                                PopenConfig {
                                    stderr: Redirection::File(log),
                                    ..Default::default()
                                })?;

        Ok(())
    }

    fn stop(&mut self) -> Result<(), Error> {
        self.pc.terminate()?;
        self.pc.wait()?;
        Ok(())
    }

    fn switch(&mut self, c: Chain) -> Result<(), Error> {
        self.stop()?;
        self.start(c)?;

        Ok(())
    }
}

/// Creates log file with name `client-<yyy-mm-ddThh-mm-ss>.log`
///
/// # Arguments:
/// p - path to log directory
///
pub fn create_log<P: AsRef<Path>>(p: P) -> Result<File, Error> {
    let mut name = String::from("client-");
    name.push_str(&timestamp());
    name.push_str(".log");

    let mut path = PathBuf::from(p.as_ref());
    path.push(name);
    let log_flie = File::create(path)?;

    Ok(log_flie)
}
