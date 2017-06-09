//! # Node managment

mod error;

use subprocess::{self, Exec, Popen, Redirection, PopenConfig};
use self::error::Error;

pub enum Chain {
    Mainnet,
    Testnet
}

pub trait NodeControl {
    ///
    fn start(&mut self) -> Result<(), Error>;

    ///
    fn stop(&mut self) -> Result<(), Error>;

    ///
    fn switch (&mut self, c: Chain) -> Result<(), Error>;
}

static args: Vec<&str> = vec!["geth", "--fast", "--cache=1024"];

struct GethControl {
    pc: Popen
}

impl NodeControl for GethControl  {
    fn start(&mut self) -> Result<(), Error> {
        self.pc = Popen::create(&args, PopenConfig {
            stdout: Redirection::Pipe,
            stderr: Redirection::Merge,
            ..Default::default()
        })?
    }

    fn stop(&mut self) -> Result<(), Error>{
        self.pc.terminate()?
    }

    fn switch(&mut self, c: Chain) -> Result<(), Error> {
        match c {
            Chain::Mainnet => {
                self.start(Chain::Mainnet)
            }

            Chain::Testnet => {
                self.start(Chain::Testnet)
            }
        }
    }
}

impl GethControl {
    ///
    fn new() -> Result<Self, Error> {
        GethControl {
            pc: Popen::create(&["geth", "--chain=morden", "fast"], PopenConfig {
                stdout: Redirection::Pipe, ..Default::default()
            })?
        }
    }
}

///
pub fn get_control<T: NodeControl>() -> T {
    GethControl::new()
}



