use super::{Chain, NodeController, get_log_name};
use super::error::Error;
use std::fs::File;
use std::path::PathBuf;
use subprocess::{Popen, PopenConfig, Redirection};

static MAINNET_ARGS: [&str; 4] = ["geth", "--chain=mainnet", "--fast", "--cache=1024"];
static TESTNET_ARGS: [&str; 4] = ["geth", "--chain=morden", "--fast", "--cache=1024"];

///
pub struct GethController {
    ///
    pc: Popen,

    ///
    log_path: PathBuf,
}

impl NodeController for GethController {
    fn start(&mut self, c: Chain) -> Result<(), Error> {
        let a = match c {
            Chain::Mainnet => &MAINNET_ARGS,
            Chain::Testnet => &TESTNET_ARGS,
        };

        let mut path = self.log_path.clone();
        path.push(get_log_name());
        let log = File::create(path)?;

        self.pc = Popen::create(a,
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

impl GethController {
    ///
    pub fn new(p: PathBuf) -> Result<Self, Error> {
        let mut ctrl = GethController {
               log_path: p,
               pc: Popen::create(&[""], PopenConfig::default())?,
           };
        ctrl.start(Chain::Testnet)?;

        Ok(ctrl)
    }
}

unsafe impl Send for GethController {}
unsafe impl Sync for GethController {}
