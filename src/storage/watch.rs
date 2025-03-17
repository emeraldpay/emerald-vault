///
///
/// Watch availability of hardware keys.
///
/// Spins up a thread that periodically checks the status of the connected devices and send a notification back to subscribers
///
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use emerald_hwkey::ledger::connect::LedgerKeyShared;
use itertools::Itertools;
use uuid::Uuid;
use emerald_hwkey::ledger::connect::LedgerKey;
use crate::chains::Blockchain;
use crate::storage::vault::{VaultAccess};
use crate::structs::seed::{Seed, WithFingerprint};
use crate::crypto::fingerprint::Fingerprints;

const RECHECK_TIME_MS: u64 = 500;

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    /// Just get the current state without actual subscription.
    /// Used to establish the starting point for the further subscriptions.
    /// Returns the resulting event immediatelly
    GetCurrent,
    /// Subscribe to any chage after the specified version.
    /// If it's already withing a different version it immediatelly returns with a new state.
    Change { version: usize },
    /// Wait until the specified blockchain is available
    Available {
        hw_key_id: Option<Uuid>,
        blockchain: Option<Blockchain>,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// A monotonic increasing number meaning the current version of the state
    pub version: usize,
    /// Available devices within the current state
    pub devices: Vec<ConnectedDevice>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum  DeviceDetails {
    Ledger(LedgerDeviceDetails)
}

#[derive(Debug, Clone, PartialEq)]
pub struct LedgerDeviceDetails {
    /// App Name as provided by the Ledger device
    pub app: String,
    /// App Version as provided by the Ledger device. Supposed to be a SemVer
    pub app_version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectedDevice {
    /// A uniq id for the device. It doesn't have any meaning and it's not a persistent id.
    /// Used only to distinguish two different devices connected at the same time.
    pub id: Uuid,
    /// Reference to a Seed Id if it's known for the device.
    pub seed_id: Option<Uuid>,
    /// Blockchain that are currently availalbe through the device
    pub blockchains: Vec<Blockchain>,
    /// Device details
    pub device: Option<DeviceDetails>,
}

pub struct WatchLoop {
    /// Current list of watch requests that a wating for an event.
    requests: Vec<(Request, Sender<Event>)>,
    /// Version.
    version: usize,
    /// True if the Watch Loop in currently runing in a separate thread.
    launched: bool,
    /// Current connected devices
    devices: Vec<ConnectedDevice>,

    /// INTERNAL: a default ID for ledger. TODO map to a figerprint
    default_id: Uuid,
    seeds: Mutex<CurrentSeeds>,
}

impl  WatchLoop {
    fn create(seeds: Arc<Mutex<dyn VaultAccess<Seed> + Send>>) -> Self {
        WatchLoop {
            requests: vec![],
            devices: vec![],
            version: 0,
            launched: false,
            default_id: Uuid::new_v4(),
            seeds: Mutex::new(CurrentSeeds::create(seeds))
        }
    }
}

pub(crate) struct Watch {
    state: Arc<Mutex<WatchLoop>>,
}

///
/// A memory cache for current seeds to avoid reloading them in loop each time we verify a device.
/// Insteaf of reloading Seeds from disk each time we keep them in memory for up to a minute.
#[derive(Clone)]
struct CurrentSeeds {
    last_refresh: DateTime<Utc>,
    cache: Vec<Seed>,
    seeds: Arc<Mutex<dyn VaultAccess<Seed> + Send>>,
}

impl CurrentSeeds {
    fn create(seeds: Arc<Mutex<dyn VaultAccess<Seed> + Send>>) -> CurrentSeeds {
        CurrentSeeds {
            last_refresh: DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
            cache: vec![],
            seeds,
        }
    }

    ///
    /// `true` if seeds must be reloaded from the disk. Code specified it as _every minute_ (applicable only when watch is active).
    fn must_refresh(&self) -> bool {
        let ttl = Utc::now() - Duration::seconds(60);
        ttl > self.last_refresh
    }

    fn get(&mut self) -> Vec<Seed> {
        if self.must_refresh() {
            let seeds = &self.seeds.lock().unwrap();
            if let Ok(seeds) = seeds.list_entries() {
                self.cache = seeds;
            }
            self.last_refresh = Utc::now();
        }
        self.cache.clone()
    }
}

impl Watch {

    pub fn new(seeds: Arc<Mutex<dyn VaultAccess<Seed> + Send>>) -> Watch {
        Watch {
            state: Arc::new(Mutex::new(WatchLoop::create(seeds)))
        }
    }

    // The entry point
    pub(crate) fn request(&mut self, request: Request) -> Receiver<Event> {
        let (send, recv) = mpsc::channel();
        {
            let mut watch = self.state.lock().unwrap();
            watch.requests.push((request, send));
        }
        self.ensure_launched();
        recv
    }

    // Make sure it processes the request. If not then it spawns a thread to process them
    fn ensure_launched(&self) {
        let mut watch = self.state.lock().unwrap();
        if watch.launched {
            return;
        }
        (*watch).launched = true;
        let state = self.state.clone();

        // spawn a new thread that process this and all new incoming requests.
        // the thread finishes when all the requests are resolved
        thread::spawn (move || {
            Watch::in_loop(state)
        });
    }

    fn in_loop(state: Arc<Mutex<WatchLoop>>) {
        let mut run = true;
        while run {
            {
                let mut watch = state.lock().unwrap();
                (*watch).process();

                // watch.launched may swithc to false (i.e, off) so we stop the loop here too
                run = watch.launched;
            }
            if run {
                //TODO sleep only if no commands
                thread::sleep(std::time::Duration::from_millis(RECHECK_TIME_MS));
            }
        }
    }
}

impl WatchLoop {

    fn process(&mut self) {
        let mut current_devices = vec![];
        if let Ok(connected) = LedgerKeyShared::instance() {
            current_devices.push(self.connected_details(&connected));
        }

        let changed = current_devices.len() != self.devices.len()
            || current_devices.iter().any(|curr| { !self.devices.iter().contains(curr) });

        // update state (devices, version, etc) _only_ if anything changed
        if changed {
            self.devices = current_devices;
            self.version = self.version + 1;
        }

        // cheack all the current requests regardles the chage. some of them may come later and the current state may be a fit for them
        let mut left_requests = vec![];
        for req in &self.requests {
            let accepted = match req.0 {
                Request::GetCurrent => {
                    true
                }
                Request::Change { version} => {
                    self.version != version
                },
                Request::Available { blockchain, hw_key_id} => {
                    WatchLoop::is_available(blockchain, hw_key_id, &self.devices)
                }
            };
            if accepted {
                let _ = req.1.send(Event { version: self.version, devices: self.devices.clone()});
            }
            let keep = !accepted;
            if keep {
                left_requests.push(req.clone());
            }
        }
        self.requests = left_requests;

        // stop when we have no more requests
        self.launched = !self.requests.is_empty();
    }

    fn connected_details<LK: LedgerKey + 'static>(&self, ledger: &LedgerKeyShared<LK>) -> ConnectedDevice {

        let blockchains;
        let device;
        if let Ok(app) = ledger.get_app_details() {
            blockchains = match app.name.as_str() {
                "Ethereum" => vec![Blockchain::Ethereum],
                "Ethereum Classic" => vec![Blockchain::EthereumClassic],
                "Goerli Testnet" => vec![Blockchain::GoerliTestnet],
                "Holesky Testnet" => vec![Blockchain::HoleskyTestnet],
                "Sepolia Testnet" => vec![Blockchain::SepoliaTestnet],
                "Bitcoin" => vec![Blockchain::Bitcoin],
                "Bitcoin Test" => vec![Blockchain::BitcoinTestnet],
                _ => vec![]
            };
            let ledger_details = LedgerDeviceDetails {
                app: app.name,
                app_version: app.version
            };
            device = Some(DeviceDetails::Ledger(ledger_details));
        } else {
            blockchains = vec![];
            device = None;
        };

        let seed_id = self.find_seed_id(ledger);
        ConnectedDevice {
            id: self.default_id, //TODO should be uniq per device, ex. based on device S/N
            seed_id,
            blockchains,
            device,
        }
    }

    fn find_seed_id<LK: LedgerKey + 'static>(&self, ledger: &LedgerKeyShared<LK>) -> Option<Uuid> {
        if let Ok(fps) = ledger.find_fingerprints() {
            let mut current_seeds = self.seeds.lock().unwrap();
            let seeds = current_seeds.get();
            let related_seed = seeds.iter().find(|seed| {
                fps.iter().any(|fp| seed.is_same(fp))
            });
            if let Some(seed) = related_seed {
                return Some(seed.id.clone());
            }
        }
        None
    }

}

impl WatchLoop {

    fn is_available(blockchain: Option<Blockchain>, id: Option<Uuid>, devices: &Vec<ConnectedDevice>) -> bool {
        devices.iter().any(|d| {
            let ok_blockchain = if let Some(blockchain) = blockchain {
                d.blockchains.contains(&blockchain)
            } else {
                true
            };
            let ok_id = if let Some(id) = id {
                d.id == id
            } else {
                true
            };
            debug!("Available: {:?} {:?} -> {}", blockchain, id, ok_blockchain && ok_id);
            ok_blockchain && ok_id
        })
    }

}

#[cfg(test)]
mod tests {
    use std::io::stdin;
    use tempdir::TempDir;
    use crate::chains::Blockchain;
    use crate::storage::vault::VaultStorage;
    use crate::storage::watch::Request;
    use crate::tests::init_tests;

    #[test]
    #[cfg(integration_test)]
    fn listen_disconnected_to_ethereum() {
        init_tests();
        let mut buffer = String::new();

        println!("DO: Disconnect Ledger [ENTER]");
        stdin().read_line(&mut buffer).unwrap();

        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let wait = vault.watch(Request::GetCurrent).recv().expect("Get Current State");
        let start_version = wait.version;
        assert_eq!(wait.devices.len(), 0);

        println!("WAIT: Connect Ledger");

        let wait = vault.watch(Request::Change {version: start_version}).recv();
        println!("REPL: State changed");
        assert!(wait.is_ok());

        println!("WAIT: Open Ethereum App");
        let wait = vault.watch(Request::Available { blockchain: Some(Blockchain::Ethereum), hw_key_id: None}).recv();
        println!("REPL: App become available");
        assert!(wait.is_ok());

        let event = wait.unwrap();
        assert_eq!(event.devices.len(), 1);
        assert_eq!(event.devices[0].blockchains[0], Blockchain::Ethereum);
    }
}
