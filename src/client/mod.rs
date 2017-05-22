//! # Client interaction logic
use std::process::*;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

///
pub struct Client {
    pr: Option<Child>,
    client_path: PathBuf,
    log_path: PathBuf,
}

impl Client {
    fn new(client: PathBuf, log: PathBuf) -> Client {
        Client {
            pr: None,
            client_path: client,
            log_path: log,
        }

    }

    /// Launches client in child process
    fn launch<I, C>(cmd: &OsStr, args: I) -> io::Result<Child>
        where I: IntoIterator<Item = C>,
              C: AsRef<OsStr>
    {
        Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
    }

    ///
    pub fn restart() -> () {
        let mut log = default_path();
        log.push("log");
        if fs::create_dir_all(log.as_path()).is_ok() {};

        log.push("geth_log.txt");
        let f = match fs::File::create(log.as_path()) {
            Ok(f) => f,
            Err(err) => {
                error!("Unable to open node log file: {}", err);
                exit(1);
            }
        };

        let node_path = Arc::new(Mutex::new(np));
        let node = match launch_node(guard_np.as_os_str(), out, err, &["--fast"]) {
            Ok(pr) => Arc::new(Mutex::new(pr)),
            Err(err) => {
                error!("Unable to launch client: {}", err);
                exit(1);
            }
        };

        let (tx, rx) = mpsc::channel();
        {
            let nd = node.clone();
            let lf = log_file.clone();
            let np = node_path.clone();

            let restart = move |chain: &str| {
                let mut n = nd.lock().unwrap();
                n.kill().expect("Expect to kill node");

                let lf = match lf.lock().unwrap().try_clone() {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Node restart: can't redirect stdio: {}", e);
                        exit(1);
                    }
                };


                let res = match chain {
                    "TESTNET" => {
                        launch_node(np.lock().unwrap().as_os_str(), &["--testnet", "--fast"])
                    }
                    "MAINNET" | _ => launch_node(np.lock().unwrap().as_os_str(), &["--fast"]),
                };

                *n = match res {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Can't restart node: {}", e);
                        exit(1);
                    }
                };
            };

            thread::spawn(move || loop {
                let chain: String = match rx.recv() {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Can't switch node chain: {}", e);
                        exit(1);
                    }
                };
                restart(&chain);
            });
        };

    }

    ///
    pub fn chain_type() -> () {

    }
}