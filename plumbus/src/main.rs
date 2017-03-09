extern crate ethcore_bigint as bigint;

use bigint::hash::{H160, H256, H512};
use rand::os::OsRng;

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

pub type Address = H160;
pub type Message = H256;
pub type Public = H512;

trait Generator {
    fn generate(self) -> Result<KeyPair, Error>;
}

struct Prefix;
struct Random;
struct KeyPair {
    secret: Secret,
    public: Public,
}

impl Generator for Random{
    fn generate(self) -> Result<KeyPair, Error> {
        let context = &SECP256K1;
        let mut rng = OsRng::new()?;
        let (sec, publ) = context.generate_keypair(&mut rng)?;

        Ok(KeyPair::from_keypair(sec, publ))
    }
}

impl Generator for Prefix {
    fn generate(self) -> Result<KeyPair, Error> {
        let keypair = Random.generate()?;
        let context = &SECP256K1;
        let mut rng = OsRng::new()?;

        loop {
            match find_keys(seed).find() {
                Some(key) => {
                    println!("Key generated: {}", key.);
                },
                None => {},
            }

            if keypair.address().starts_with(&self.prefix) {
                return Ok(keypair)
            }
        }

        Err(Error::Custom("Could not find keypair".into()))
    }
}

impl KeyPair {
    pub fn address(&self) -> Address {
        let hash = self.public.keccak256();
        let mut result = Address::default();
        result.copy_from_slice(&hash[12..]);
        result
    }
}

pub fn public_to_address(public: &Public) -> Address {
    let hash = public.keccak256();
    let mut result = Address::default();
    result.copy_from_slice(&hash[12..]);
    result
}

fn key_match(pair: KeyPair) -> u32 {

}

fn main() {
    let prefix = args.arg_prefix.from_hex()?;
    Prefix.generate()?;
    println!("Hello, world!");
}


#[cfg(test)]
mod tests {
    use super::execute;
    use {Generator, Prefix};

    #[test]
    fn prefix_generator() {
        let prefix = vec![0xffu8];
        let keypair = Prefix::new(prefix.clone(), usize::max_value()).generate().unwrap();
        assert!(keypair.address().starts_with(&prefix));
    }

    #[test]
    fn generate() {
        let command = vec!["ethkey", "generate", "brain", "this is sparta", "--address"]
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>();

        let expected = "26d1ec50b4e62c1d1a40d16e7cacc6a6580757d5".to_owned();
        assert_eq!(execute(command).unwrap(), expected);
    }
}