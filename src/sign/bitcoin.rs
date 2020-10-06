use crate::{
    blockchain::{
        bitcoin::{
            AddressType,
            BitcoinTransferProposal,
            InputReference,
            InputScriptSource,
            KeyMapping,
        },
        chains::Blockchain,
    },
    sign::key_source::PrivateKeySource,
    storage::{error::VaultError, vault::VaultStorage},
    structs::{book::AddressRef, wallet::WalletEntry},
};
use bitcoin::{
    blockdata::{opcodes, script::Builder},
    consensus::{serialize, Encodable},
    util::{bip143::SighashComponents, bip32::ChildNumber, psbt::serialize::Serialize},
    Address,
    Network,
    PrivateKey,
    PublicKey,
    Script,
    SigHash,
    SigHashType,
    Transaction,
    TxIn,
    TxOut,
};
use bitcoin_hashes::{hash160::Hash as hash160, sha256, Hash, HashEngine};
use secp256k1::{All, Message, Secp256k1, Signature};
use std::io;

lazy_static! {
    pub static ref DEFAULT_SECP256K1: Secp256k1<All> = Secp256k1::new();
}

// For reference:
// - https://en.bitcoin.it/wiki/BIP_0143

fn encode_signature(sig: Signature) -> Vec<u8> {
    let sig = sig.serialize_der().to_vec();
    let mut result = Vec::with_capacity(sig.len() + 1);
    result.extend(sig);
    result.push(SigHashType::All as u8);
    result
}

impl From<Blockchain> for Network {
    fn from(b: Blockchain) -> Self {
        match b {
            Blockchain::Bitcoin => Network::Bitcoin,
            Blockchain::BitcoinTestnet => Network::Testnet,
            _ => panic!("not a bitcoin"),
        }
    }
}

impl WalletEntry {
    pub fn sign_bitcoin(&self, tx: BitcoinTransferProposal) -> Result<Vec<u8>, VaultError> {
        let signed = tx.seal()?;
        Ok(signed.serialize())
    }

    pub fn bitcoin_address(&self, change: u32, index: u32) -> Result<Address, VaultError> {
        match &self.address {
            None => Err(VaultError::PublicKeyUnavailable),
            Some(address_ref) => match address_ref {
                AddressRef::ExtendedPub(xpub) => {
                    let network = Network::from(self.blockchain);

                    let change_child = ChildNumber::from_normal_idx(change)
                        .map_err(|_| VaultError::InvalidDataError("change".to_string()))?;
                    let change_pubkey = xpub
                        .value
                        .ckd_pub(&DEFAULT_SECP256K1, change_child)
                        .map_err(|_| VaultError::InvalidDataError("xpub".to_string()))?;

                    let index_child = ChildNumber::from_normal_idx(index)
                        .map_err(|_| VaultError::InvalidDataError("index".to_string()))?;
                    let pubkey = change_pubkey
                        .ckd_pub(&DEFAULT_SECP256K1, index_child)
                        .map_err(|_| VaultError::InvalidDataError("xpub".to_string()))?;

                    match xpub.address_type {
                        AddressType::P2WPKH => {
                            Address::p2wpkh(&pubkey.public_key, network.clone())
                                .map_err(|_| VaultError::PublicKeyUnavailable)
                        }
                        //TODO support other types
                        _ => Err(VaultError::InvalidDataError("address_type".to_string())),
                    }
                }
                _ => Err(VaultError::PublicKeyUnavailable),
            },
        }
    }
}


impl InputScriptSource {
    fn to_pk(&self, proposal: &BitcoinTransferProposal) -> Result<PrivateKey, VaultError> {
        match self {
            InputScriptSource::HD(seed, hd_path) => {
                let seed = proposal
                    .get_seed(seed)
                    .ok_or(VaultError::PrivateKeyUnavailable)?;
                let password = proposal.keys.get_password(&seed.id)?;
                let pk = seed
                    .source
                    .get_pk(Some(password), hd_path)?
                    .into_bitcoin_key(&proposal.network);
                Ok(pk)
            }
        }
    }
}


impl InputReference {
    pub fn get_pk(&self, proposal: &BitcoinTransferProposal) -> Result<PrivateKey, VaultError> {
        self.script_source.to_pk(proposal)
    }

    pub fn get_pubkey(&self, proposal: &BitcoinTransferProposal) -> Result<PublicKey, VaultError> {
        Ok(self.get_pk(proposal)?.public_key(&DEFAULT_SECP256K1))
    }

    pub fn to_address(&self, proposal: &BitcoinTransferProposal) -> Result<Address, VaultError> {
        let pubkey = self.get_pubkey(proposal)?;
        let address = Address::p2wpkh(&pubkey, proposal.network.clone())
            .map_err(|_| VaultError::PublicKeyUnavailable)?;
        Ok(address)
    }

    pub fn to_sign_script(&self, proposal: &BitcoinTransferProposal) -> Result<Script, VaultError> {
        let pubkey = self.get_pubkey(proposal)?;
        Ok(Address::p2pkh(&pubkey, proposal.network).script_pubkey())
        //
        // SPEC:
        // >> For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac
        //
        // Can be also:
        //
        // let pubkey_hash = hash160::hash(&pubkey.key.serialize()).to_vec();
        // let script = Builder::new()
        //     .push_opcode(opcodes::all::OP_DUP)
        //     .push_opcode(opcodes::all::OP_HASH160)
        //     .push_slice(pubkey_hash.as_slice())
        //     .push_opcode(opcodes::all::OP_EQUALVERIFY)
        //     .push_opcode(opcodes::all::OP_CHECKSIG)
        //     .into_script();
        // Ok(script)
    }

    pub fn sign(
        &self,
        proposal: &BitcoinTransferProposal,
        tx: &Transaction,
        index: usize,
    ) -> Result<Vec<u8>, VaultError> {
        let pk = self.get_pk(proposal)?;
        let script = self.to_sign_script(proposal)?;
        let txin = &tx.input[index];

        let hash = SighashComponents::new(tx)
            .sighash_all(&txin, &script, self.expected_value)
            .as_hash()
            .to_vec();
        let msg = Message::from_slice(hash.as_slice())
            .map_err(|_| VaultError::InvalidDataError("tx-hash".to_string()))?;

        let signature = DEFAULT_SECP256K1.sign(&msg, &pk.key);
        let result = encode_signature(signature);
        Ok(result)
    }

    pub fn witness(
        &self,
        proposal: &BitcoinTransferProposal,
        signature: &Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, VaultError> {
        Ok(vec![
            signature.clone(),
            self.get_pubkey(proposal)?.serialize(),
        ])
    }

    pub fn to_input(&self) -> TxIn {
        TxIn {
            previous_output: self.output,
            script_sig: Script::new(),
            sequence: self.sequence,
            witness: vec![],
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BitcoinTxError {
    InsufficientFunds(u64, u64),
    LargeFee,
    IncorrectFee,
    NoOutputs,
    NoInputs,
}

/// Max fee, check during _optinal_ validation, is 0.05 BTC.
const FEE_MAX: u64 = 5_000_000;

impl BitcoinTransferProposal {
    fn unsigned(&self) -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: self.input.iter().map(|ir| ir.to_input()).collect(),
            output: self.output.clone(),
        }
    }

    fn seal(&self) -> Result<Transaction, VaultError> {
        let unsigned_tx = self.unsigned();

        let mut input = Vec::with_capacity(self.input.len());
        for (i, ir) in self.input.iter().enumerate() {
            let signature = ir.sign(self, &unsigned_tx, i)?;
            let witness = ir.witness(self, &signature)?;
            input.push(TxIn {
                witness,
                ..ir.to_input()
            });
        }

        let tx = Transaction {
            input,
            ..unsigned_tx
        };

        Ok(tx)
    }

    /// Validates _structure_ of the transaction. I.e. that it has inputs, outputs, and amounts are
    /// agreed.
    pub fn validate(&self) -> Result<(), BitcoinTxError> {
        let send: u64 = self.input.iter().map(|it| it.expected_value).sum();
        if send == 0 {
            return Err(BitcoinTxError::NoInputs);
        }
        let receive: u64 = self.output.iter().map(|it| it.value).sum();
        if receive == 0 {
            return Err(BitcoinTxError::NoOutputs);
        }
        if receive > send {
            return Err(BitcoinTxError::InsufficientFunds(send, receive));
        }
        let fee = self.expected_fee;
        if fee != send - receive {
            return Err(BitcoinTxError::IncorrectFee);
        }
        if fee > FEE_MAX {
            return Err(BitcoinTxError::LargeFee);
        }
        Ok(())
    }

    pub fn raw_unsigned(&self) -> Vec<u8> {
        serialize(&self.unsigned())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::{
            bitcoin::{
                BitcoinTransferProposal,
                InputReference,
                InputScriptSource,
                KeyMapping,
                XPub,
            },
            chains::Blockchain,
        },
        mnemonic::{Language, Mnemonic},
        structs::{
            book::AddressRef,
            seed::{Seed, SeedSource},
            wallet::WalletEntry,
        },
    };
    use bitcoin::{util::bip32::ExtendedPubKey, Network, OutPoint, TxOut, Txid, Address};
    use chrono::{TimeZone, Utc};
    use hdpath::StandardHDPath;
    use std::{convert::TryFrom, process::id, str::FromStr};
    use uuid::Uuid;
    use crate::sign::bitcoin::BitcoinTxError;

    fn create_proposal_1() -> (WalletEntry, BitcoinTransferProposal) {
        let phrase = Mnemonic::try_from(Language::English,
                                        "next script sight verify truly filter snake size sea video cream palace cruise glory furnace second host ordinary strike wasp crystal",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();
        let seed_id = Uuid::new_v4();

        let value_1 = 120_000u64;
        let fee = 432u64;

        let from = InputReference {
            output: OutPoint::new(
                Txid::from_str("a386377a406465423275f51d6dc71a2c245acc55c356a7e851a03b508827bc1e")
                    .unwrap(),
                1,
            ),
            script_source: InputScriptSource::HD(
                seed_id.clone(),
                StandardHDPath::try_from("m/84'/1'/0'/0/0").unwrap(),
            ),
            sequence: 0xffffffff,
            expected_value: value_1,
        };

        let entry = WalletEntry {
            address: Some(
                AddressRef::ExtendedPub(
                    XPub::from_str("vpub5ZXnQV6v5nrLX2vMhMyRPAHdSYtvkR4W3TseErkPm2ZrDGGRYDXPCDAk7PyVnm6D39XFZsZBZpVYsy5mtUMazobptrf71U7HeSPKhipGftY").unwrap()
                )
            ),
            blockchain: Blockchain::BitcoinTestnet,
            ..Default::default()
        };

        let proposal = BitcoinTransferProposal {
            network: Network::Testnet,
            seed: vec![Seed {
                id: seed_id.clone(),
                source: seed,
                label: None,
                created_at: Utc.timestamp_millis(0),
            }],
            keys: KeyMapping::single(seed_id.clone(), "test".to_string()),
            input: vec![from],
            output: vec![TxOut {
                value: value_1 - fee,
                script_pubkey: entry.bitcoin_address(0, 0).unwrap().script_pubkey(),
            }],
            change: entry.clone(),
            expected_fee: fee,
        };

        (entry, proposal)
    }

    fn create_proposal_2() -> (WalletEntry, BitcoinTransferProposal) {
        let phrase = Mnemonic::try_from(Language::English,
                                        "next script sight verify truly filter snake size sea video cream palace cruise glory furnace second host ordinary strike wasp crystal",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();
        let seed_id = Uuid::new_v4();

        let value_1 = 120_000u64;
        let fee = 432u64;

        let from = InputReference {
            output: OutPoint::new(
                Txid::from_str("16aa2d98e37e50c4c007a815a3cb8c20026a3df467781a7e97206a730cf4ef01")
                    .unwrap(),
                1,
            ),
            script_source: InputScriptSource::HD(
                seed_id.clone(),
                StandardHDPath::try_from("m/84'/1'/0'/0/0").unwrap(),
            ),
            sequence: 0xfffffffd,
            expected_value: value_1,
        };

        let entry = WalletEntry {
            address: Some(
                AddressRef::ExtendedPub(
                    XPub::from_str("vpub5ZXnQV6v5nrLX2vMhMyRPAHdSYtvkR4W3TseErkPm2ZrDGGRYDXPCDAk7PyVnm6D39XFZsZBZpVYsy5mtUMazobptrf71U7HeSPKhipGftY").unwrap()
                )
            ),
            blockchain: Blockchain::BitcoinTestnet,
            ..Default::default()
        };

        let proposal = BitcoinTransferProposal {
            network: Network::Testnet,
            seed: vec![Seed {
                id: seed_id.clone(),
                source: seed,
                label: None,
                created_at: Utc.timestamp_millis(0),
            }],
            keys: KeyMapping::single(seed_id.clone(), "test".to_string()),
            input: vec![from],
            output: vec![TxOut {
                value: value_1 - fee,
                script_pubkey: entry.bitcoin_address(0, 0).unwrap().script_pubkey(),
            }],
            change: entry.clone(),
            expected_fee: fee,
        };

        (entry, proposal)
    }

    fn create_proposal_3() -> (WalletEntry, BitcoinTransferProposal) {
        // summary:
        // BITCOIN network
        // from:
        //   16aa2d98e37e50c4c007a815a3cb8c20026a3df467781a7e97206a730cf4ef01:1
        //   1_120_000 sat
        //   by bc1ql09uhx3xy4sra99zsg7wxhyfxkx25h6qs9kafp (SK: L4pw8nW4YEK42edsVp3YM3UATfVBCWyd642WVN8PNieEMXTNGzwY)
        //
        //   8c20026a3df467781a7e97206a730cf4ef0116aa2d98e37e50c4c007a815a3cb:0
        //   2_000_000 sat
        //   by bc1q9t9werndltgzvcw5rzxwm887gv354d7jvjzt8m (SK: KxfA9zpTCJcJkpFJPts2iwYNBrZA5pd9xmDHriDwG8bJJYMJ7cXY)
        //
        // to:
        //   819_568 sat bc1qpfv2avr740dpms6udyqz53y49fpwkvf0ga26q9
        //   1_200_000 sat 3MPSdemXQLHJmw1tAB9YTVa84LC24xJ6X3
        //   1_100_000 sat 13TwUDiEthUop7FWoyZ6U9Jtd1oHAgabzg
        //   432 fees

        let phrase = Mnemonic::try_from(Language::English,
                                        "next script sight verify truly filter snake size sea video cream palace cruise glory furnace second host ordinary strike wasp crystal",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();
        let seed_id = Uuid::new_v4();

        let value_1 = 1_120_000u64;
        let value_2 = 2_000_000u64;
        let fee = 432u64;

        let from1 = InputReference {
            output: OutPoint::new(
                Txid::from_str("16aa2d98e37e50c4c007a815a3cb8c20026a3df467781a7e97206a730cf4ef01")
                    .unwrap(),
                1,
            ),
            script_source: InputScriptSource::HD(
                seed_id.clone(),
                StandardHDPath::try_from("m/84'/0'/0'/0/0").unwrap(),
            ),
            sequence: 0xfffffffd,
            expected_value: value_1,
        };

        let from2 = InputReference {
            output: OutPoint::new(
                Txid::from_str("8c20026a3df467781a7e97206a730cf4ef0116aa2d98e37e50c4c007a815a3cb")
                    .unwrap(),
                0,
            ),
            script_source: InputScriptSource::HD(
                seed_id.clone(),
                StandardHDPath::try_from("m/84'/0'/0'/0/1").unwrap(),
            ),
            sequence: 0xfffffffd,
            expected_value: value_2,
        };

        let entry = WalletEntry {
            address: Some(
                AddressRef::ExtendedPub(
                    XPub::from_str("zpub6rJvhC2ZYTfV6JKoUF5nEyohJr4L11ib23wpzhjd6JwmHDkusBJV9V6dN6ExfEkm11qhmXLqbjHBHRJhtaNRrFVdWJEY4tpkEyBB4gn2GCF").unwrap()
                )
            ),
            blockchain: Blockchain::Bitcoin,
            ..Default::default()
        };

        let proposal = BitcoinTransferProposal {
            network: Network::Bitcoin,
            seed: vec![Seed {
                id: seed_id.clone(),
                source: seed,
                label: None,
                created_at: Utc.timestamp_millis(0),
            }],
            keys: KeyMapping::single(seed_id.clone(), "test".to_string()),
            input: vec![
                from1, from2
            ],
            output: vec![
                TxOut {
                    value: value_1 + value_2 - 1_200_000 - 1_100_000 - fee,
                    script_pubkey: entry.bitcoin_address(1, 0).unwrap().script_pubkey(),
                },
                // next two are from: "ignore save system happy novel dance stool hen crater key misery draft ramp fox absorb"
                TxOut {
                    value: 1_200_000,
                    // m/49'/0'/0'/0/0
                    script_pubkey: Address::from_str("3MPSdemXQLHJmw1tAB9YTVa84LC24xJ6X3").unwrap().script_pubkey(),
                },
                TxOut {
                    value: 1_100_000,
                    // m/44'/0'/0'/0/0
                    script_pubkey: Address::from_str("13TwUDiEthUop7FWoyZ6U9Jtd1oHAgabzg").unwrap().script_pubkey(),
                }
            ],
            change: entry.clone(),
            expected_fee: fee,
        };

        (entry, proposal)
    }

    #[test]
    fn validate_ok() {
        let (_, proposal) = create_proposal_1();
        assert_eq!(Ok(()), proposal.validate());

        let (_, proposal) = create_proposal_2();
        assert_eq!(Ok(()), proposal.validate());

        let (_, proposal) = create_proposal_3();
        assert_eq!(Ok(()), proposal.validate());
    }

    #[test]
    fn invalidate_no_input() {
        let (_, mut proposal) = create_proposal_1();
        proposal.input = vec![];
        assert_eq!(proposal.validate(), Err(BitcoinTxError::NoInputs));
    }

    #[test]
    fn invalidate_no_output() {
        let (_, mut proposal) = create_proposal_1();
        proposal.output = vec![];
        assert_eq!(proposal.validate(), Err(BitcoinTxError::NoOutputs));
    }

    #[test]
    fn invalidate_not_enough_sent() {
        let (_, mut proposal) = create_proposal_1();
        proposal.output[0].value = 140_000;
        assert_eq!(proposal.validate(), Err(BitcoinTxError::InsufficientFunds(120000, 140000)));

        let (_, mut proposal) = create_proposal_3();
        proposal.output[2].value += 40_000;
        assert_eq!(proposal.validate(), Err(BitcoinTxError::InsufficientFunds(1_120_000 + 2_000_000, 1_120_000 + 2_000_000 - 432 + 40_000)));
    }

    #[test]
    fn invalidate_fee_wrong() {
        let (_, mut proposal) = create_proposal_1();
        proposal.expected_fee = 100;
        assert_eq!(proposal.validate(), Err(BitcoinTxError::IncorrectFee));
    }

    #[test]
    fn invalidate_large_fee() {
        let (_, mut proposal) = create_proposal_1();
        proposal.input[0].expected_value += 6_000_000;
        proposal.expected_fee += 6_000_000;
        assert_eq!(proposal.validate(), Err(BitcoinTxError::LargeFee));
    }

    #[test]
    fn encode_basic_unsigned_tx() {
        let (entry, proposal) = create_proposal_1();
        let raw = proposal.raw_unsigned();
        assert_eq!(
            "01000000011ebc2788503ba051e8a756c355cc5a242c1ac76d1df57532426564407a3786a30100000000ffffffff0110d30100000000001600142757c732c931d7722a6bdaf99ee995530311652000000000",
            hex::encode(raw)
        )
    }

    #[test]
    fn encode_nonsegwit_out_unsigned_tx() {
        let (entry, proposal) = create_proposal_3();
        let raw = proposal.raw_unsigned();
        assert_eq!(
            "010000000201eff40c736a20977e1a7867f43d6a02208ccba315a807c0c4507ee3982daa160100000000fdffffffcba315a807c0c4507ee3982daa1601eff40c736a20977e1a7867f43d6a02208c0000000000fdffffff0370810c00000000001600140a58aeb07eabda1dc35c69002a44952a42eb312f804f12000000000017a914d80fa779a090737095a3ac918f4bb110af3ad52e87e0c81000000000001976a9141b0889064d55d54e0d722015c24dbec18e9c130888ac00000000",
            hex::encode(raw)
        )
    }

    #[test]
    fn sign_basic_tx() {
        let (entry, proposal) = create_proposal_1();

        // sign raw tx from encode_basic_unsigned_tx() as:
        // signrawtransactionwithkey "..." [\"cW2om2kLrF7g6ZBC5Ctse2qD2TXg6v5ahGkX1ver9LkobpHG5coU\"]

        let signed = entry.sign_bitcoin(proposal).unwrap();
        assert_eq!(
            "010000000001011ebc2788503ba051e8a756c355cc5a242c1ac76d1df57532426564407a3786a30100000000ffffffff0110d30100000000001600142757c732c931d7722a6bdaf99ee995530311652002483045022100c5af6d33efc9a564c0e955160e0b8def089cc6c933ddf08967eac25d4ddfc09a02205ed59dcc068251dee669ca19425c0c83208d1b1c1f5b7147f4f0b7cb2d15a872012103a3aa29d96671671b065b35de511c03ea5592eafb5de7a07542633af2d42f49ea00000000",
            hex::encode(signed)
        );
    }

    #[test]
    fn sign_two_input_tx() {
        let (entry, proposal) = create_proposal_3();

        let signed = entry.sign_bitcoin(proposal).unwrap();
        assert_eq!(
            "0100000000010201eff40c736a20977e1a7867f43d6a02208ccba315a807c0c4507ee3982daa160100000000fdffffffcba315a807c0c4507ee3982daa1601eff40c736a20977e1a7867f43d6a02208c0000000000fdffffff0370810c00000000001600140a58aeb07eabda1dc35c69002a44952a42eb312f804f12000000000017a914d80fa779a090737095a3ac918f4bb110af3ad52e87e0c81000000000001976a9141b0889064d55d54e0d722015c24dbec18e9c130888ac0248304502210083ad6bada1106d63326647616be507031b28712788036269156a37255ed509a402206c2e3c2cef0f2467a9abda70a8837ddf2d60fa4b809ccd43ffee59ebedc75e81012103ac6c5500040904ae7ed004c1971cf7e00afcf25de6d599a6b90f79681e90133d0248304502210096372fe1d649f45efb6142458c15a6254fe2c14fb9bfc618cf01c35918ccee8802204ac4a01492cc7b24500d62d38b0451e7990679ef32cef4d8a1d897f696fc42e00121026307cafeaac676cfc824d66cd16d106f9a9bc34d8ce1f1ca90f8b6355bd11b4600000000",
            hex::encode(signed)
        );
    }


    #[test]
    fn witness_basic_tx() {
        let (entry, proposal) = create_proposal_1();
        let signed_tx = proposal.seal().unwrap();
        let signature = &signed_tx.input[0].witness[0];
        let pubkey = &signed_tx.input[0].witness[0];

        assert_eq!(
            "3045022100c5af6d33efc9a564c0e955160e0b8def089cc6c933ddf08967eac25d4ddfc09a02205ed59dcc068251dee669ca19425c0c83208d1b1c1f5b7147f4f0b7cb2d15a87201",
            hex::encode(signature)
        )
    }

    #[test]
    fn sign_basic_tx_2() {
        let (entry, proposal) = create_proposal_2();
        let signed = entry.sign_bitcoin(proposal).unwrap();
        println!("RAW {:?}", hex::encode(signed));
    }
}
