use crate::error::WalletSignerError;
use alloy_consensus::TxEip1559;
use alloy_network::TxKind;
use alloy_primitives::B256;
use alloy_signer::Signer as AlloySigner;
use alloy_signer_aws::AwsSigner;
use async_trait::async_trait;
use ethers_core::types::{
    transaction::{eip2718::TypedTransaction, eip712::Eip712},
    Signature,
};
use ethers_signers::{
    coins_bip39::English, HDPath as LedgerHDPath, Ledger, LocalWallet, MnemonicBuilder, Signer,
    Trezor, TrezorHDPath,
};
use foundry_common::types::{ToAlloy, ToEthers};
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, WalletSignerError>;

fn sig_to_ethers(sig: alloy_signer::Signature) -> Signature {
    Signature { r: sig.r().to_ethers(), s: sig.s().to_ethers(), v: sig.v().to_u64() }
}

/// Wrapper enum around different signers.
#[derive(Debug)]
pub enum WalletSigner {
    /// Wrapper around local wallet. e.g. private key, mnemonic
    Local(LocalWallet),
    /// Wrapper around Ledger signer.
    Ledger(Ledger),
    /// Wrapper around Trezor signer.
    Trezor(Trezor),
    /// Wrapper around AWS KMS signer.
    Aws(AwsSigner),
}

impl WalletSigner {
    pub async fn from_ledger_path(path: LedgerHDPath) -> Result<Self> {
        let ledger = Ledger::new(path, 1).await?;
        Ok(Self::Ledger(ledger))
    }

    pub async fn from_trezor_path(path: TrezorHDPath) -> Result<Self> {
        // cached to ~/.ethers-rs/trezor/cache/trezor.session
        let trezor = Trezor::new(path, 1, None).await?;
        Ok(Self::Trezor(trezor))
    }

    pub async fn from_aws(key_id: &str) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);

        let signer = AwsSigner::new(client, key_id.to_string(), None).await?;

        Ok(Self::Aws(signer))
    }

    pub fn from_private_key(private_key: impl AsRef<[u8]>) -> Result<Self> {
        let wallet = LocalWallet::from_bytes(private_key.as_ref())?;
        Ok(Self::Local(wallet))
    }

    /// Returns a list of addresses available to use with current signer
    ///
    /// - for Ledger and Trezor signers the number of addresses to retrieve is specified as argument
    /// - the result for Ledger signers includes addresses available for both LedgerLive and Legacy
    ///   derivation paths
    /// - for Local and AWS signers the result contains a single address
    pub async fn available_senders(&self, max: usize) -> Result<Vec<ethers_core::types::Address>> {
        let mut senders = Vec::new();
        match self {
            WalletSigner::Local(local) => {
                senders.push(local.address());
            }
            WalletSigner::Ledger(ledger) => {
                for i in 0..max {
                    if let Ok(address) =
                        ledger.get_address_with_path(&LedgerHDPath::LedgerLive(i)).await
                    {
                        senders.push(address);
                    }
                }
                for i in 0..max {
                    if let Ok(address) =
                        ledger.get_address_with_path(&LedgerHDPath::Legacy(i)).await
                    {
                        senders.push(address);
                    }
                }
            }
            WalletSigner::Trezor(trezor) => {
                for i in 0..max {
                    if let Ok(address) =
                        trezor.get_address_with_path(&TrezorHDPath::TrezorLive(i)).await
                    {
                        senders.push(address);
                    }
                }
            }
            WalletSigner::Aws(aws) => {
                senders.push(aws.address().to_ethers());
            }
        }
        Ok(senders)
    }

    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        derivation_path: Option<&str>,
        index: u32,
    ) -> Result<Self> {
        let mut builder = MnemonicBuilder::<English>::default().phrase(mnemonic);

        if let Some(passphrase) = passphrase {
            builder = builder.password(passphrase)
        }

        builder = if let Some(hd_path) = derivation_path {
            builder.derivation_path(hd_path)?
        } else {
            builder.index(index)?
        };

        Ok(Self::Local(builder.build()?))
    }
}

macro_rules! delegate {
    ($s:ident, $inner:ident => $e:expr) => {
        match $s {
            Self::Local($inner) => $e,
            Self::Ledger($inner) => $e,
            Self::Trezor($inner) => $e,
            _ => unimplemented!("handle separately"),
            // Self::Aws($inner) => $e,
        }
    };
}

#[async_trait]
impl Signer for WalletSigner {
    type Error = WalletSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(&self, message: S) -> Result<Signature> {
        if let Self::Aws(inner) = self {
            let sig = inner.sign_message(message.as_ref()).await?;
            return Ok(sig_to_ethers(sig));
        }
        delegate!(self, inner => inner.sign_message(message).await.map_err(Into::into))
    }

    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature> {
        if let Self::Aws(inner) = self {
            let mut msg = match tx {
                TypedTransaction::Eip1559(tx) => TxEip1559 {
                    chain_id: tx.chain_id.unwrap_or_default().as_u64(),
                    nonce: tx.nonce.unwrap_or_default().as_u64(),
                    gas_limit: tx.gas.unwrap_or_default().as_u64(),
                    value: tx.value.unwrap_or_default().to_alloy(),
                    max_fee_per_gas: tx.max_fee_per_gas.unwrap_or_default().as_u64() as u128,
                    max_priority_fee_per_gas: tx
                        .max_priority_fee_per_gas
                        .unwrap_or_default()
                        .as_u64() as u128,
                    to: TxKind::Call(tx.to.clone().unwrap().as_address().unwrap().to_alloy()),
                    input: tx.data.clone().unwrap_or_default().to_alloy(),
                    access_list: Default::default(),
                },
                _ => unimplemented!("only EIP-1559 transactions are supported at this time"),
            };
            let sig = inner.sign_transaction(&mut msg).await?;
            return Ok(sig_to_ethers(sig));
        }
        delegate!(self, inner => inner.sign_transaction(tx).await.map_err(Into::into))
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(&self, payload: &T) -> Result<Signature> {
        delegate!(self, inner => inner.sign_typed_data(payload).await.map_err(Into::into))
    }

    fn address(&self) -> ethers_core::types::Address {
        if let Self::Aws(inner) = self {
            return inner.address().to_ethers();
        }
        delegate!(self, inner => inner.address())
    }

    fn chain_id(&self) -> u64 {
        if let Self::Aws(inner) = self {
            return inner.chain_id().expect("aws signer did not set chain id");
        }
        delegate!(self, inner => inner.chain_id())
    }

    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        match self {
            Self::Local(inner) => Self::Local(inner.with_chain_id(chain_id)),
            Self::Ledger(inner) => Self::Ledger(inner.with_chain_id(chain_id)),
            Self::Trezor(inner) => Self::Trezor(inner.with_chain_id(chain_id)),
            Self::Aws(inner) => Self::Aws(inner.with_chain_id(Some(chain_id.into()))),
        }
    }
}

#[async_trait]
impl Signer for &WalletSigner {
    type Error = WalletSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(&self, message: S) -> Result<Signature> {
        (*self).sign_message(message).await
    }

    async fn sign_transaction(&self, message: &TypedTransaction) -> Result<Signature> {
        (*self).sign_transaction(message).await
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(&self, payload: &T) -> Result<Signature> {
        (*self).sign_typed_data(payload).await
    }

    fn address(&self) -> ethers_core::types::Address {
        (*self).address()
    }

    fn chain_id(&self) -> u64 {
        (*self).chain_id()
    }

    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        let _ = chain_id;
        self
    }
}

impl WalletSigner {
    pub async fn sign_hash(&self, hash: &B256) -> Result<Signature> {
        match self {
            Self::Aws(aws) => {
               let sig = aws.sign_hash(*hash).await?;
               Ok(sig_to_ethers(sig))
            },
            Self::Ledger(_) => Err(WalletSignerError::CannotSignRawHash("Ledger")),
            Self::Local(wallet) => wallet.sign_hash(hash.0.into()).map_err(Into::into),
            Self::Trezor(_) => Err(WalletSignerError::CannotSignRawHash("Trezor")),
        }
    }
}

/// Signers that require user action to be obtained.
#[derive(Debug, Clone)]
pub enum PendingSigner {
    Keystore(PathBuf),
    Interactive,
}

impl PendingSigner {
    pub fn unlock(self) -> Result<WalletSigner> {
        match self {
            Self::Keystore(path) => {
                let password = rpassword::prompt_password("Enter keystore password:")?;
                Ok(WalletSigner::Local(LocalWallet::decrypt_keystore(path, password)?))
            }
            Self::Interactive => {
                let private_key = rpassword::prompt_password("Enter private key:")?;
                Ok(WalletSigner::from_private_key(hex::decode(private_key)?)?)
            }
        }
    }
}
