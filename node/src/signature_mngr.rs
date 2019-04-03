//! # Signature Manager
//!
//! This module provides a Signature Manager, which, after being
//! initialized with a key, can be used repeatedly to sign data with
//! that key.
use actix::prelude::*;
use failure;
use failure::bail;
use futures::future::Future;
use log;

use crate::{actors::storage_keys::EXTENDED_SK_KEY, storage_mngr};

use witnet_crypto::{
    key::{ExtendedSK, MasterKeyGen, SK},
    mnemonic::MnemonicGen,
    signature,
};

use witnet_data_structures::chain::{ExtendedSecretKey, Hash, Hashable};

/// Start the signature manager
pub fn start() {
    let addr = SignatureManager::start_default();
    actix::System::current().registry().set(addr);
}

/// Set the key used to sign
pub fn set_key(key: SK) -> impl Future<Item = (), Error = failure::Error> {
    let addr = actix::System::current()
        .registry()
        .get::<SignatureManager>();
    addr.send(SetKey(key)).flatten()
}

/// Sign a piece of data with the stored key.
///
/// This might fail if the manager has not been initialized with a key
pub fn sign<T>(data: &T) -> impl Future<Item = signature::Signature, Error = failure::Error>
where
    T: Hashable,
{
    let addr = actix::System::current()
        .registry()
        .get::<SignatureManager>();
    let Hash::SHA256(data_hash) = data.hash();

    addr.send(Sign(data_hash.to_vec())).flatten()
}

#[derive(Debug, Default)]
struct SignatureManager {
    key: Option<SK>,
}

struct SetKey(SK);
struct Sign(Vec<u8>);

/// Auxiliary methods for SignatureManager actor
impl SignatureManager {
    /// Method to persist the extended secret key into storage
    fn persist_extended_sk(&self, ctx: &mut Context<Self>, extended_sk: ExtendedSK) {
        let extended_secret_key = ExtendedSecretKey::from(extended_sk);

        storage_mngr::put(&EXTENDED_SK_KEY, &extended_secret_key)
            .into_actor(self)
            .and_then(|_, _, _| {
                log::debug!("Successfully persisted the extended secret key into storage");
                fut::ok(())
            })
            .map_err(|err, _, _| {
                log::error!(
                    "Failed to persist the extended secret key into storage: {}",
                    err
                )
            })
            .spawn(ctx);
    }
}

impl Actor for SignatureManager {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        log::debug!("Signature Manager actor has been started!");

        storage_mngr::get::<_, ExtendedSecretKey>(&EXTENDED_SK_KEY)
            .into_actor(self)
            .map_err(|e, _, _| {
                log::error!(
                    "Error while getting the extended secret key from storage: {}",
                    e
                )
            })
            .and_then(move |extended_sk_from_storage, act, ctx| {
                extended_sk_from_storage.map_or_else(
                    || {
                        log::warn!("No extended secret key in storage");

                        // Create a new Secret Key
                        let mnemonic = MnemonicGen::new().generate();
                        // TODO: Seed words must be saved?
                        let _words: Vec<&str> = mnemonic.words().split_whitespace().collect();
                        let seed = mnemonic.seed("");

                        match MasterKeyGen::new(seed).generate() {
                            Ok(extended_sk) => {
                                set_key(extended_sk.secret_key);

                                act.persist_extended_sk(ctx, extended_sk);
                            }
                            Err(e) => log::warn!("{}", e),
                        }
                    },
                    |extended_secret_key| {
                        log::debug!("Secret key load and set");
                        let extended_sk: ExtendedSK = extended_secret_key.into();
                        set_key(extended_sk.secret_key);
                    },
                );

                fut::ok(())
            })
            .spawn(ctx);
    }
}

impl Supervised for SignatureManager {}

impl SystemService for SignatureManager {}

impl Message for SetKey {
    type Result = Result<(), failure::Error>;
}

impl Message for Sign {
    type Result = Result<signature::Signature, failure::Error>;
}

impl Handler<SetKey> for SignatureManager {
    type Result = <SetKey as Message>::Result;

    fn handle(&mut self, SetKey(key): SetKey, _ctx: &mut Self::Context) -> Self::Result {
        self.key = Some(key);
        Ok(())
    }
}

impl Handler<Sign> for SignatureManager {
    type Result = <Sign as Message>::Result;

    fn handle(&mut self, Sign(data): Sign, _ctx: &mut Self::Context) -> Self::Result {
        match self.key {
            Some(key) => Ok(signature::sign(key, &data)),
            None => bail!("Signature Manager cannot sign because it contains no key"),
        }
    }
}
