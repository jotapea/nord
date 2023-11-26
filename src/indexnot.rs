use {
  self::{
    entry::{
      BlockHashValue, Entry, InscriptionEntry, InscriptionEntryValue, InscriptionIdValue,
      OutPointValue, RuneEntryValue, RuneIdValue, SatPointValue, SatRange, TxidValue,
    },
    runes::{Rune, RuneId},
  },
  super::*,
  crate::subcommand::find::FindRangeOutput,
  crate::wallet::Wallet,
  bitcoin::block::Header,
  bitcoincore_rpc::{json::GetBlockHeaderResult, Client},
  chrono::SubsecRound,
  indicatif::{ProgressBar, ProgressStyle},
  log::log_enabled,
  std::{
    collections::{BTreeSet, HashMap},
    io::{BufWriter, Write},
    sync::Once,
  },
};

pub(crate) use self::entry::RuneEntry;

pub(crate) mod entry;

const SCHEMA_VERSION: u64 = 13;

#[derive(Debug, PartialEq)]
pub enum List {
  Spent,
  Unspent(Vec<(u64, u64)>),
}

#[derive(Copy, Clone)]
pub(crate) enum Statistic {
  Schema = 0,
  BlessedInscriptions,
  Commits,
  CursedInscriptions,
  IndexRunes,
  IndexSats,
  LostSats,
  OutputsTraversed,
  Runes,
  SatRanges,
  UnboundInscriptions,
}

impl Statistic {
  fn key(self) -> u64 {
    self.into()
  }
}

impl From<Statistic> for u64 {
  fn from(statistic: Statistic) -> Self {
    statistic as u64
  }
}

#[derive(Serialize)]
pub(crate) struct Info {
  blocks_indexed: u32,
  branch_pages: u64,
  fragmented_bytes: u64,
  index_file_size: u64,
  index_path: PathBuf,
  leaf_pages: u64,
  metadata_bytes: u64,
  outputs_traversed: u64,
  page_size: usize,
  sat_ranges: u64,
  stored_bytes: u64,
  tables: BTreeMap<String, TableInfo>,
  pub(crate) transactions: Vec<TransactionInfo>,
  tree_height: u32,
  utxos_indexed: u64,
}

#[derive(Serialize)]
pub(crate) struct TableInfo {
  branch_pages: u64,
  fragmented_bytes: u64,
  leaf_pages: u64,
  metadata_bytes: u64,
  stored_bytes: u64,
  tree_height: u32,
}

#[derive(Serialize)]
pub(crate) struct TransactionInfo {
  pub(crate) starting_block_count: u32,
  pub(crate) starting_timestamp: u128,
}

trait BitcoinCoreRpcResultExt<T> {
  fn into_option(self) -> Result<Option<T>>;
}

impl<T> BitcoinCoreRpcResultExt<T> for Result<T, bitcoincore_rpc::Error> {
  fn into_option(self) -> Result<Option<T>> {
    match self {
      Ok(ok) => Ok(Some(ok)),
      Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
        bitcoincore_rpc::jsonrpc::error::RpcError { code: -8, .. },
      ))) => Ok(None),
      Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
        bitcoincore_rpc::jsonrpc::error::RpcError { message, .. },
      )))
        if message.ends_with("not found") =>
      {
        Ok(None)
      }
      Err(err) => Err(err.into()),
    }
  }
}

pub(crate) struct Indexnot {
  client: Client,
  options: Options,
}

impl Indexnot {
  pub(crate) fn open(options: &Options) -> Result<Self> {
    let client = options.bitcoin_rpc_client()?;

    Ok(Self {
      client,
      options: options.clone(),
    })
  }
}
