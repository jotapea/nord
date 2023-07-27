use {
  // self::{
  //   entry::{
  //     BlockHashValue, Entry, InscriptionEntry, InscriptionEntryValue, InscriptionIdValue,
  //     OutPointValue, SatPointValue, SatRange,
  //   },
  //   updater::Updater,
  // },
  super::*,
  // crate::wallet::Wallet,
  // bitcoin::block::Header,
  bitcoincore_rpc::{json::GetBlockHeaderResult, Client},
  // chrono::SubsecRound,
  // indicatif::{ProgressBar, ProgressStyle},
  log::log_enabled,
  // redb::{
  //   Database, MultimapTable, MultimapTableDefinition, ReadableMultimapTable, ReadableTable, Table,
  //   TableDefinition, WriteTransaction,
  // },
  // std::collections::HashMap,
  // std::io::{BufWriter, Write},
  // std::sync::atomic::{self, AtomicBool},
};

// mod entry;
// mod fetcher;
// mod rtx;
// mod updater;

// const SCHEMA_VERSION: u64 = 5;

// macro_rules! define_table {
//   ($name:ident, $key:ty, $value:ty) => {
//     const $name: TableDefinition<$key, $value> = TableDefinition::new(stringify!($name));
//   };
// }

// macro_rules! define_multimap_table {
//   ($name:ident, $key:ty, $value:ty) => {
//     const $name: MultimapTableDefinition<$key, $value> =
//       MultimapTableDefinition::new(stringify!($name));
//   };
// }

// define_table! { HEIGHT_TO_BLOCK_HASH, u64, &BlockHashValue }
// define_table! { INSCRIPTION_ID_TO_INSCRIPTION_ENTRY, &InscriptionIdValue, InscriptionEntryValue }
// define_table! { INSCRIPTION_ID_TO_SATPOINT, &InscriptionIdValue, &SatPointValue }
// define_table! { INSCRIPTION_NUMBER_TO_INSCRIPTION_ID, i64, &InscriptionIdValue }
// define_table! { OUTPOINT_TO_SAT_RANGES, &OutPointValue, &[u8] }
// define_table! { OUTPOINT_TO_VALUE, &OutPointValue, u64}
// define_table! { REINSCRIPTION_ID_TO_SEQUENCE_NUMBER, &InscriptionIdValue, u64 }
// define_multimap_table! { SATPOINT_TO_INSCRIPTION_ID, &SatPointValue, &InscriptionIdValue }
// define_multimap_table! { SAT_TO_INSCRIPTION_ID, u64, &InscriptionIdValue }
// define_table! { SAT_TO_SATPOINT, u64, &SatPointValue }
// define_table! { STATISTIC_TO_COUNT, u64, u64 }
// define_table! { WRITE_TRANSACTION_STARTING_BLOCK_COUNT_TO_TIMESTAMP, u64, u128 }

pub(crate) struct Indexnot {
  client: Client,
  // database: Database,
  // path: PathBuf,
  // first_inscription_height: u64,
  // genesis_block_coinbase_transaction: Transaction,
  // genesis_block_coinbase_txid: Txid,
  // height_limit: Option<u64>,
  options: Options,
  // reorged: AtomicBool,
}

// #[derive(Debug, PartialEq)]
// pub(crate) enum List {
//   Spent,
//   Unspent(Vec<(u64, u64)>),
// }

// #[derive(Copy, Clone)]
// #[repr(u64)]
// pub(crate) enum Statistic {
//   Schema = 0,
//   Commits = 1,
//   LostSats = 2,
//   OutputsTraversed = 3,
//   SatRanges = 4,
//   UnboundInscriptions = 5,
// }

// impl Statistic {
//   fn key(self) -> u64 {
//     self.into()
//   }
// }

// impl From<Statistic> for u64 {
//   fn from(statistic: Statistic) -> Self {
//     statistic as u64
//   }
// }

// #[derive(Serialize)]
// pub(crate) struct Info {
//   pub(crate) blocks_indexed: u64,
//   pub(crate) branch_pages: u64,
//   pub(crate) fragmented_bytes: u64,
//   pub(crate) index_file_size: u64,
//   pub(crate) index_path: PathBuf,
//   pub(crate) leaf_pages: u64,
//   pub(crate) metadata_bytes: u64,
//   pub(crate) outputs_traversed: u64,
//   pub(crate) page_size: usize,
//   pub(crate) sat_ranges: u64,
//   pub(crate) stored_bytes: u64,
//   pub(crate) transactions: Vec<TransactionInfo>,
//   pub(crate) tree_height: u32,
//   pub(crate) utxos_indexed: u64,
// }

// #[derive(Serialize)]
// pub(crate) struct TransactionInfo {
//   pub(crate) starting_block_count: u64,
//   pub(crate) starting_timestamp: u128,
// }

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

impl Indexnot {
  pub(crate) fn open(options: &Options) -> Result<Self> {
    let client = options.bitcoin_rpc_client()?;

    // let path = if let Some(path) = &options.index {
    //   path.clone()
    // } else {
    //   options.data_dir()?.join("index.redb")
    // };

    // if let Err(err) = fs::create_dir_all(path.parent().unwrap()) {
    //   bail!(
    //     "failed to create data dir `{}`: {err}",
    //     path.parent().unwrap().display()
    //   );
    // }

    // let db_cache_size = match options.db_cache_size {
    //   Some(db_cache_size) => db_cache_size,
    //   None => {
    //     let mut sys = System::new();
    //     sys.refresh_memory();
    //     usize::try_from(sys.total_memory() / 4)?
    //   }
    // };

    // log::info!("Setting DB cache size to {} bytes", db_cache_size);

    // let database = match Database::builder()
    //   .set_cache_size(db_cache_size)
    //   .open(&path)
    // {
    //   Ok(database) => {
    //     let schema_version = database
    //       .begin_read()?
    //       .open_table(STATISTIC_TO_COUNT)?
    //       .get(&Statistic::Schema.key())?
    //       .map(|x| x.value())
    //       .unwrap_or(0);

    //     match schema_version.cmp(&SCHEMA_VERSION) {
    //       cmp::Ordering::Less =>
    //         bail!(
    //           "index at `{}` appears to have been built with an older, incompatible version of ord, consider deleting and rebuilding the index: index schema {schema_version}, ord schema {SCHEMA_VERSION}",
    //           path.display()
    //         ),
    //       cmp::Ordering::Greater =>
    //         bail!(
    //           "index at `{}` appears to have been built with a newer, incompatible version of ord, consider updating ord: index schema {schema_version}, ord schema {SCHEMA_VERSION}",
    //           path.display()
    //         ),
    //       cmp::Ordering::Equal => {
    //       }
    //     }

    //     database
    //   }
    //   Err(_) => {
    //     let database = Database::builder()
    //       .set_cache_size(db_cache_size)
    //       .create(&path)?;

    //     let mut tx = database.begin_write()?;

    //     if cfg!(test) {
    //       tx.set_durability(redb::Durability::None);
    //     } else {
    //       tx.set_durability(redb::Durability::Immediate);
    //     };

    //     tx.open_table(HEIGHT_TO_BLOCK_HASH)?;
    //     tx.open_table(INSCRIPTION_ID_TO_INSCRIPTION_ENTRY)?;
    //     tx.open_table(INSCRIPTION_ID_TO_SATPOINT)?;
    //     tx.open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?;
    //     tx.open_table(OUTPOINT_TO_VALUE)?;
    //     tx.open_table(REINSCRIPTION_ID_TO_SEQUENCE_NUMBER)?;
    //     tx.open_multimap_table(SATPOINT_TO_INSCRIPTION_ID)?;
    //     tx.open_multimap_table(SAT_TO_INSCRIPTION_ID)?;
    //     tx.open_table(SAT_TO_SATPOINT)?;
    //     tx.open_table(WRITE_TRANSACTION_STARTING_BLOCK_COUNT_TO_TIMESTAMP)?;

    //     tx.open_table(STATISTIC_TO_COUNT)?
    //       .insert(&Statistic::Schema.key(), &SCHEMA_VERSION)?;

    //     if options.index_sats {
    //       tx.open_table(OUTPOINT_TO_SAT_RANGES)?
    //         .insert(&OutPoint::null().store(), [].as_slice())?;
    //     }

    //     tx.commit()?;

    //     database
    //   }
    // };

    // let genesis_block_coinbase_transaction =
    //   options.chain().genesis_block().coinbase().unwrap().clone();

    Ok(Self {
      // genesis_block_coinbase_txid: genesis_block_coinbase_transaction.txid(),
      client,
      // database,
      // path,
      // first_inscription_height: options.first_inscription_height(),
      // genesis_block_coinbase_transaction,
      // height_limit: options.height_limit,
      // reorged: AtomicBool::new(false),
      options: options.clone(),
    })
  }

  // pub(crate) fn get_unspent_outputs(&self, _wallet: Wallet) -> Result<BTreeMap<OutPoint, Amount>> {
  //   let mut utxos = BTreeMap::new();
  //   utxos.extend(
  //     self
  //       .client
  //       .list_unspent(None, None, None, None, None)?
  //       .into_iter()
  //       .map(|utxo| {
  //         let outpoint = OutPoint::new(utxo.txid, utxo.vout);
  //         let amount = utxo.amount;

  //         (outpoint, amount)
  //       }),
  //   );

  //   #[derive(Deserialize)]
  //   pub(crate) struct JsonOutPoint {
  //     txid: bitcoin::Txid,
  //     vout: u32,
  //   }

  //   for JsonOutPoint { txid, vout } in self
  //     .client
  //     .call::<Vec<JsonOutPoint>>("listlockunspent", &[])?
  //   {
  //     utxos.insert(
  //       OutPoint { txid, vout },
  //       Amount::from_sat(self.client.get_raw_transaction(&txid, None)?.output[vout as usize].value),
  //     );
  //   }
  //   let rtx = self.database.begin_read()?;
  //   let outpoint_to_value = rtx.open_table(OUTPOINT_TO_VALUE)?;
  //   for outpoint in utxos.keys() {
  //     if outpoint_to_value.get(&outpoint.store())?.is_none() {
  //       return Err(anyhow!(
  //         "output in Bitcoin Core wallet but not in ord index: {outpoint}"
  //       ));
  //     }
  //   }

  //   Ok(utxos)
  // }

  // pub(crate) fn get_unspent_output_ranges(
  //   &self,
  //   wallet: Wallet,
  // ) -> Result<Vec<(OutPoint, Vec<(u64, u64)>)>> {
  //   self
  //     .get_unspent_outputs(wallet)?
  //     .into_keys()
  //     .map(|outpoint| match self.list(outpoint)? {
  //       Some(List::Unspent(sat_ranges)) => Ok((outpoint, sat_ranges)),
  //       Some(List::Spent) => bail!("output {outpoint} in wallet but is spent according to index"),
  //       None => bail!("index has not seen {outpoint}"),
  //     })
  //     .collect()
  // }

  // pub(crate) fn is_reorged(&self) -> bool {
  //   self.reorged.load(atomic::Ordering::Relaxed)
  // }

  // pub(crate) fn block_count(&self) -> Result<u64> {
  //   self.begin_read()?.block_count()
  // }

  // pub(crate) fn block_height(&self) -> Result<Option<Height>> {
  //   self.begin_read()?.block_height()
  // }

  // pub(crate) fn block_hash(&self, height: Option<u64>) -> Result<Option<BlockHash>> {
  //   self.begin_read()?.block_hash(height)
  // }

  // pub(crate) fn blocks(&self, take: usize) -> Result<Vec<(u64, BlockHash)>> {
  //   let mut blocks = Vec::new();

  //   let rtx = self.begin_read()?;

  //   let block_count = rtx.block_count()?;

  //   let height_to_block_hash = rtx.0.open_table(HEIGHT_TO_BLOCK_HASH)?;

  //   for next in height_to_block_hash.range(0..block_count)?.rev().take(take) {
  //     let next = next?;
  //     blocks.push((next.0.value(), Entry::load(*next.1.value())));
  //   }

  //   Ok(blocks)
  // }

  // pub(crate) fn block_header(&self, hash: BlockHash) -> Result<Option<Header>> {
  //   self.client.get_block_header(&hash).into_option()
  // }

  // pub(crate) fn block_header_info(&self, hash: BlockHash) -> Result<Option<GetBlockHeaderResult>> {
  //   self.client.get_block_header_info(&hash).into_option()
  // }

  // pub(crate) fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
  //   Ok(
  //     self
  //       .client
  //       .get_block_hash(height)
  //       .into_option()?
  //       .map(|hash| self.client.get_block(&hash))
  //       .transpose()?,
  //   )
  // }

  // pub(crate) fn get_block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>> {
  //   self.client.get_block(&hash).into_option()
  // }

  pub(crate) fn get_inscription_by_id(
    &self,
    inscription_id: InscriptionId,
  ) -> Result<Option<Inscription>> {
    // if self
    //   .database
    //   .begin_read()?
    //   .open_table(INSCRIPTION_ID_TO_SATPOINT)?
    //   .get(&inscription_id.store())?
    //   .is_none()
    // {
    //   return Ok(None);
    // }

    Ok(self.get_transaction(inscription_id.txid)?.and_then(|tx| {
      Inscription::from_transaction(&tx)
        .get(inscription_id.index as usize)
        .map(|transaction_inscription| transaction_inscription.inscription.clone())
    }))
  }

  // pub(crate) fn get_inscriptions_on_output_with_satpoints(
  //   &self,
  //   outpoint: OutPoint,
  // ) -> Result<Vec<(SatPoint, InscriptionId)>> {
  //   let rtx = &self.database.begin_read()?;
  //   let sat_to_id = rtx.open_multimap_table(SATPOINT_TO_INSCRIPTION_ID)?;
  //   let re_id_to_seq_num = rtx.open_table(REINSCRIPTION_ID_TO_SEQUENCE_NUMBER)?;

  //   Self::inscriptions_on_output_ordered(&re_id_to_seq_num, &sat_to_id, outpoint)
  // }

  // pub(crate) fn get_inscriptions_on_output(
  //   &self,
  //   outpoint: OutPoint,
  // ) -> Result<Vec<InscriptionId>> {
  //   Ok(
  //     self
  //       .get_inscriptions_on_output_with_satpoints(outpoint)?
  //       .iter()
  //       .map(|(_satpoint, inscription_id)| *inscription_id)
  //       .collect(),
  //   )
  // }

  pub(crate) fn get_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
    // if txid == self.genesis_block_coinbase_txid {
    //   Ok(Some(self.genesis_block_coinbase_transaction.clone()))
    // } else {
      self.client.get_raw_transaction(&txid, None).into_option()
    // }
  }

  pub(crate) fn get_transaction_blockhash(&self, txid: Txid) -> Result<Option<BlockHash>> {
    Ok(
      self
        .client
        .get_raw_transaction_info(&txid, None)
        .into_option()?
        .and_then(|info| {
          if info.in_active_chain.unwrap_or_default() {
            info.blockhash
          } else {
            None
          }
        }),
    )
  }

  pub(crate) fn is_transaction_in_active_chain(&self, txid: Txid) -> Result<bool> {
    Ok(
      self
        .client
        .get_raw_transaction_info(&txid, None)
        .into_option()?
        .and_then(|info| info.in_active_chain)
        .unwrap_or(false),
    )
  }

  // pub(crate) fn find(&self, sat: u64) -> Result<Option<SatPoint>> {
  //   self.require_sat_index("find")?;

  //   let rtx = self.begin_read()?;

  //   if rtx.block_count()? <= Sat(sat).height().n() {
  //     return Ok(None);
  //   }

  //   let outpoint_to_sat_ranges = rtx.0.open_table(OUTPOINT_TO_SAT_RANGES)?;

  //   for range in outpoint_to_sat_ranges.range::<&[u8; 36]>(&[0; 36]..)? {
  //     let (key, value) = range?;
  //     let mut offset = 0;
  //     for chunk in value.value().chunks_exact(11) {
  //       let (start, end) = SatRange::load(chunk.try_into().unwrap());
  //       if start <= sat && sat < end {
  //         return Ok(Some(SatPoint {
  //           outpoint: Entry::load(*key.value()),
  //           offset: offset + sat - start,
  //         }));
  //       }
  //       offset += end - start;
  //     }
  //   }

  //   Ok(None)
  // }

  // fn list_inner(&self, outpoint: OutPointValue) -> Result<Option<Vec<u8>>> {
  //   Ok(
  //     self
  //       .database
  //       .begin_read()?
  //       .open_table(OUTPOINT_TO_SAT_RANGES)?
  //       .get(&outpoint)?
  //       .map(|outpoint| outpoint.value().to_vec()),
  //   )
  // }

  // pub(crate) fn list(&self, outpoint: OutPoint) -> Result<Option<List>> {
  //   self.require_sat_index("list")?;

  //   let array = outpoint.store();

  //   let sat_ranges = self.list_inner(array)?;

  //   match sat_ranges {
  //     Some(sat_ranges) => Ok(Some(List::Unspent(
  //       sat_ranges
  //         .chunks_exact(11)
  //         .map(|chunk| SatRange::load(chunk.try_into().unwrap()))
  //         .collect(),
  //     ))),
  //     None => {
  //       if self.is_transaction_in_active_chain(outpoint.txid)? {
  //         Ok(Some(List::Spent))
  //       } else {
  //         Ok(None)
  //       }
  //     }
  //   }
  // }

  // pub(crate) fn block_time(&self, height: Height) -> Result<Blocktime> {
  //   let height = height.n();

  //   match self.get_block_by_height(height)? {
  //     Some(block) => Ok(Blocktime::confirmed(block.header.time)),
  //     None => {
  //       let tx = self.database.begin_read()?;

  //       let current = tx
  //         .open_table(HEIGHT_TO_BLOCK_HASH)?
  //         .range(0..)?
  //         .next_back()
  //         .and_then(|result| result.ok())
  //         .map(|(height, _hash)| height)
  //         .map(|x| x.value())
  //         .unwrap_or(0);

  //       let expected_blocks = height.checked_sub(current).with_context(|| {
  //         format!("current {current} height is greater than sat height {height}")
  //       })?;

  //       Ok(Blocktime::Expected(
  //         Utc::now()
  //           .round_subsecs(0)
  //           .checked_add_signed(chrono::Duration::seconds(
  //             10 * 60 * i64::try_from(expected_blocks)?,
  //           ))
  //           .ok_or_else(|| anyhow!("block timestamp out of range"))?,
  //       ))
  //     }
  //   }
  // }

  // pub(crate) fn get_inscriptions(
  //   &self,
  //   n: Option<usize>,
  // ) -> Result<BTreeMap<SatPoint, InscriptionId>> {
  //   let rtx = self.database.begin_read()?;

  //   let mut result = BTreeMap::new();

  //   for range_result in rtx
  //     .open_multimap_table(SATPOINT_TO_INSCRIPTION_ID)?
  //     .range::<&[u8; 44]>(&[0; 44]..)?
  //   {
  //     let (satpoint, ids) = range_result?;
  //     for id_result in ids {
  //       let id = id_result?;
  //       result.insert(Entry::load(*satpoint.value()), Entry::load(*id.value()));
  //     }
  //     if result.len() >= n.unwrap_or(usize::MAX) {
  //       break;
  //     }
  //   }

  //   Ok(result)
  // }

  // pub(crate) fn get_homepage_inscriptions(&self) -> Result<Vec<InscriptionId>> {
  //   Ok(
  //     self
  //       .database
  //       .begin_read()?
  //       .open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?
  //       .iter()?
  //       .rev()
  //       .take(8)
  //       .flat_map(|result| result.map(|(_number, id)| Entry::load(*id.value())))
  //       .collect(),
  //   )
  // }

  // pub(crate) fn get_latest_inscriptions_with_prev_and_next(
  //   &self,
  //   n: usize,
  //   from: Option<i64>,
  // ) -> Result<(Vec<InscriptionId>, Option<i64>, Option<i64>)> {
  //   let rtx = self.database.begin_read()?;

  //   let inscription_number_to_inscription_id =
  //     rtx.open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?;

  //   let latest = match inscription_number_to_inscription_id.iter()?.next_back() {
  //     Some(Ok((number, _id))) => number.value(),
  //     Some(Err(_)) => return Ok(Default::default()),
  //     None => return Ok(Default::default()),
  //   };

  //   let from = from.unwrap_or(latest);

  //   let prev = if let Some(prev) = from.checked_sub(n.try_into()?) {
  //     inscription_number_to_inscription_id
  //       .get(&prev)?
  //       .map(|_| prev)
  //   } else {
  //     None
  //   };

  //   let next = if from < latest {
  //     Some(
  //       from
  //         .checked_add(n.try_into()?)
  //         .unwrap_or(latest)
  //         .min(latest),
  //     )
  //   } else {
  //     None
  //   };

  //   let inscriptions = inscription_number_to_inscription_id
  //     .range(..=from)?
  //     .rev()
  //     .take(n)
  //     .flat_map(|result| result.map(|(_number, id)| Entry::load(*id.value())))
  //     .collect();

  //   Ok((inscriptions, prev, next))
  // }

  // pub(crate) fn get_feed_inscriptions(&self, n: usize) -> Result<Vec<(i64, InscriptionId)>> {
  //   Ok(
  //     self
  //       .database
  //       .begin_read()?
  //       .open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?
  //       .iter()?
  //       .rev()
  //       .take(n)
  //       .flat_map(|result| result.map(|(number, id)| (number.value(), Entry::load(*id.value()))))
  //       .collect(),
  //   )
  // }

  // pub(crate) fn get_inscription_entry(
  //   &self,
  //   inscription_id: InscriptionId,
  // ) -> Result<Option<InscriptionEntry>> {
  //   Ok(
  //     self
  //       .database
  //       .begin_read()?
  //       .open_table(INSCRIPTION_ID_TO_INSCRIPTION_ENTRY)?
  //       .get(&inscription_id.store())?
  //       .map(|value| InscriptionEntry::load(value.value())),
  //   )
  // }

  // #[cfg(test)]
  // fn assert_inscription_location(
  //   &self,
  //   inscription_id: InscriptionId,
  //   satpoint: SatPoint,
  //   sat: Option<u64>,
  // ) {
  //   let rtx = self.database.begin_read().unwrap();

  //   let satpoint_to_inscription_id = rtx.open_multimap_table(SATPOINT_TO_INSCRIPTION_ID).unwrap();

  //   let inscription_id_to_satpoint = rtx.open_table(INSCRIPTION_ID_TO_SATPOINT).unwrap();

  //   assert_eq!(
  //     satpoint_to_inscription_id.len().unwrap(),
  //     inscription_id_to_satpoint.len().unwrap(),
  //   );

  //   assert_eq!(
  //     SatPoint::load(
  //       *inscription_id_to_satpoint
  //         .get(&inscription_id.store())
  //         .unwrap()
  //         .unwrap()
  //         .value()
  //     ),
  //     satpoint,
  //   );

  //   assert!(satpoint_to_inscription_id
  //     .get(&satpoint.store())
  //     .unwrap()
  //     .any(|id| InscriptionId::load(*id.unwrap().value()) == inscription_id));

  //   match sat {
  //     Some(sat) => {
  //       if self.has_sat_index().unwrap() {
  //         // unbound inscriptions should not be assigned to a sat
  //         assert!(satpoint.outpoint != unbound_outpoint());
  //         assert!(rtx
  //           .open_multimap_table(SAT_TO_INSCRIPTION_ID)
  //           .unwrap()
  //           .get(&sat)
  //           .unwrap()
  //           .any(|id| InscriptionId::load(*id.unwrap().value()) == inscription_id));

  //         // we do not track common sats (only the sat ranges)
  //         if !Sat(sat).is_common() {
  //           assert_eq!(
  //             SatPoint::load(
  //               *rtx
  //                 .open_table(SAT_TO_SATPOINT)
  //                 .unwrap()
  //                 .get(&sat)
  //                 .unwrap()
  //                 .unwrap()
  //                 .value()
  //             ),
  //             satpoint,
  //           );
  //         }
  //       }
  //     }
  //     None => {
  //       if self.has_sat_index().unwrap() {
  //         assert!(satpoint.outpoint == unbound_outpoint())
  //       }
  //     }
  //   }
  // }

  // fn inscriptions_on_output_unordered<'a: 'tx, 'tx>(
  //   satpoint_to_id: &'a impl ReadableMultimapTable<&'static SatPointValue, &'static InscriptionIdValue>,
  //   outpoint: OutPoint,
  // ) -> Result<impl Iterator<Item = (SatPoint, InscriptionId)> + 'tx> {
  //   let start = SatPoint {
  //     outpoint,
  //     offset: 0,
  //   }
  //   .store();

  //   let end = SatPoint {
  //     outpoint,
  //     offset: u64::MAX,
  //   }
  //   .store();

  //   let mut inscriptions = Vec::new();

  //   for range in satpoint_to_id.range::<&[u8; 44]>(&start..=&end)? {
  //     let (satpoint, ids) = range?;
  //     for id_result in ids {
  //       let id = id_result?;
  //       inscriptions.push((Entry::load(*satpoint.value()), Entry::load(*id.value())));
  //     }
  //   }

  //   Ok(inscriptions.into_iter())
  // }

  // fn inscriptions_on_output_ordered<'a: 'tx, 'tx>(
  //   re_id_to_seq_num: &'a impl ReadableTable<&'static InscriptionIdValue, u64>,
  //   satpoint_to_id: &'a impl ReadableMultimapTable<&'static SatPointValue, &'static InscriptionIdValue>,
  //   outpoint: OutPoint,
  // ) -> Result<Vec<(SatPoint, InscriptionId)>> {
  //   let mut result = Self::inscriptions_on_output_unordered(satpoint_to_id, outpoint)?
  //     .collect::<Vec<(SatPoint, InscriptionId)>>();

  //   if result.len() <= 1 {
  //     return Ok(result);
  //   }

  //   result.sort_by_key(|(_satpoint, inscription_id)| {
  //     match re_id_to_seq_num.get(&inscription_id.store()) {
  //       Ok(Some(num)) => num.value() + 1, // remove at next index refactor
  //       Ok(None) => 0,
  //       _ => 0,
  //     }
  //   });

  //   Ok(result)
  // }
}
