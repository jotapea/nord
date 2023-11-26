use {
  self::{
    accept_encoding::AcceptEncoding,
    accept_json::AcceptJson,
    deserialize_from_str::DeserializeFromStr,
    error::{OptionExt, ServerError, ServerResult},
  },
  super::*,
  crate::{
    page_config::PageConfig,
    runes::Rune,
    templates::{
      BlockHtml, BlockJson, BlocksHtml, ChildrenHtml, ChildrenJson, ClockSvg, CollectionsHtml,
      HomeHtml, InputHtml, InscriptionHtml, InscriptionJson, InscriptionsBlockHtml,
      InscriptionsHtml, InscriptionsJson, OutputHtml, OutputJson, PageContent, PageHtml,
      PreviewAudioHtml, PreviewCodeHtml, PreviewFontHtml, PreviewImageHtml, PreviewMarkdownHtml,
      PreviewModelHtml, PreviewPdfHtml, PreviewTextHtml, PreviewUnknownHtml, PreviewVideoHtml,
      RangeHtml, RareTxt, RuneHtml, RunesHtml, SatHtml, SatInscriptionJson, SatInscriptionsJson,
      SatJson, TransactionHtml,
    },
  },
  axum::{
    body,
    extract::{Extension, Json, Path, Query},
    headers::UserAgent,
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router, TypedHeader,
  },
  axum_server::Handle,
  rust_embed::RustEmbed,
  rustls_acme::{
    acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
    axum::AxumAcceptor,
    caches::DirCache,
    AcmeConfig,
  },
  std::{cmp::Ordering, str, sync::Arc},
  tokio_stream::StreamExt,
  tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
  },
};

mod accept_encoding;
mod accept_json;
mod error;

#[derive(Clone)]
pub struct ServerConfig {
  pub is_json_api_enabled: bool,
}

enum InscriptionQuery {
  Id(InscriptionId),
  Number(i32),
}

impl FromStr for InscriptionQuery {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s.contains('i') {
      InscriptionQuery::Id(s.parse()?)
    } else {
      InscriptionQuery::Number(s.parse()?)
    })
  }
}

enum BlockQuery {
  Height(u32),
  Hash(BlockHash),
}

impl FromStr for BlockQuery {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s.len() == 64 {
      BlockQuery::Hash(s.parse()?)
    } else {
      BlockQuery::Height(s.parse()?)
    })
  }
}

enum SpawnConfig {
  Https(AxumAcceptor),
  Http,
  Redirect(String),
}

#[derive(Deserialize)]
struct Search {
  query: String,
}

#[derive(RustEmbed)]
#[folder = "static"]
struct StaticAssets;

struct StaticHtml {
  title: &'static str,
  html: &'static str,
}

impl PageContent for StaticHtml {
  fn title(&self) -> String {
    self.title.into()
  }
}

impl Display for StaticHtml {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    f.write_str(self.html)
  }
}

#[derive(Debug, Parser)]
pub(crate) struct Servernot {
  #[arg(
    long,
    default_value = "0.0.0.0",
    help = "Listen on <ADDRESS> for incoming requests."
  )]
  address: String,
  #[arg(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  acme_domain: Vec<String>,
  #[arg(
    long,
    help = "Use <CSP_ORIGIN> in Content-Security-Policy header. Set this to the public-facing URL of your ord instance."
  )]
  csp_origin: Option<String>,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]."
  )]
  http_port: Option<u16>,
  #[arg(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]."
  )]
  https_port: Option<u16>,
  #[arg(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  acme_cache: Option<PathBuf>,
  #[arg(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  acme_contact: Vec<String>,
  #[arg(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  http: bool,
  #[arg(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  https: bool,
  #[arg(long, help = "Redirect HTTP traffic to HTTPS.")]
  redirect_http_to_https: bool,
  #[arg(long, short = 'j', help = "Enable JSON API.")]
  pub(crate) enable_json_api: bool,
}

impl Servernot {
  pub(crate) fn run(self, options: Options, index: Arc<Indexnot>, handle: Handle) -> SubcommandResult {
    Runtime::new()?.block_on(async {
      // let index_clone = index.clone();

      // let index_thread = thread::spawn(move || loop {
      //   if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
      //     break;
      //   }
      //   if let Err(error) = index_clone.update() {
      //     log::warn!("Updating index: {error}");
      //   }
      //   thread::sleep(Duration::from_millis(5000));
      // });
      // INDEXER.lock().unwrap().replace(index_thread);

      let server_config = Arc::new(ServerConfig {
        is_json_api_enabled: self.enable_json_api,
      });

      let config = options.load_config()?;
      let acme_domains = self.acme_domains()?;

      let page_config = Arc::new(PageConfig {
        chain: options.chain(),
        csp_origin: self.csp_origin.clone(),
        domain: acme_domains.first().cloned(),
        index_sats: false,
        // index_sats: index.has_sat_index(),
      });

      let router = Router::new()
        // .route("/", get(Self::home))
        // .route("/block/:query", get(Self::block))
        // .route("/blockcount", get(Self::block_count))
        // .route("/blockhash", get(Self::block_hash))
        // .route("/blockhash/:height", get(Self::block_hash_from_height))
        // .route("/blockheight", get(Self::block_height))
        // .route("/blocks", get(Self::blocks))
        // .route("/blocktime", get(Self::block_time))
        // .route("/bounties", get(Self::bounties))
        // .route("/children/:inscription_id", get(Self::children))
        // .route(
        //   "/children/:inscription_id/:page",
        //   get(Self::children_paginated),
        // )
        // .route("/clock", get(Self::clock))
        // .route("/collections", get(Self::collections))
        // .route("/collections/:page", get(Self::collections_paginated))
        // .route("/content/:inscription_id", get(Self::content))
        // .route("/faq", get(Self::faq))
        .route("/favicon.ico", get(Self::favicon))
        // .route("/feed.xml", get(Self::feed))
        // .route("/input/:block/:transaction/:input", get(Self::input))
        // .route("/inscription/:inscription_query", get(Self::inscription))
        // .route("/inscriptions", get(Self::inscriptions))
        // .route("/inscriptions/:page", get(Self::inscriptions_paginated))
        // .route(
        //   "/inscriptions/block/:height",
        //   get(Self::inscriptions_in_block),
        // )
        // .route(
        //   "/inscriptions/block/:height/:page",
        //   get(Self::inscriptions_in_block_paginated),
        // )
        // .route("/install.sh", get(Self::install_script))
        // .route("/ordinal/:sat", get(Self::ordinal))
        // .route("/output/:output", get(Self::output))
        // .route("/preview/:inscription_id", get(Self::preview))
        // .route("/r/blockhash", get(Self::block_hash_json))
        // .route(
        //   "/r/blockhash/:height",
        //   get(Self::block_hash_from_height_json),
        // )
        // .route("/r/blockheight", get(Self::block_height))
        // .route("/r/blocktime", get(Self::block_time))
        // .route("/r/children/:inscription_id", get(Self::children_recursive))
        // .route(
        //   "/r/children/:inscription_id/:page",
        //   get(Self::children_recursive_paginated),
        // )
        // .route("/r/metadata/:inscription_id", get(Self::metadata))
        // .route("/r/sat/:sat_number", get(Self::sat_inscriptions))
        // .route(
        //   "/r/sat/:sat_number/:page",
        //   get(Self::sat_inscriptions_paginated),
        // )
        // .route(
        //   "/r/sat/:sat_number/at/:index",
        //   get(Self::sat_inscription_at_index),
        // )
        // .route("/range/:start/:end", get(Self::range))
        // .route("/rare.txt", get(Self::rare_txt))
        // .route("/rune/:rune", get(Self::rune))
        // .route("/runes", get(Self::runes))
        // .route("/sat/:sat", get(Self::sat))
        // .route("/search", get(Self::search_by_query))
        // .route("/search/*query", get(Self::search_by_path))
        // .route("/static/*path", get(Self::static_asset))
        // .route("/status", get(Self::status))
        // .route("/tx/:txid", get(Self::transaction))
        .layer(Extension(index))
        .layer(Extension(page_config))
        .layer(Extension(Arc::new(config)))
        .layer(SetResponseHeaderLayer::if_not_present(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'self'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
          header::STRICT_TRANSPORT_SECURITY,
          HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(
          CorsLayer::new()
            .allow_methods([http::Method::GET])
            .allow_origin(Any),
        )
        .layer(CompressionLayer::new())
        .with_state(server_config);

      match (self.http_port(), self.https_port()) {
        (Some(http_port), None) => {
          self
            .spawn(router, handle, http_port, SpawnConfig::Http)?
            .await??
        }
        (None, Some(https_port)) => {
          self
            .spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
            .await??
        }
        (Some(http_port), Some(https_port)) => {
          let http_spawn_config = if self.redirect_http_to_https {
            SpawnConfig::Redirect(if https_port == 443 {
              format!("https://{}", acme_domains[0])
            } else {
              format!("https://{}:{https_port}", acme_domains[0])
            })
          } else {
            SpawnConfig::Http
          };

          let (http_result, https_result) = tokio::join!(
            self.spawn(router.clone(), handle.clone(), http_port, http_spawn_config)?,
            self.spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
          );
          http_result.and(https_result)??;
        }
        (None, None) => unreachable!(),
      }

      Ok(Box::new(Empty {}) as Box<dyn Output>)
    })
  }

  fn spawn(
    &self,
    router: Router,
    handle: Handle,
    port: u16,
    config: SpawnConfig,
  ) -> Result<task::JoinHandle<io::Result<()>>> {
    let addr = (self.address.as_str(), port)
      .to_socket_addrs()?
      .next()
      .ok_or_else(|| anyhow!("failed to get socket addrs"))?;

    if !integration_test() {
      eprintln!(
        "Listening on {}://{addr}",
        match config {
          SpawnConfig::Https(_) => "https",
          _ => "http",
        }
      );
    }

    Ok(tokio::spawn(async move {
      match config {
        SpawnConfig::Https(acceptor) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .acceptor(acceptor)
            .serve(router.into_make_service())
            .await
        }
        SpawnConfig::Redirect(destination) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(
              Router::new()
                .fallback(Self::redirect_http_to_https)
                .layer(Extension(destination))
                .into_make_service(),
            )
            .await
        }
        SpawnConfig::Http => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await
        }
      }
    }))
  }

  fn acme_cache(acme_cache: Option<&PathBuf>, options: &Options) -> Result<PathBuf> {
    let acme_cache = if let Some(acme_cache) = acme_cache {
      acme_cache.clone()
    } else {
      options.data_dir()?.join("acme-cache")
    };

    Ok(acme_cache)
  }

  fn acme_domains(&self) -> Result<Vec<String>> {
    if !self.acme_domain.is_empty() {
      Ok(self.acme_domain.clone())
    } else {
      Ok(vec![System::new()
        .host_name()
        .ok_or(anyhow!("no hostname found"))?])
    }
  }

  fn http_port(&self) -> Option<u16> {
    if self.http || self.http_port.is_some() || (self.https_port.is_none() && !self.https) {
      Some(self.http_port.unwrap_or(80))
    } else {
      None
    }
  }

  fn https_port(&self) -> Option<u16> {
    if self.https || self.https_port.is_some() {
      Some(self.https_port.unwrap_or(443))
    } else {
      None
    }
  }

  fn acceptor(&self, options: &Options) -> Result<AxumAcceptor> {
    let config = AcmeConfig::new(self.acme_domains()?)
      .contact(&self.acme_contact)
      .cache_option(Some(DirCache::new(Self::acme_cache(
        self.acme_cache.as_ref(),
        options,
      )?)))
      .directory(if cfg!(test) {
        LETS_ENCRYPT_STAGING_DIRECTORY
      } else {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
      });

    let mut state = config.state();

    let acceptor = state.axum_acceptor(Arc::new(
      rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver()),
    ));

    tokio::spawn(async move {
      while let Some(result) = state.next().await {
        match result {
          Ok(ok) => log::info!("ACME event: {:?}", ok),
          Err(err) => log::error!("ACME error: {:?}", err),
        }
      }
    });

    Ok(acceptor)
  }

  fn index_height(index: &Index) -> ServerResult<Height> {
    index.block_height()?.ok_or_not_found(|| "genesis block")
  }

  async fn clock(Extension(index): Extension<Arc<Index>>) -> ServerResult<Response> {
    Ok(
      (
        [(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'unsafe-inline'"),
        )],
        ClockSvg::new(Self::index_height(&index)?),
      )
        .into_response(),
    )
  }

  async fn sat(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(sat)): Path<DeserializeFromStr<Sat>>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let inscriptions = index.get_inscription_ids_by_sat(sat)?;
    let satpoint = index.rare_sat_satpoint(sat)?.or_else(|| {
      inscriptions.first().and_then(|&first_inscription_id| {
        index
          .get_inscription_satpoint_by_id(first_inscription_id)
          .ok()
          .flatten()
      })
    });
    let blocktime = index.block_time(sat.height())?;
    Ok(if accept_json.0 {
      Json(SatJson {
        number: sat.0,
        decimal: sat.decimal().to_string(),
        degree: sat.degree().to_string(),
        name: sat.name(),
        block: sat.height().0,
        cycle: sat.cycle(),
        epoch: sat.epoch().0,
        period: sat.period(),
        offset: sat.third(),
        rarity: sat.rarity(),
        percentile: sat.percentile(),
        satpoint,
        timestamp: blocktime.timestamp().timestamp(),
        inscriptions,
      })
      .into_response()
    } else {
      SatHtml {
        sat,
        satpoint,
        blocktime,
        inscriptions,
      }
      .page(page_config)
      .into_response()
    })
  }

  async fn ordinal(Path(sat): Path<String>) -> Redirect {
    Redirect::to(&format!("/sat/{sat}"))
  }

  async fn output(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(outpoint): Path<OutPoint>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let list = index.list(outpoint)?;

    let output = if outpoint == OutPoint::null() || outpoint == unbound_outpoint() {
      let mut value = 0;

      if let Some(List::Unspent(ranges)) = &list {
        for (start, end) in ranges {
          value += end - start;
        }
      }

      TxOut {
        value,
        script_pubkey: ScriptBuf::new(),
      }
    } else {
      index
        .get_transaction(outpoint.txid)?
        .ok_or_not_found(|| format!("output {outpoint}"))?
        .output
        .into_iter()
        .nth(outpoint.vout as usize)
        .ok_or_not_found(|| format!("output {outpoint}"))?
    };

    let inscriptions = index.get_inscriptions_on_output(outpoint)?;

    let runes = index.get_rune_balances_for_outpoint(outpoint)?;

    Ok(if accept_json.0 {
      Json(OutputJson::new(
        outpoint,
        list,
        page_config.chain,
        output,
        inscriptions,
        runes
          .into_iter()
          .map(|(rune, pile)| (rune, pile.amount))
          .collect(),
      ))
      .into_response()
    } else {
      OutputHtml {
        outpoint,
        inscriptions,
        list,
        chain: page_config.chain,
        output,
        runes,
      }
      .page(page_config)
      .into_response()
    })
  }

  async fn range(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Path((DeserializeFromStr(start), DeserializeFromStr(end))): Path<(
      DeserializeFromStr<Sat>,
      DeserializeFromStr<Sat>,
    )>,
  ) -> ServerResult<PageHtml<RangeHtml>> {
    match start.cmp(&end) {
      Ordering::Equal => Err(ServerError::BadRequest("empty range".to_string())),
      Ordering::Greater => Err(ServerError::BadRequest(
        "range start greater than range end".to_string(),
      )),
      Ordering::Less => Ok(RangeHtml { start, end }.page(page_config)),
    }
  }

  async fn rare_txt(Extension(index): Extension<Arc<Index>>) -> ServerResult<RareTxt> {
    Ok(RareTxt(index.rare_sat_satpoints()?))
  }

  async fn rune(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(rune)): Path<DeserializeFromStr<Rune>>,
  ) -> ServerResult<PageHtml<RuneHtml>> {
    let (id, entry) = index.rune(rune)?.ok_or_else(|| {
      ServerError::NotFound(
        "tracking runes requires index created with `--index-runes-pre-alpha-i-agree-to-get-rekt` flag".into(),
      )
    })?;

    let parent = InscriptionId {
      txid: entry.etching,
      index: 0,
    };

    let parent = index.inscription_exists(parent)?.then_some(parent);

    Ok(RuneHtml { id, entry, parent }.page(page_config))
  }

  async fn runes(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<RunesHtml>> {
    Ok(
      RunesHtml {
        entries: index.runes()?,
      }
      .page(page_config),
    )
  }

  async fn home(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<HomeHtml>> {
    Ok(
      HomeHtml {
        inscriptions: index.get_home_inscriptions()?,
      }
      .page(page_config),
    )
  }

  async fn blocks(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<BlocksHtml>> {
    let blocks = index.blocks(100)?;
    let mut featured_blocks = BTreeMap::new();
    for (height, hash) in blocks.iter().take(5) {
      let (inscriptions, _total_num) =
        index.get_highest_paying_inscriptions_in_block(*height, 8)?;

      featured_blocks.insert(*hash, inscriptions);
    }

    Ok(BlocksHtml::new(blocks, featured_blocks).page(page_config))
  }

  async fn install_script() -> Redirect {
    Redirect::to("https://raw.githubusercontent.com/ordinals/ord/master/install.sh")
  }

  async fn block(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(query)): Path<DeserializeFromStr<BlockQuery>>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let (block, height) = match query {
      BlockQuery::Height(height) => {
        let block = index
          .get_block_by_height(height)?
          .ok_or_not_found(|| format!("block {height}"))?;

        (block, height)
      }
      BlockQuery::Hash(hash) => {
        let info = index
          .block_header_info(hash)?
          .ok_or_not_found(|| format!("block {hash}"))?;

        let block = index
          .get_block_by_hash(hash)?
          .ok_or_not_found(|| format!("block {hash}"))?;

        (block, u32::try_from(info.height).unwrap())
      }
    };

    Ok(if accept_json.0 {
      let inscriptions = index.get_inscriptions_in_block(height)?;
      Json(BlockJson::new(
        block,
        Height(height),
        Self::index_height(&index)?,
        inscriptions,
      ))
      .into_response()
    } else {
      let (featured_inscriptions, total_num) =
        index.get_highest_paying_inscriptions_in_block(height, 8)?;
      BlockHtml::new(
        block,
        Height(height),
        Self::index_height(&index)?,
        total_num,
        featured_inscriptions,
      )
      .page(page_config)
      .into_response()
    })
  }

  async fn transaction(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(txid): Path<Txid>,
  ) -> ServerResult<PageHtml<TransactionHtml>> {
    let inscription = index.get_inscription_by_id(InscriptionId { txid, index: 0 })?;

    let blockhash = index.get_transaction_blockhash(txid)?;

    Ok(
      TransactionHtml::new(
        index
          .get_transaction(txid)?
          .ok_or_not_found(|| format!("transaction {txid}"))?,
        blockhash,
        inscription.map(|_| InscriptionId { txid, index: 0 }),
        page_config.chain,
        index.get_etching(txid)?,
      )
      .page(page_config),
    )
  }

  async fn metadata(
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Json<String>> {
    let metadata = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?
      .metadata
      .ok_or_not_found(|| format!("inscription {inscription_id} metadata"))?;

    Ok(Json(hex::encode(metadata)))
  }

  async fn status(Extension(index): Extension<Arc<Index>>) -> (StatusCode, &'static str) {
    if index.is_unrecoverably_reorged() {
      (
        StatusCode::OK,
        "unrecoverable reorg detected, please rebuild the database.",
      )
    } else {
      (
        StatusCode::OK,
        StatusCode::OK.canonical_reason().unwrap_or_default(),
      )
    }
  }

  async fn search_by_query(
    Extension(index): Extension<Arc<Index>>,
    Query(search): Query<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(&index, &search.query).await
  }

  async fn search_by_path(
    Extension(index): Extension<Arc<Index>>,
    Path(search): Path<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(&index, &search.query).await
  }

  async fn search(index: &Index, query: &str) -> ServerResult<Redirect> {
    Self::search_inner(index, query)
  }

  fn search_inner(index: &Index, query: &str) -> ServerResult<Redirect> {
    lazy_static! {
      static ref HASH: Regex = Regex::new(r"^[[:xdigit:]]{64}$").unwrap();
      static ref INSCRIPTION_ID: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
      static ref OUTPOINT: Regex = Regex::new(r"^[[:xdigit:]]{64}:\d+$").unwrap();
      static ref RUNE: Regex = Regex::new(r"^[A-Z]+$").unwrap();
      static ref RUNE_ID: Regex = Regex::new(r"^[0-9]+/[0-9]+$").unwrap();
    }

    let query = query.trim();

    if HASH.is_match(query) {
      if index.block_header(query.parse().unwrap())?.is_some() {
        Ok(Redirect::to(&format!("/block/{query}")))
      } else {
        Ok(Redirect::to(&format!("/tx/{query}")))
      }
    } else if OUTPOINT.is_match(query) {
      Ok(Redirect::to(&format!("/output/{query}")))
    } else if INSCRIPTION_ID.is_match(query) {
      Ok(Redirect::to(&format!("/inscription/{query}")))
    } else if RUNE.is_match(query) {
      Ok(Redirect::to(&format!("/rune/{query}")))
    } else if RUNE_ID.is_match(query) {
      let id = query
        .parse::<RuneId>()
        .map_err(|err| ServerError::BadRequest(err.to_string()))?;

      let rune = index.get_rune_by_id(id)?.ok_or_not_found(|| "rune ID")?;

      Ok(Redirect::to(&format!("/rune/{rune}")))
    } else {
      Ok(Redirect::to(&format!("/sat/{query}")))
    }
  }

  async fn favicon(user_agent: Option<TypedHeader<UserAgent>>) -> ServerResult<Response> {
    if user_agent
      .map(|user_agent| {
        user_agent.as_str().contains("Safari/")
          && !user_agent.as_str().contains("Chrome/")
          && !user_agent.as_str().contains("Chromium/")
      })
      .unwrap_or_default()
    {
      Ok(
        Self::static_asset(Path("/favicon.png".to_string()))
          .await
          .into_response(),
      )
    } else {
      Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'unsafe-inline'"),
          )],
          Self::static_asset(Path("/favicon.svg".to_string())).await?,
        )
          .into_response(),
      )
    }
  }

  async fn feed(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<Response> {
    let mut builder = rss::ChannelBuilder::default();

    let chain = page_config.chain;
    match chain {
      Chain::Mainnet => builder.title("Inscriptions".to_string()),
      _ => builder.title(format!("Inscriptions – {chain:?}")),
    };

    builder.generator(Some("ord".to_string()));

    for (number, id) in index.get_feed_inscriptions(300)? {
      builder.item(
        rss::ItemBuilder::default()
          .title(Some(format!("Inscription {number}")))
          .link(Some(format!("/inscription/{id}")))
          .guid(Some(rss::Guid {
            value: format!("/inscription/{id}"),
            permalink: true,
          }))
          .build(),
      );
    }

    Ok(
      (
        [
          (header::CONTENT_TYPE, "application/rss+xml"),
          (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'unsafe-inline'",
          ),
        ],
        builder.build().to_string(),
      )
        .into_response(),
    )
  }

  async fn static_asset(Path(path): Path<String>) -> ServerResult<Response> {
    let content = StaticAssets::get(if let Some(stripped) = path.strip_prefix('/') {
      stripped
    } else {
      &path
    })
    .ok_or_not_found(|| format!("asset {path}"))?;
    let body = body::boxed(body::Full::from(content.data));
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Ok(
      Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .body(body)
        .unwrap(),
    )
  }

  async fn block_count(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    Ok(index.block_count()?.to_string())
  }

  async fn block_height(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    Ok(
      index
        .block_height()?
        .ok_or_not_found(|| "blockheight")?
        .to_string(),
    )
  }

  async fn block_hash(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    Ok(
      index
        .block_hash(None)?
        .ok_or_not_found(|| "blockhash")?
        .to_string(),
    )
  }

  async fn block_hash_json(Extension(index): Extension<Arc<Index>>) -> ServerResult<Json<String>> {
    Ok(Json(
      index
        .block_hash(None)?
        .ok_or_not_found(|| "blockhash")?
        .to_string(),
    ))
  }

  async fn block_hash_from_height(
    Extension(index): Extension<Arc<Index>>,
    Path(height): Path<u32>,
  ) -> ServerResult<String> {
    Ok(
      index
        .block_hash(Some(height))?
        .ok_or_not_found(|| "blockhash")?
        .to_string(),
    )
  }

  async fn block_hash_from_height_json(
    Extension(index): Extension<Arc<Index>>,
    Path(height): Path<u32>,
  ) -> ServerResult<Json<String>> {
    Ok(Json(
      index
        .block_hash(Some(height))?
        .ok_or_not_found(|| "blockhash")?
        .to_string(),
    ))
  }

  async fn block_time(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    Ok(
      index
        .block_time(index.block_height()?.ok_or_not_found(|| "blocktime")?)?
        .unix_timestamp()
        .to_string(),
    )
  }

  async fn input(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(path): Path<(u32, usize, usize)>,
  ) -> Result<PageHtml<InputHtml>, ServerError> {
    let not_found = || format!("input /{}/{}/{}", path.0, path.1, path.2);

    let block = index
      .get_block_by_height(path.0)?
      .ok_or_not_found(not_found)?;

    let transaction = block
      .txdata
      .into_iter()
      .nth(path.1)
      .ok_or_not_found(not_found)?;

    let input = transaction
      .input
      .into_iter()
      .nth(path.2)
      .ok_or_not_found(not_found)?;

    Ok(InputHtml { path, input }.page(page_config))
  }

  async fn faq() -> Redirect {
    Redirect::to("https://docs.ordinals.com/faq/")
  }

  async fn bounties() -> Redirect {
    Redirect::to("https://docs.ordinals.com/bounty/")
  }

  async fn content(
    Extension(index): Extension<Arc<Index>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(page_config): Extension<Arc<PageConfig>>,
    Path(inscription_id): Path<InscriptionId>,
    accept_encoding: AcceptEncoding,
  ) -> ServerResult<Response> {
    if config.is_hidden(inscription_id) {
      return Ok(PreviewUnknownHtml.into_response());
    }

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    Ok(
      Self::content_response(inscription, accept_encoding, &page_config)?
        .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
        .into_response(),
    )
  }

  fn content_response(
    inscription: Inscription,
    accept_encoding: AcceptEncoding,
    page_config: &PageConfig,
  ) -> ServerResult<Option<(HeaderMap, Vec<u8>)>> {
    let mut headers = HeaderMap::new();

    headers.insert(
      header::CONTENT_TYPE,
      inscription
        .content_type()
        .and_then(|content_type| content_type.parse().ok())
        .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );

    if let Some(content_encoding) = inscription.content_encoding() {
      if accept_encoding.is_acceptable(&content_encoding) {
        headers.insert(header::CONTENT_ENCODING, content_encoding);
      } else {
        return Err(ServerError::NotAcceptable(
          content_encoding.to_str().unwrap_or_default().to_string(),
        ));
      }
    }

    match &page_config.csp_origin {
      None => {
        headers.insert(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:"),
        );
        headers.append(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src *:*/content/ *:*/blockheight *:*/blockhash *:*/blockhash/ *:*/blocktime *:*/r/ 'unsafe-eval' 'unsafe-inline' data: blob:"),
        );
      }
      Some(origin) => {
        let csp = format!("default-src {origin}/content/ {origin}/blockheight {origin}/blockhash {origin}/blockhash/ {origin}/blocktime {origin}/r/ 'unsafe-eval' 'unsafe-inline' data: blob:");
        headers.insert(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_str(&csp).map_err(|err| ServerError::Internal(Error::from(err)))?,
        );
      }
    }

    headers.insert(
      header::CACHE_CONTROL,
      HeaderValue::from_static("max-age=31536000, immutable"),
    );

    let Some(body) = inscription.into_body() else {
      return Ok(None);
    };

    Ok(Some((headers, body)))
  }

  async fn preview(
    Extension(index): Extension<Arc<Index>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(page_config): Extension<Arc<PageConfig>>,
    Path(inscription_id): Path<InscriptionId>,
    accept_encoding: AcceptEncoding,
  ) -> ServerResult<Response> {
    if config.is_hidden(inscription_id) {
      return Ok(PreviewUnknownHtml.into_response());
    }

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    match inscription.media() {
      Media::Audio => Ok(PreviewAudioHtml { inscription_id }.into_response()),
      Media::Code(language) => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self' https://cdn.jsdelivr.net",
          )],
          PreviewCodeHtml {
            inscription_id,
            language,
          },
        )
          .into_response(),
      ),
      Media::Font => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self'; style-src 'self' 'unsafe-inline';",
          )],
          PreviewFontHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Iframe => Ok(
        Self::content_response(inscription, accept_encoding, &page_config)?
          .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
          .into_response(),
      ),
      Media::Image => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self' 'unsafe-inline'",
          )],
          PreviewImageHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Markdown => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self' https://cdn.jsdelivr.net",
          )],
          PreviewMarkdownHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Model => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self' https://ajax.googleapis.com",
          )],
          PreviewModelHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Pdf => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self' https://cdn.jsdelivr.net",
          )],
          PreviewPdfHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Text => Ok(PreviewTextHtml { inscription_id }.into_response()),
      Media::Unknown => Ok(PreviewUnknownHtml.into_response()),
      Media::Video => Ok(PreviewVideoHtml { inscription_id }.into_response()),
    }
  }

  async fn inscription(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(query)): Path<DeserializeFromStr<InscriptionQuery>>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let inscription_id = match query {
      InscriptionQuery::Id(id) => id,
      InscriptionQuery::Number(inscription_number) => index
        .get_inscription_id_by_inscription_number(inscription_number)?
        .ok_or_not_found(|| format!("{inscription_number}"))?,
    };

    let entry = index
      .get_inscription_entry(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let satpoint = index
      .get_inscription_satpoint_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let output = if satpoint.outpoint == unbound_outpoint() || satpoint.outpoint == OutPoint::null()
    {
      None
    } else {
      Some(
        index
          .get_transaction(satpoint.outpoint.txid)?
          .ok_or_not_found(|| format!("inscription {inscription_id} current transaction"))?
          .output
          .into_iter()
          .nth(satpoint.outpoint.vout.try_into().unwrap())
          .ok_or_not_found(|| format!("inscription {inscription_id} current transaction output"))?,
      )
    };

    let previous = if let Some(n) = entry.sequence_number.checked_sub(1) {
      index.get_inscription_id_by_sequence_number(n)?
    } else {
      None
    };

    let next = index.get_inscription_id_by_sequence_number(entry.sequence_number + 1)?;

    let (children, _more_children) =
      index.get_children_by_sequence_number_paginated(entry.sequence_number, 4, 0)?;

    let rune = index.get_rune_by_sequence_number(entry.sequence_number)?;

    let parent = match entry.parent {
      Some(parent) => index.get_inscription_id_by_sequence_number(parent)?,
      None => None,
    };

    let mut charms = entry.charms;

    if satpoint.outpoint == OutPoint::null() {
      Charm::Lost.set(&mut charms);
    }

    Ok(if accept_json.0 {
      Json(InscriptionJson {
        inscription_id,
        children,
        inscription_number: entry.inscription_number,
        genesis_height: entry.height,
        parent,
        genesis_fee: entry.fee,
        output_value: output.as_ref().map(|o| o.value),
        address: output
          .as_ref()
          .and_then(|o| page_config.chain.address_from_script(&o.script_pubkey).ok())
          .map(|address| address.to_string()),
        sat: entry.sat,
        satpoint,
        content_type: inscription.content_type().map(|s| s.to_string()),
        content_length: inscription.content_length(),
        timestamp: timestamp(entry.timestamp).timestamp(),
        previous,
        next,
        rune,
      })
      .into_response()
    } else {
      InscriptionHtml {
        chain: page_config.chain,
        charms,
        children,
        genesis_fee: entry.fee,
        genesis_height: entry.height,
        inscription,
        inscription_id,
        inscription_number: entry.inscription_number,
        next,
        output,
        parent,
        previous,
        rune,
        sat: entry.sat,
        satpoint,
        timestamp: timestamp(entry.timestamp),
      }
      .page(page_config)
      .into_response()
    })
  }

  async fn collections(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<Response> {
    Self::collections_paginated(Extension(page_config), Extension(index), Path(0)).await
  }

  async fn collections_paginated(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(page_index): Path<usize>,
  ) -> ServerResult<Response> {
    let (collections, more_collections) = index.get_collections_paginated(100, page_index)?;

    let prev = page_index.checked_sub(1);

    let next = more_collections.then_some(page_index + 1);

    Ok(
      CollectionsHtml {
        inscriptions: collections,
        prev,
        next,
      }
      .page(page_config)
      .into_response(),
    )
  }

  async fn children(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Response> {
    Self::children_paginated(
      Extension(page_config),
      Extension(index),
      Path((inscription_id, 0)),
    )
    .await
  }

  async fn children_paginated(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((parent, page)): Path<(InscriptionId, usize)>,
  ) -> ServerResult<Response> {
    let entry = index
      .get_inscription_entry(parent)?
      .ok_or_not_found(|| format!("inscription {parent}"))?;

    let parent_number = entry.inscription_number;

    let (children, more_children) =
      index.get_children_by_sequence_number_paginated(entry.sequence_number, 100, page)?;

    let prev_page = page.checked_sub(1);

    let next_page = more_children.then_some(page + 1);

    Ok(
      ChildrenHtml {
        parent,
        parent_number,
        children,
        prev_page,
        next_page,
      }
      .page(page_config)
      .into_response(),
    )
  }

  async fn children_recursive(
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Response> {
    Self::children_recursive_paginated(Extension(index), Path((inscription_id, 0))).await
  }

  async fn children_recursive_paginated(
    Extension(index): Extension<Arc<Index>>,
    Path((parent, page)): Path<(InscriptionId, usize)>,
  ) -> ServerResult<Response> {
    let parent_sequence_number = index
      .get_inscription_entry(parent)?
      .ok_or_not_found(|| format!("inscription {parent}"))?
      .sequence_number;

    let (ids, more) =
      index.get_children_by_sequence_number_paginated(parent_sequence_number, 100, page)?;

    Ok(Json(ChildrenJson { ids, more, page }).into_response())
  }

  async fn inscriptions(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    Self::inscriptions_paginated(
      Extension(page_config),
      Extension(index),
      Path(0),
      accept_json,
    )
    .await
  }

  async fn inscriptions_paginated(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(page_index): Path<usize>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let (inscriptions, more_inscriptions) = index.get_inscriptions_paginated(100, page_index)?;

    let prev = page_index.checked_sub(1);

    let next = more_inscriptions.then_some(page_index + 1);

    Ok(if accept_json.0 {
      Json(InscriptionsJson {
        inscriptions,
        page_index,
        more: more_inscriptions,
      })
      .into_response()
    } else {
      InscriptionsHtml {
        inscriptions,
        next,
        prev,
      }
      .page(page_config)
      .into_response()
    })
  }

  async fn inscriptions_in_block(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(block_height): Path<u32>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    Self::inscriptions_in_block_paginated(
      Extension(page_config),
      Extension(index),
      Path((block_height, 0)),
      accept_json,
    )
    .await
  }

  async fn inscriptions_in_block_paginated(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((block_height, page_index)): Path<(u32, usize)>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    let page_size = 100;

    let mut inscriptions = index
      .get_inscriptions_in_block(block_height)?
      .into_iter()
      .skip(page_index.saturating_mul(page_size))
      .take(page_size.saturating_add(1))
      .collect::<Vec<InscriptionId>>();

    let more = inscriptions.len() > page_size;

    if more {
      inscriptions.pop();
    }

    Ok(if accept_json.0 {
      Json(InscriptionsJson {
        inscriptions,
        page_index,
        more,
      })
      .into_response()
    } else {
      InscriptionsBlockHtml::new(
        block_height,
        index.block_height()?.unwrap_or(Height(0)).n(),
        inscriptions,
        page_index,
      )?
      .page(page_config)
      .into_response()
    })
  }

  async fn sat_inscriptions(
    Extension(index): Extension<Arc<Index>>,
    Path(sat): Path<u64>,
  ) -> ServerResult<Json<SatInscriptionsJson>> {
    Self::sat_inscriptions_paginated(Extension(index), Path((sat, 0))).await
  }

  async fn sat_inscriptions_paginated(
    Extension(index): Extension<Arc<Index>>,
    Path((sat, page)): Path<(u64, u64)>,
  ) -> ServerResult<Json<SatInscriptionsJson>> {
    if !index.has_sat_index() {
      return Err(ServerError::NotFound(
        "this server has no sat index".to_string(),
      ));
    }

    let (ids, more) = index.get_inscription_ids_by_sat_paginated(Sat(sat), 100, page)?;

    Ok(Json(SatInscriptionsJson { ids, more, page }))
  }

  async fn sat_inscription_at_index(
    Extension(index): Extension<Arc<Index>>,
    Path((DeserializeFromStr(sat), inscription_index)): Path<(DeserializeFromStr<Sat>, isize)>,
  ) -> ServerResult<Json<SatInscriptionJson>> {
    if !index.has_sat_index() {
      return Err(ServerError::NotFound(
        "this server has no sat index".to_string(),
      ));
    }

    let id = index.get_inscription_id_by_sat_indexed(sat, inscription_index)?;

    Ok(Json(SatInscriptionJson { id }))
  }

  async fn redirect_http_to_https(
    Extension(mut destination): Extension<String>,
    uri: Uri,
  ) -> Redirect {
    if let Some(path_and_query) = uri.path_and_query() {
      destination.push_str(path_and_query.as_str());
    }

    Redirect::to(&destination)
  }
}
