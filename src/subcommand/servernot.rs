use {
  self::{
    // deserialize_from_str::DeserializeFromStr,
    error::{OptionExt, ServerError, ServerResult},
  },
  super::*,
  crate::page_config::PageConfig,
  // crate::templates::{
  //   BlockHtml, ClockSvg, HomeHtml, InputHtml, InscriptionHtml, InscriptionsHtml, OutputHtml,
  //   PageContent, PageHtml, PreviewAudioHtml, PreviewImageHtml, PreviewPdfHtml, PreviewTextHtml,
  //   PreviewUnknownHtml, PreviewVideoHtml, RangeHtml, RareTxt, SatHtml, TransactionHtml,
  // },
  axum::{
    // body,
    extract::{Extension, Path, Query},
    // headers::UserAgent,
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
  std::{cmp::Ordering, str},
  tokio_stream::StreamExt,
  tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
  },
};

mod error;

// enum BlockQuery {
//   Height(u64),
//   Hash(BlockHash),
// }

// impl FromStr for BlockQuery {
//   type Err = Error;

//   fn from_str(s: &str) -> Result<Self, Self::Err> {
//     Ok(if s.len() == 64 {
//       BlockQuery::Hash(s.parse()?)
//     } else {
//       BlockQuery::Height(s.parse()?)
//     })
//   }
// }

enum SpawnConfig {
  Https(AxumAcceptor),
  Http,
  Redirect(String),
}

// #[derive(Deserialize)]
// struct Search {
//   query: String,
// }

// #[derive(RustEmbed)]
// #[folder = "static"]
// struct StaticAssets;

// struct StaticHtml {
//   title: &'static str,
//   html: &'static str,
// }

// impl PageContent for StaticHtml {
//   fn title(&self) -> String {
//     self.title.into()
//   }
// }

// impl Display for StaticHtml {
//   fn fmt(&self, f: &mut Formatter) -> fmt::Result {
//     f.write_str(self.html)
//   }
// }

#[derive(Debug, Parser)]
pub(crate) struct Servernot {
  #[clap(
    long,
    default_value = "0.0.0.0",
    help = "Listen on <ADDRESS> for incoming requests."
  )]
  address: String,
  #[clap(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  acme_domain: Vec<String>,
  #[clap(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]."
  )]
  http_port: Option<u16>,
  #[clap(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]."
  )]
  https_port: Option<u16>,
  #[clap(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  acme_cache: Option<PathBuf>,
  #[clap(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  acme_contact: Vec<String>,
  #[clap(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  http: bool,
  #[clap(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  https: bool,
  #[clap(long, help = "Redirect HTTP traffic to HTTPS.")]
  redirect_http_to_https: bool,
}

impl Servernot {
  pub(crate) fn run(self, options: Options, index: Arc<Indexnot>, handle: Handle) -> Result {
    Runtime::new()?.block_on(async {
      // let index_clone = index.clone();
      // let index_thread = thread::spawn(move || loop {
      //   if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
      //     break;
      //   }
      //   if let Err(error) = index_clone.update() {
      //     log::warn!("{error}");
      //   }
      //   thread::sleep(Duration::from_millis(5000));
      // });
      // INDEXER.lock().unwrap().replace(index_thread);

      let config = options.load_config()?;
      let acme_domains = self.acme_domains()?;

      let page_config = Arc::new(PageConfig {
        chain: options.chain(),
        domain: acme_domains.first().cloned(),
      });

      let router = Router::new()
        .route("/status", get(Self::status))
        .route("/tx/:txid", get(Self::transaction))
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
        .layer(CompressionLayer::new());

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

      Ok(())
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

  // fn index_height(index: &Index) -> ServerResult<Height> {
  //   index.block_height()?.ok_or_not_found(|| "genesis block")
  // }

  async fn transaction(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Indexnot>>,
    Path(txid): Path<Txid>,
  ) -> ServerResult<Response> {
    // let inscription = index.get_inscription_by_id(txid.into())?;
    Ok(
      String::from("hello from get transaction").into_response()
      // String::from(format!("txid {}", txid.into())).into_response()
    )
  }

  async fn status(Extension(index): Extension<Arc<Indexnot>>) -> (StatusCode, &'static str) {
    // if index.is_reorged() {
    //   (
    //     StatusCode::OK,
    //     "reorg detected, please rebuild the database.",
    //   )
    // } else {
      (
        StatusCode::OK,
        StatusCode::OK.canonical_reason().unwrap_or_default(),
      )
    // }
  }

  // fn content_response(inscription: Inscription) -> Option<(HeaderMap, Vec<u8>)> {
  //   let mut headers = HeaderMap::new();

  //   headers.insert(
  //     header::CONTENT_TYPE,
  //     inscription
  //       .content_type()
  //       .unwrap_or("application/octet-stream")
  //       .parse()
  //       .unwrap(),
  //   );
  //   headers.insert(
  //     header::CONTENT_SECURITY_POLICY,
  //     HeaderValue::from_static("default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:"),
  //   );
  //   headers.append(
  //     header::CONTENT_SECURITY_POLICY,
  //     HeaderValue::from_static("default-src *:*/content/ *:*/blockheight *:*/blockhash *:*/blockhash/ *:*/blocktime 'unsafe-eval' 'unsafe-inline' data: blob:"),
  //   );

  //   let body = inscription.into_body();
  //   let cache_control = match body {
  //     Some(_) => "max-age=31536000, immutable",
  //     None => "max-age=600",
  //   };
  //   headers.insert(
  //     header::CACHE_CONTROL,
  //     HeaderValue::from_str(cache_control).unwrap(),
  //   );

  //   Some((headers, body?))
  // }

  // async fn inscriptions_inner(
  //   page_config: Arc<PageConfig>,
  //   index: Arc<Index>,
  //   from: Option<i64>,
  // ) -> ServerResult<PageHtml<InscriptionsHtml>> {
  //   let (inscriptions, prev, next) = index.get_latest_inscriptions_with_prev_and_next(100, from)?;
  //   Ok(
  //     InscriptionsHtml {
  //       inscriptions,
  //       next,
  //       prev,
  //     }
  //     .page(page_config, index.has_sat_index()?),
  //   )
  // }

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
