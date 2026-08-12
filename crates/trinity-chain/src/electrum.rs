//! Electrum [`ChainBackend`] — Spec §1.6, WP-14.
//!
//! Built on `bdk_electrum 0.24.0` → `electrum-client 0.25.0`. Configuration
//! surface matches the Spec table: host, port, TLS pin, optional SOCKS5 (Tor).
//!
//! ## No silent fallback
//!
//! Connection and protocol failures map to [`ChainError`] only. This module
//! never opens a Core RPC or CBF path (S13 / T16).

use std::fmt;
use std::time::Duration;

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_electrum::electrum_client::{self, Client, ConfigBuilder, ElectrumApi, Socks5Config};
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{Transaction, Txid};

use crate::backend::ChainBackend;
use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Default stop-gap for full scan (matches watch-wallet gap limit order).
pub const DEFAULT_STOP_GAP: usize = 20;

/// Default Electrum batch size for history queries.
pub const DEFAULT_BATCH_SIZE: usize = 20;

/// Confirmation targets requested from `blockchain.estimatefee` (blocks).
const FEE_TARGETS_BLOCKS: &[u32] = &[1, 3, 6, 144];

/// Optional SOCKS5 proxy (typically Tor at `127.0.0.1:9050`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5Proxy {
    /// `host:port` of the SOCKS5 endpoint.
    pub addr: String,
    /// Optional username/password.
    pub credentials: Option<(String, String)>,
}

impl Socks5Proxy {
    /// Proxy without credentials.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            credentials: None,
        }
    }

    fn to_electrum(&self) -> Socks5Config {
        match &self.credentials {
            Some((user, pass)) => {
                Socks5Config::with_credentials(self.addr.clone(), user.clone(), pass.clone())
            }
            None => Socks5Config::new(self.addr.clone()),
        }
    }
}

/// Connection settings for [`ElectrumBackend`] — Spec §1.6 table.
///
/// There is **no vendor default server** (Spec §1.6): the caller always
/// supplies host and port. Test env: `127.0.0.1:60401` (plaintext electrs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectrumConfig {
    /// Electrum server hostname or IP.
    pub host: String,
    /// Electrum TCP/TLS port.
    pub port: u16,
    /// When `true`, connect with `ssl://` (TLS). When `false`, `tcp://`.
    pub use_tls: bool,
    /// Optional TLS certificate pin (SHA-256 hex of the peer DER certificate).
    ///
    /// Spec §1.6 lists "TLS pin" as configuration. `electrum-client` 0.25
    /// verifies the certificate chain / domain but does not expose fingerprint
    /// pinning APIs; the pin is retained on the config surface for callers/UI.
    /// `tls_pin` without `use_tls` is rejected at connect.
    pub tls_pin: Option<String>,
    /// Optional SOCKS5 proxy (Tor).
    pub socks5: Option<Socks5Proxy>,
    /// `true` → [`PrivacyProfile::electrum_own_server`]; `false` → third-party.
    pub own_server: bool,
    /// Full-scan stop gap (unused SPKs before stopping a keychain).
    pub stop_gap: usize,
    /// Max scriptPubKeys per Electrum batch request.
    pub batch_size: usize,
    /// Socket timeout; `None` uses electrum-client default.
    pub timeout: Option<Duration>,
    /// Retry count after a failed call (0 = fail on first network error).
    pub retry: u8,
    /// Whether to validate the TLS domain name (ignored for plaintext).
    pub validate_domain: bool,
    /// Fetch previous TxOuts during scan/sync (needed for fee calculation on
    /// foreign inputs). Costs extra Electrum round-trips.
    pub fetch_prev_txouts: bool,
}

impl ElectrumConfig {
    /// Minimal plaintext config (host, port). Own-server privacy by default
    /// when the user enters a host (no third-party preset without opt-in).
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            use_tls: false,
            tls_pin: None,
            socks5: None,
            own_server: true,
            stop_gap: DEFAULT_STOP_GAP,
            batch_size: DEFAULT_BATCH_SIZE,
            timeout: Some(Duration::from_secs(30)),
            retry: 1,
            validate_domain: true,
            fetch_prev_txouts: false,
        }
    }

    /// Local regtest electrs from `./scripts/test-env.sh` (`127.0.0.1:60401`).
    pub fn regtest_electrs() -> Self {
        let mut c = Self::new("127.0.0.1", 60401);
        c.own_server = true;
        c.use_tls = false;
        c.timeout = Some(Duration::from_secs(10));
        c.retry = 0;
        c
    }

    /// Mark as third-party Electrum (T16 selection warning).
    pub fn third_party(mut self) -> Self {
        self.own_server = false;
        self
    }

    /// Mark as user-operated server.
    pub fn own_server(mut self) -> Self {
        self.own_server = true;
        self
    }

    /// Enable TLS (`ssl://`).
    pub fn with_tls(mut self, pin: Option<String>) -> Self {
        self.use_tls = true;
        self.tls_pin = pin;
        self
    }

    /// Route traffic through SOCKS5 (Tor).
    pub fn with_socks5(mut self, proxy: Socks5Proxy) -> Self {
        self.socks5 = Some(proxy);
        self
    }

    /// Build the Electrum URL (`tcp://host:port` or `ssl://host:port`).
    pub fn server_url(&self) -> String {
        let scheme = if self.use_tls { "ssl" } else { "tcp" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    fn validate(&self) -> Result<(), ChainError> {
        if self.host.trim().is_empty() {
            return Err(ChainError::Other("electrum host must not be empty".into()));
        }
        if self.tls_pin.is_some() && !self.use_tls {
            return Err(ChainError::Other(
                "tls_pin requires use_tls (ssl connection)".into(),
            ));
        }
        if self.stop_gap == 0 {
            return Err(ChainError::Other("stop_gap must be >= 1".into()));
        }
        if self.batch_size == 0 {
            return Err(ChainError::Other("batch_size must be >= 1".into()));
        }
        Ok(())
    }

    fn electrum_config(&self) -> electrum_client::Config {
        let socks5 = self.socks5.as_ref().map(Socks5Proxy::to_electrum);
        ConfigBuilder::new()
            .socks5(socks5)
            .timeout(self.timeout)
            .retry(self.retry)
            .validate_domain(self.validate_domain)
            .build()
    }
}

/// Electrum-server [`ChainBackend`] (WP-14).
///
/// Holds a connected [`BdkElectrumClient`]. Construction opens the socket;
/// failures surface as [`ChainError::Network`] with no alternate backend.
pub struct ElectrumBackend {
    client: BdkElectrumClient<Client>,
    config: ElectrumConfig,
}

impl fmt::Debug for ElectrumBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElectrumBackend")
            .field("url", &self.config.server_url())
            .field("own_server", &self.config.own_server)
            .field("socks5", &self.config.socks5.is_some())
            .field("use_tls", &self.config.use_tls)
            .field("has_tls_pin", &self.config.tls_pin.is_some())
            .finish()
    }
}

impl ElectrumBackend {
    /// Connect to the configured Electrum server.
    ///
    /// On failure returns [`ChainError`] only — never falls back to Core RPC
    /// or CBF (S13).
    pub fn connect(config: ElectrumConfig) -> Result<Self, ChainError> {
        config.validate()?;
        let url = config.server_url();
        let ecfg = config.electrum_config();
        let raw = Client::from_config(&url, ecfg).map_err(map_electrum_error)?;
        let client = BdkElectrumClient::new(raw);
        Ok(Self { client, config })
    }

    /// Configuration used for this connection.
    pub fn config(&self) -> &ElectrumConfig {
        &self.config
    }

    /// Underlying BDK Electrum client (cache population, advanced use).
    pub fn client(&self) -> &BdkElectrumClient<Client> {
        &self.client
    }
}

impl ChainBackend for ElectrumBackend {
    fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
        let response = self
            .client
            .full_scan(
                req,
                self.config.stop_gap,
                self.config.batch_size,
                self.config.fetch_prev_txouts,
            )
            .map_err(map_electrum_error)?;
        Ok(Update::from(response))
    }

    fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
        let response = self
            .client
            .sync(req, self.config.batch_size, self.config.fetch_prev_txouts)
            .map_err(map_electrum_error)?;
        Ok(Update::from(response))
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        self.client
            .transaction_broadcast(tx)
            .map_err(map_broadcast_error)
    }

    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
        let mut targets = Vec::with_capacity(FEE_TARGETS_BLOCKS.len());
        for &blocks in FEE_TARGETS_BLOCKS {
            // electrum-client: BTC per kilobyte; -1 means no estimate.
            let btc_per_kb = self
                .client
                .inner
                .estimate_fee(blocks as usize, None)
                .map_err(map_electrum_error)?;
            if let Some(sat_vb) = btc_per_kb_to_sat_per_vb(btc_per_kb) {
                targets.push((blocks, sat_vb));
            }
        }
        Ok(FeeEstimates::from_targets(targets))
    }

    fn tip_height(&self) -> Result<u32, ChainError> {
        let header = self
            .client
            .inner
            .block_headers_subscribe()
            .map_err(map_electrum_error)?;
        Ok(header.height as u32)
    }

    fn privacy_profile(&self) -> PrivacyProfile {
        if self.config.own_server {
            PrivacyProfile::electrum_own_server()
        } else {
            PrivacyProfile::electrum_third_party()
        }
    }
}

/// Map Electrum BTC/kB feerate to sat/vB. Returns `None` for unknown (-1) or
/// non-finite values.
fn btc_per_kb_to_sat_per_vb(btc_per_kb: f64) -> Option<u64> {
    if !btc_per_kb.is_finite() || btc_per_kb < 0.0 {
        return None;
    }
    // 1 BTC/kB = 1e8 sat / 1000 vB = 1e5 sat/vB.
    let sat = (btc_per_kb * 100_000.0).round();
    if sat < 0.0 || sat > u64::MAX as f64 {
        return None;
    }
    Some(sat as u64)
}

fn map_broadcast_error(err: electrum_client::Error) -> ChainError {
    // Broadcast rejections are protocol-level; connection loss is network.
    if is_transport_error(&err) {
        map_electrum_error(err)
    } else {
        ChainError::Broadcast(err.to_string())
    }
}

fn is_transport_error(err: &electrum_client::Error) -> bool {
    matches!(
        err,
        electrum_client::Error::IOError(_)
            | electrum_client::Error::SharedIOError(_)
            | electrum_client::Error::AllAttemptsErrored(_)
            | electrum_client::Error::CouldNotCreateConnection(_)
            | electrum_client::Error::InvalidDNSNameError(_)
            | electrum_client::Error::MissingDomain
    )
}

fn map_electrum_error(err: electrum_client::Error) -> ChainError {
    use electrum_client::Error as E;
    // Group arms so each semantic class is one branch: transport → Network,
    // bad payload → Protocol, local client state → Unavailable. Individual
    // variants within a class are not constructible in unit tests without
    // private electrum/rustls types (TESTING.md §3.2 network-error exception).
    match err {
        e if is_transport_error(&e) => {
            let msg = match &e {
                E::AllAttemptsErrored(errs) => format!(
                    "all attempts failed: {}",
                    errs.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                other => other.to_string(),
            };
            ChainError::Network(msg)
        }
        E::Protocol(v) | E::InvalidResponse(v) => ChainError::Protocol(v.to_string()),
        E::JSON(e) => ChainError::Protocol(format!("json: {e}")),
        E::Bitcoin(e) => ChainError::Protocol(format!("bitcoin decode: {e}")),
        E::Hex(e) => ChainError::Protocol(format!("hex: {e}")),
        E::Message(m) => {
            if m.contains("cannot find agreement") || m.contains("connect") {
                ChainError::Network(m)
            } else {
                ChainError::Other(m)
            }
        }
        E::AlreadySubscribed(_) | E::NotSubscribed(_) | E::CouldntLockReader | E::Mpsc => {
            ChainError::Unavailable(err.to_string())
        }
        // Catch-all: future electrum-client variants stay clean ChainErrors
        // (never a silent Core/CBF fallback).
        other => ChainError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::BackendKind;

    #[test]
    fn server_url_plaintext_and_tls() {
        let plain = ElectrumConfig::new("example.org", 50001);
        assert_eq!(plain.server_url(), "tcp://example.org:50001");
        let tls = ElectrumConfig::new("example.org", 50002).with_tls(Some("ab".into()));
        assert_eq!(tls.server_url(), "ssl://example.org:50002");
        assert_eq!(tls.tls_pin.as_deref(), Some("ab"));
    }

    #[test]
    fn privacy_own_vs_third_party() {
        // connect() needs a live server — profile is pure config here via
        // a temporary backend-shaped check on config flags alone.
        assert!(ElectrumConfig::new("h", 1).own_server);
        assert!(!ElectrumConfig::new("h", 1).third_party().own_server);
        assert_eq!(
            PrivacyProfile::electrum_own_server().kind,
            BackendKind::ElectrumOwnServer
        );
        assert_eq!(
            PrivacyProfile::electrum_third_party().kind,
            BackendKind::ElectrumThirdParty
        );
        assert!(PrivacyProfile::electrum_third_party().requires_selection_warning);
        assert!(PrivacyProfile::electrum_own_server().reveals_full_wallet_graph);
    }

    #[test]
    fn config_rejects_tls_pin_without_tls() {
        let mut c = ElectrumConfig::new("127.0.0.1", 1);
        c.tls_pin = Some("deadbeef".into());
        c.use_tls = false;
        let err = ElectrumBackend::connect(c).unwrap_err();
        assert!(
            matches!(err, ChainError::Other(ref m) if m.contains("tls_pin")),
            "got {err:?}"
        );
    }

    #[test]
    fn config_rejects_empty_host_and_zero_gaps() {
        let c = ElectrumConfig::new("  ", 1);
        assert!(matches!(
            ElectrumBackend::connect(c),
            Err(ChainError::Other(_))
        ));
        let mut c = ElectrumConfig::new("h", 1);
        c.stop_gap = 0;
        assert!(matches!(
            ElectrumBackend::connect(c),
            Err(ChainError::Other(_))
        ));
        let mut c = ElectrumConfig::new("h", 1);
        c.batch_size = 0;
        assert!(matches!(
            ElectrumBackend::connect(c),
            Err(ChainError::Other(_))
        ));
    }

    #[test]
    fn btc_per_kb_conversion() {
        // 0.00001 BTC/kB = 1 sat/vB
        assert_eq!(btc_per_kb_to_sat_per_vb(0.00001), Some(1));
        // 0.0001 BTC/kB = 10 sat/vB
        assert_eq!(btc_per_kb_to_sat_per_vb(0.0001), Some(10));
        assert_eq!(btc_per_kb_to_sat_per_vb(-1.0), None);
        assert_eq!(btc_per_kb_to_sat_per_vb(f64::NAN), None);
    }

    /// S13: unreachable host/port → clean [`ChainError`], no Core/CBF fallback.
    #[test]
    fn s13_unreachable_port_returns_chain_error() {
        let mut c = ElectrumConfig::new("127.0.0.1", 1); // port 1: nothing listens
        c.timeout = Some(Duration::from_millis(400));
        c.retry = 0;
        let err = ElectrumBackend::connect(c).expect_err("must not connect");
        match err {
            ChainError::Network(_) | ChainError::Unavailable(_) | ChainError::Other(_) => {}
            other => panic!("expected clean ChainError, got {other:?}"),
        }
        // Explicit: error surface is only ChainError — no alternate transport.
        let _ = err.to_string();
    }

    /// S13: wrong host that does not resolve / is blackholed still errors cleanly.
    #[test]
    fn s13_unroutable_host_returns_chain_error() {
        // RFC 5737 documentation / TEST-NET-1: not routable on the public
        // Internet; connect should fail without hanging forever.
        let mut c = ElectrumConfig::new("192.0.2.1", 60401);
        c.timeout = Some(Duration::from_millis(500));
        c.retry = 0;
        let err = ElectrumBackend::connect(c).expect_err("must not connect");
        assert!(
            matches!(
                err,
                ChainError::Network(_) | ChainError::Unavailable(_) | ChainError::Other(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn socks5_builders_and_debug() {
        let p = Socks5Proxy::new("127.0.0.1:9050");
        assert_eq!(p.addr, "127.0.0.1:9050");
        // Both credential branches of `to_electrum`.
        let _ = p.to_electrum();
        let with_cred = Socks5Proxy {
            addr: "127.0.0.1:9050".into(),
            credentials: Some(("u".into(), "p".into())),
        };
        let _ = with_cred.to_electrum();
        let c = ElectrumConfig::regtest_electrs()
            .with_socks5(Socks5Proxy::new("127.0.0.1:9050"))
            .own_server();
        assert!(c.socks5.is_some());
        assert!(c.own_server);
        // Debug of config must not panic.
        let _ = format!("{c:?}");
    }

    #[test]
    fn regtest_electrs_defaults() {
        let c = ElectrumConfig::regtest_electrs();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 60401);
        assert!(!c.use_tls);
        assert!(c.own_server);
        assert_eq!(c.server_url(), "tcp://127.0.0.1:60401");
    }

    #[test]
    fn map_error_variants_cover_surface() {
        let n = map_electrum_error(electrum_client::Error::Message(
            "cannot find agreement block with server".into(),
        ));
        assert!(matches!(n, ChainError::Network(_)));

        let other_msg =
            map_electrum_error(electrum_client::Error::Message("server says hi".into()));
        assert!(matches!(other_msg, ChainError::Other(_)));

        let p = map_electrum_error(electrum_client::Error::Protocol(serde_json::json!("x")));
        assert!(matches!(p, ChainError::Protocol(_)));

        let inv = map_electrum_error(electrum_client::Error::InvalidResponse(
            serde_json::json!({"a":1}),
        ));
        assert!(matches!(inv, ChainError::Protocol(_)));

        let miss = map_electrum_error(electrum_client::Error::MissingDomain);
        assert!(matches!(miss, ChainError::Network(_)));

        let dns = map_electrum_error(electrum_client::Error::InvalidDNSNameError("x".into()));
        assert!(matches!(dns, ChainError::Network(_)));

        let u = map_electrum_error(electrum_client::Error::CouldntLockReader);
        assert!(matches!(u, ChainError::Unavailable(_)));

        let mpsc = map_electrum_error(electrum_client::Error::Mpsc);
        assert!(matches!(mpsc, ChainError::Unavailable(_)));

        let all = map_electrum_error(electrum_client::Error::AllAttemptsErrored(vec![
            electrum_client::Error::Message("a".into()),
            electrum_client::Error::Message("b".into()),
        ]));
        assert!(matches!(all, ChainError::Network(_)));

        let b = map_broadcast_error(electrum_client::Error::Protocol(serde_json::json!(
            "reject"
        )));
        assert!(matches!(b, ChainError::Broadcast(_)));

        // Broadcast path still classifies IO-ish errors as network.
        let b_net = map_broadcast_error(electrum_client::Error::AllAttemptsErrored(vec![
            electrum_client::Error::Message("down".into()),
        ]));
        assert!(matches!(b_net, ChainError::Network(_)));

        assert_eq!(btc_per_kb_to_sat_per_vb(f64::INFINITY), None);
        assert_eq!(btc_per_kb_to_sat_per_vb(-0.5), None);
        // Overflow arm of the sat conversion (not representable as u64).
        assert_eq!(btc_per_kb_to_sat_per_vb(1e300), None);

        let io = map_electrum_error(electrum_client::Error::IOError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert!(matches!(io, ChainError::Network(_)));

        let shared = map_electrum_error(electrum_client::Error::SharedIOError(
            std::sync::Arc::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe")),
        ));
        assert!(matches!(shared, ChainError::Network(_)));

        let b_io = map_broadcast_error(electrum_client::Error::IOError(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )));
        assert!(matches!(b_io, ChainError::Network(_)));
    }

    #[test]
    fn third_party_privacy_on_connected_shape() {
        // Privacy is config-driven; prove the third-party branch on a live
        // connection only when electrs is up, else the flag alone.
        let mut c = ElectrumConfig::regtest_electrs().third_party();
        assert!(!c.own_server);
        c.timeout = Some(Duration::from_millis(300));
        c.retry = 0;
        // If electrs is not listening this is still a ChainError (S13), never a
        // silent Core/CBF switch.
        match ElectrumBackend::connect(c) {
            Ok(b) => {
                assert_eq!(b.privacy_profile().kind, BackendKind::ElectrumThirdParty);
                assert!(b.privacy_profile().requires_selection_warning);
                let _ = format!("{:?}", b);
                let _ = b.config().host.clone();
                let _ = b.client();
            }
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        ChainError::Network(_) | ChainError::Unavailable(_) | ChainError::Other(_)
                    ),
                    "got {e:?}"
                );
            }
        }
    }
}
