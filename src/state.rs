use openswap::{
    protocol::common_messages::Offer,
    taker::offers::{BanReason, MakerOfferCandidate, MakerProtocol, MakerState, UnavailableReason},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

#[derive(Serialize, Clone, Debug)]
pub struct ApiOutpoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct ApiFidelityBond {
    pub amount: u64,
    pub outpoint: ApiOutpoint,
    pub lock_time: u32,
    pub cert_hash: String,
    pub cert_sig: String,
}

/// Offer payload — populated only when the taker has successfully fetched
/// the maker's advertisement.
#[derive(Serialize, Clone, Debug)]
pub struct ApiOffer {
    /// Public maker label. Older offers deserialize with an empty name, which
    /// is exposed as `None` instead of an ambiguous empty string.
    pub name: Option<String>,
    pub base_fee: u64,
    pub amount_relative_fee_pct: f64,
    pub time_relative_fee_pct: f64,
    pub min_size: u64,
    pub max_size: u64,
    pub required_confirms: u32,
    pub minimum_locktime: u16,
    pub tweakable_point: String,
    pub fidelity_bond: ApiFidelityBond,
}

impl ApiOffer {
    pub fn from_openswap(offer: &Offer) -> Self {
        let bond = &offer.fidelity.bond;
        let outpoint = bond.outpoint();

        Self {
            name: optional_maker_name(&offer.name),
            base_fee: offer.base_fee,
            amount_relative_fee_pct: offer.amount_relative_fee_pct,
            time_relative_fee_pct: offer.time_relative_fee_pct,
            min_size: offer.min_size,
            max_size: offer.max_size,
            required_confirms: offer.required_confirms,
            minimum_locktime: offer.minimum_locktime,
            tweakable_point: offer.tweakable_point.to_string(),
            fidelity_bond: ApiFidelityBond {
                amount: bond.amount.to_sat(),
                outpoint: ApiOutpoint {
                    txid: outpoint.txid.to_string(),
                    vout: outpoint.vout,
                },
                lock_time: bond.lock_time.to_consensus_u32(),
                cert_hash: offer.fidelity.cert_hash.to_string(),
                cert_sig: hex::encode(offer.fidelity.cert_sig.serialize_der().as_ref()),
            },
        }
    }
}

fn optional_maker_name(name: &str) -> Option<String> {
    (!name.is_empty()).then(|| name.to_owned())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiMakerState {
    Good,
    Unavailable {
        reason: ApiUnavailableReason,
        since_ts: Option<u64>,
        last_attempt_ts: Option<u64>,
        attempts: u32,
    },
    Banned {
        reason: ApiBanReason,
        recorded_at_ts: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApiUnavailableReason {
    AwaitingOffer,
    NoOfferResponse,
    BondUnconfirmed,
    BondExpired,
    BondReorged,
    BondUnverified,
    UnpriceableOffer,
    LegacyStatus,
}

impl From<&UnavailableReason> for ApiUnavailableReason {
    fn from(reason: &UnavailableReason) -> Self {
        match reason {
            UnavailableReason::AwaitingOffer => Self::AwaitingOffer,
            UnavailableReason::NoOfferResponse => Self::NoOfferResponse,
            UnavailableReason::BondUnconfirmed => Self::BondUnconfirmed,
            UnavailableReason::BondExpired => Self::BondExpired,
            UnavailableReason::BondReorged => Self::BondReorged,
            UnavailableReason::BondUnverified => Self::BondUnverified,
            UnavailableReason::UnpriceableOffer => Self::UnpriceableOffer,
            UnavailableReason::LegacyStatus => Self::LegacyStatus,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApiBanReason {
    ProvenViolation,
    InvalidFidelityProof,
    FundingWithheld,
    LegacyProvenViolation,
}

impl From<&BanReason> for ApiBanReason {
    fn from(reason: &BanReason) -> Self {
        match reason {
            BanReason::ProvenViolation => Self::ProvenViolation,
            BanReason::InvalidFidelityProof => Self::InvalidFidelityProof,
            BanReason::FundingWithheld => Self::FundingWithheld,
            BanReason::LegacyProvenViolation => Self::LegacyProvenViolation,
        }
    }
}

impl From<&MakerState> for ApiMakerState {
    fn from(s: &MakerState) -> Self {
        match s {
            MakerState::Good => Self::Good,
            MakerState::Unavailable(unavailable) => Self::Unavailable {
                reason: (&unavailable.reason).into(),
                since_ts: unavailable.since_ts,
                last_attempt_ts: unavailable.last_attempt_ts,
                attempts: unavailable.attempts,
            },
            MakerState::Banned(ban) => Self::Banned {
                reason: (&ban.reason).into(),
                recorded_at_ts: ban.recorded_at_ts,
            },
        }
    }
}

fn protocol_label(p: &MakerProtocol) -> &'static str {
    match p {
        MakerProtocol::Legacy => "legacy",
        MakerProtocol::Taproot => "taproot",
        MakerProtocol::Unified => "unified",
    }
}

/// A maker known to the taker's offerbook — *whether or not* we have a
/// current offer for it. Unavailable and banned makers come through here too.
#[derive(Serialize, Clone, Debug)]
pub struct ApiMaker {
    pub address: String,
    pub state: ApiMakerState,
    pub protocol: Option<&'static str>,
    pub timestamp: u64,
    pub last_offer_update_ts: Option<u64>,
    pub next_offer_check_ts: Option<u64>,
    pub offer: Option<ApiOffer>,
}

impl ApiMaker {
    pub fn from_candidate(candidate: &MakerOfferCandidate, timestamp: u64) -> Self {
        Self {
            address: candidate.address.to_string(),
            state: (&candidate.state).into(),
            protocol: candidate.protocol.as_ref().map(protocol_label),
            timestamp,
            last_offer_update_ts: candidate.last_offer_update_ts,
            next_offer_check_ts: candidate.next_offer_check_ts,
            offer: candidate.offer.as_ref().map(ApiOffer::from_openswap),
        }
    }
}

#[derive(Default, Clone)]
pub struct MakerStore {
    pub makers: Vec<ApiMaker>,
    pub last_sync: Option<u64>,
}

pub type SharedStore = Arc<RwLock<MakerStore>>;

pub fn new_store() -> SharedStore {
    Arc::new(RwLock::new(MakerStore::default()))
}

#[cfg(test)]
mod tests {
    use super::optional_maker_name;

    #[test]
    fn legacy_empty_maker_name_becomes_none() {
        assert_eq!(optional_maker_name(""), None);
        assert_eq!(optional_maker_name("Alice"), Some("Alice".to_owned()));
    }
}
