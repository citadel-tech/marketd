use anyhow::Result;
use serde::{Deserialize, Serialize};
use socks::Socks5Stream;
use std::fs;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Serialize, Deserialize)]
enum DnsRequest {
    Get,
}

#[derive(Serialize, Deserialize)]
struct TakerHello {
    protocol_version_min: u32,
    protocol_version_max: u32,
}

#[derive(Serialize, Deserialize)]
struct GiveOffer;

#[derive(Serialize, Deserialize)]
enum TakerToMakerMessage {
    TakerHello(TakerHello),
    ReqGiveOffer(GiveOffer),
}

#[derive(Serialize, Deserialize)]
enum MakerToTakerMessage {
    MakerHello(MakerHello),
    RespOffer(Box<Offer>),
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize)]
struct MakerHello {
    protocol_version_min: u32,
    protocol_version_max: u32,
}

mod txid_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_cbor::Value;

    pub fn serialize<S: Serializer>(data: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(data)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Text(s) => Ok(s),
            Value::Bytes(bytes) => Ok(hex::encode(bytes)),
            _ => Err(serde::de::Error::custom("expected string or bytes")),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct OutPoint {
    #[serde(with = "txid_serde")]
    txid: String,
    vout: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct FidelityBond {
    outpoint: OutPoint,
    amount: u64,
    lock_time: u32,
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
    conf_height: u32,
    cert_expiry: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct FidelityProof {
    bond: FidelityBond,
    #[serde(with = "serde_bytes")]
    cert_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    cert_sig: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Offer {
    base_fee: u64,
    amount_relative_fee_pct: f64,
    time_relative_fee_pct: f64,
    min_size: u64,
    max_size: u64,
    required_confirms: u32,
    minimum_locktime: u16,
    fidelity: FidelityProof,
    #[serde(with = "serde_bytes")]
    tweakable_point: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MakerAddress {
    onion_addr: String,
    port: String,
}

impl std::fmt::Display for MakerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.onion_addr, self.port)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct OfferAndAddress {
    offer: Offer,
    address: MakerAddress,
    timestamp: u64,
}

fn send_msg<T: Serialize>(s: &mut impl Write, msg: &T) -> Result<()> {
    let b = serde_cbor::to_vec(msg)?;
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)?;
    s.flush()?;
    Ok(())
}

fn read_msg(s: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let mut buf = vec![0; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn handshake(s: &mut (impl Read + Write)) -> Result<()> {
    send_msg(
        s,
        &TakerToMakerMessage::TakerHello(TakerHello {
            protocol_version_min: 1,
            protocol_version_max: 1,
        }),
    )?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&read_msg(s)?)?;
    if let MakerToTakerMessage::MakerHello(_) = msg {
        Ok(())
    } else {
        anyhow::bail!("Bad handshake")
    }
}

fn fetch_dns() -> Result<Vec<MakerAddress>> {
    for i in 0..3 {
        let target_addr = "kizqnaslcb2r3mbk2vm77bdff3madcvddntmaaz2htmkyuw7sgh4ddqd.onion:8080";
        println!("Fetching DNS {target_addr}... Try {i}");
        if let Ok(socks_conn) = Socks5Stream::connect("127.0.0.1:9050", target_addr) {
            let mut s = socks_conn.into_inner();
            send_msg(&mut s, &DnsRequest::Get)?;
            let resp: String = serde_cbor::from_slice(&read_msg(&mut s)?)?;
            let addrs: Vec<MakerAddress> = resp
                .lines()
                .filter_map(|line| {
                    line.split_once(':').map(|(addr, port)| MakerAddress {
                        onion_addr: addr.to_string(),
                        port: port.to_string(),
                    })
                })
                .collect();
            return Ok(addrs);
        }
        thread::sleep(Duration::from_secs(5));
    }
    anyhow::bail!("DNS failed")
}

fn get_offer(addr: &MakerAddress) -> Result<OfferAndAddress> {
    let addr_str = addr.to_string();
    println!("Downloading offer from {addr_str}");
    let socks_conn = Socks5Stream::connect("127.0.0.1:9050", addr_str.as_str())?;
    let mut s = socks_conn.into_inner();
    handshake(&mut s)?;
    send_msg(&mut s, &TakerToMakerMessage::ReqGiveOffer(GiveOffer))?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&read_msg(&mut s)?)?;
    if let MakerToTakerMessage::RespOffer(offer) = msg {
        Ok(OfferAndAddress {
            offer: *offer,
            address: addr.clone(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
        })
    } else {
        anyhow::bail!("Bad offer")
    }
}

fn get_all_offers(addrs: &[MakerAddress]) -> Vec<OfferAndAddress> {
    let (tx, rx) = mpsc::channel();
    for addr in addrs {
        let tx = tx.clone();
        let addr = addr.clone();
        thread::spawn(move || {
            let _ = tx.send(get_offer(&addr).ok());
        });
    }
    drop(tx);
    rx.iter().flatten().collect()
}

fn main() -> Result<()> {
    println!("Starting...");
    loop {
        if let Ok(addrs) = fetch_dns() {
            let offers = get_all_offers(&addrs);
            if !offers.is_empty() {
                let json: Vec<serde_json::Value> = offers
                    .iter()
                    .map(|o| {
                        serde_json::json!({
                            "address": o.address.to_string(),
                            "timestamp": o.timestamp,
                            "base_fee": o.offer.base_fee,
                            "amount_relative_fee_pct": o.offer.amount_relative_fee_pct,
                            "time_relative_fee_pct": o.offer.time_relative_fee_pct,
                            "min_size": o.offer.min_size,
                            "max_size": o.offer.max_size,
                            "required_confirms": o.offer.required_confirms,
                            "minimum_locktime": o.offer.minimum_locktime,
                            "fidelity_bond": {
                                "amount": o.offer.fidelity.bond.amount,
                                "outpoint": {
                                    "txid": o.offer.fidelity.bond.outpoint.txid,
                                    "vout": o.offer.fidelity.bond.outpoint.vout
                                },
                                "lock_time": o.offer.fidelity.bond.lock_time,
                                "conf_height": o.offer.fidelity.bond.conf_height,
                                "cert_expiry": o.offer.fidelity.bond.cert_expiry
                            },
                            "tweakable_point": hex::encode(&o.offer.tweakable_point)
                        })
                    })
                    .collect();
                fs::write(
                    "../web/offer_data.json",
                    serde_json::to_string_pretty(&json)?,
                )?;
                println!("Updated with {} offers", offers.len());
            }
        }
        thread::sleep(Duration::from_secs(2 * 60));
    }
}
