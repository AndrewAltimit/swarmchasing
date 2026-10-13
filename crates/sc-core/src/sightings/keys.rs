//! The keyed hash behind a sighting's linking features, and the published
//! per-epoch keys it uses.
//!
//! An epoch is a calendar quarter in UTC (`2026Q4`). Every epoch has one
//! random key, published here no later than the epoch starts, so two
//! operators who saw the same swarm in the same quarter hash its tags alike
//! and their sightings match. The key is public: it stops a sighting being
//! read against a plain or unkeyed lookup table, and makes a guesser start
//! again each quarter, but anyone holding it can test a guessed value
//! (SC-Sightings v1, "What the keyed hash protects").

use sha2::{Digest, Sha256};

/// Domain separation for every keyed hash: a sighting's hash never equals
/// one computed for another purpose under the same key.
const DOMAIN: &str = "sc-sightings-v1";

/// Hex digits of a feature hash (128 bits).
pub const HASH_HEX: usize = 32;

/// The published epoch keys, oldest first: (epoch, 32 random bytes as hex).
/// A new epoch's key is added no later than the day the epoch starts; a key
/// is never changed or removed, so old sightings stay comparable.
pub const EPOCH_KEYS: &[(&str, &str)] = &[
    (
        "2026Q2",
        "520818c69d967887dbff82ba94e1eb9c25114e888967d687cec99be93dafdb14",
    ),
    (
        "2026Q3",
        "e6792197337db127e10ba5c0d7d3521d992a1b9e786edce6fcf766ced70a84a4",
    ),
    (
        "2026Q4",
        "5f2f0a5a7a81b397b0b524073b88ad05bab7e89e8fc11a372b6a100a66f24a08",
    ),
    (
        "2027Q1",
        "ffa476617302f7cd1e3920db85dfae18c2959d1ad1232695b3a7f3d0b54faf9b",
    ),
];

/// The epoch keys a sighting is made or matched with: the published table,
/// or another for tests and for a group running its own exchange.
#[derive(Debug, Clone)]
pub struct EpochKeys {
    keys: Vec<(String, Vec<u8>)>,
}

impl Default for EpochKeys {
    fn default() -> Self {
        Self::from_pairs(EPOCH_KEYS.iter().copied()).expect("the published epoch keys are valid")
    }
}

impl EpochKeys {
    /// Keys from (epoch, hex) pairs. Fails on a malformed epoch or key.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, String> {
        let mut keys = Vec::new();
        for (epoch, hex) in pairs {
            if !valid_epoch(epoch) {
                return Err(format!("epoch `{epoch}` is not `<year>Q<1-4>`"));
            }
            let key = unhex(hex)
                .filter(|k| k.len() >= 16)
                .ok_or_else(|| format!("epoch {epoch}: the key is not at least 16 bytes of hex"))?;
            keys.push((epoch.to_string(), key));
        }
        Ok(Self { keys })
    }

    /// The key of `epoch`, when one is published.
    pub fn get(&self, epoch: &str) -> Option<&[u8]> {
        self.keys
            .iter()
            .find(|(e, _)| e == epoch)
            .map(|(_, k)| k.as_slice())
    }

    /// The keyed hash of one feature under `epoch`'s key: 32 hex digits of
    /// HMAC-SHA256 over `sc-sightings-v1`, the kind, the name and the value,
    /// separated by NUL. `None` when the epoch has no key.
    pub fn hash(&self, epoch: &str, kind: &str, name: &str, value: &str) -> Option<String> {
        let key = self.get(epoch)?;
        let msg = [DOMAIN, kind, name, value].join("\0");
        let mac = hmac_sha256(key, msg.as_bytes());
        Some(hex(&mac[..HASH_HEX / 2]))
    }
}

/// The epoch (calendar quarter, UTC) of unix time `ts`; `None` for an
/// unknown time.
pub fn epoch_of(ts: i64) -> Option<String> {
    use chrono::Datelike;
    if ts <= 0 {
        return None;
    }
    let d = chrono::DateTime::from_timestamp(ts, 0)?;
    Some(format!("{}Q{}", d.year(), d.month0() / 3 + 1))
}

/// `<year>Q<1-4>`.
pub fn valid_epoch(s: &str) -> bool {
    match s.split_once('Q') {
        Some((y, q)) => {
            y.len() == 4
                && y.bytes().all(|b| b.is_ascii_digit())
                && matches!(q, "1" | "2" | "3" | "4")
        }
        None => false,
    }
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad = block.map(|b| b ^ 0x36);
    let opad = block.map(|b| b ^ 0x5c);
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231() {
        // Test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block is hashed first.
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn epochs_are_utc_quarters() {
        assert_eq!(epoch_of(1791101400).as_deref(), Some("2026Q4")); // 2026-10-04
        assert_eq!(epoch_of(1782863999).as_deref(), Some("2026Q2")); // 2026-06-30 23:59:59
        assert_eq!(epoch_of(1782864000).as_deref(), Some("2026Q3")); // 2026-07-01
        assert_eq!(epoch_of(0), None);
        assert!(valid_epoch("2026Q4") && !valid_epoch("2026Q5") && !valid_epoch("26Q1"));
    }

    #[test]
    fn the_published_keys_load_and_differ() {
        let k = EpochKeys::default();
        let mut seen = std::collections::BTreeSet::new();
        for (e, _) in EPOCH_KEYS {
            assert_eq!(k.get(e).map(<[u8]>::len), Some(32), "{e}");
            assert!(seen.insert(k.get(e).unwrap().to_vec()), "{e} repeats a key");
        }
        assert!(EpochKeys::from_pairs([("2026Q4", "abcd")]).is_err());
        assert!(EpochKeys::from_pairs([("2026-10", &"00".repeat(32)[..])]).is_err());
    }
}
