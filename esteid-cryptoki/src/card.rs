use std::collections::BTreeMap;
use std::path::PathBuf;

use tokenkey::{DiscoveredKey, Discovery, KeyClass, TokenKey, discover};

use crate::EstEidError;
use crate::error::Result;
use crate::filter::{is_esteid_issued, modules};

/// An Estonian ID card.
pub struct IdCard {
    /// The Authentication key (PIN1).
    pub auth: DiscoveredKey,
    /// The Signing key (PIN2).
    pub sign: DiscoveredKey,
}

impl IdCard {
    /// All connected Estonian ID cards.
    pub fn list() -> Result<Vec<IdCard>> {
        Ok(cards_from_pairs(pair_cards(discover_keys()?)))
    }

    /// Find the connected ID card. Errors unless exactly one card is connected and both its keys are found.
    pub fn find() -> Result<IdCard> {
        find_from_pairs(pair_cards(discover_keys()?))
    }

    /// The card's document number.
    pub fn document_number(&self) -> &str {
        &self.auth.token_serial
    }

    /// DER of the Authentication certificate.
    pub fn auth_certificate_der(&self) -> &[u8] {
        &self.auth.cert_der
    }

    /// DER of the Signing certificate.
    pub fn signing_certificate_der(&self) -> &[u8] {
        &self.sign.cert_der
    }

    /// Open the Authentication key. Requires PIN1.
    pub fn open_auth(&self, pin1: &str) -> Result<TokenKey> {
        Ok(TokenKey::open_discovered(&self.auth, pin1)?)
    }

    /// Open the Signing key for qualified signing.
    /// Requires PIN2.
    pub fn open_signing(&self, pin2: &str) -> Result<TokenKey> {
        Ok(TokenKey::open_discovered(&self.sign, pin2)?)
    }
}

enum CardOutcome {
    /// Both key types present.
    Complete(Box<IdCard>),
    /// Only one key type present.
    Incomplete {
        token_label: String,
        token_serial: String,
        missing: &'static str,
    },
}

fn discover_keys() -> Result<Vec<DiscoveredKey>> {
    let Discovery { keys, skipped } = discover(&modules());
    if keys.is_empty()
        && let Some(module) = skipped.into_iter().next()
    {
        return Err(module.error.into());
    }
    Ok(keys)
}

fn pair_cards(keys: Vec<DiscoveredKey>) -> Vec<CardOutcome> {
    // OpenSC exposes a card's auth and signing keys as separate slots.
    // We can group by serial since the serial is the same for both.
    let mut groups: BTreeMap<(PathBuf, String), (Option<DiscoveredKey>, Option<DiscoveredKey>)> =
        BTreeMap::new();

    for key in keys {
        if !matches!(key.usage, KeyClass::Authentication | KeyClass::Signing) {
            continue;
        }
        if !is_esteid_issued(&key.cert_der) {
            continue;
        }
        let token = (key.module.clone(), key.token_serial.clone());
        let entry = groups.entry(token).or_insert((None, None));
        match key.usage {
            KeyClass::Authentication => entry.0 = Some(key),
            KeyClass::Signing => entry.1 = Some(key),
            KeyClass::Other => unreachable!("filtered above"),
        }
    }

    groups
        .into_values()
        .map(|(auth, signing)| match (auth, signing) {
            (Some(auth), Some(signing)) => CardOutcome::Complete(Box::new(IdCard {
                auth,
                sign: signing,
            })),
            (Some(auth), None) => CardOutcome::Incomplete {
                token_label: auth.token_label,
                token_serial: auth.token_serial,
                missing: "a signing certificate",
            },
            (None, Some(signing)) => CardOutcome::Incomplete {
                token_label: signing.token_label,
                token_serial: signing.token_serial,
                missing: "an authentication certificate",
            },
            (None, None) => unreachable!("a group is only created when a key is inserted"),
        })
        .collect()
}

fn cards_from_pairs(outcomes: Vec<CardOutcome>) -> Vec<IdCard> {
    outcomes
        .into_iter()
        .filter_map(|outcome| match outcome {
            CardOutcome::Complete(card) => Some(*card),
            CardOutcome::Incomplete { .. } => None,
        })
        .collect()
}

fn find_from_pairs(outcomes: Vec<CardOutcome>) -> Result<IdCard> {
    let mut complete = Vec::new();
    let mut incomplete = Vec::new();
    for outcome in outcomes {
        match outcome {
            CardOutcome::Complete(card) => complete.push(*card),
            CardOutcome::Incomplete {
                token_label,
                token_serial,
                missing,
            } => incomplete.push((token_label, token_serial, missing)),
        }
    }

    match (complete.len(), incomplete.len()) {
        (0, 0) => Err(EstEidError::NoCard),
        (1, 0) => Ok(complete.into_iter().next().expect("len checked above")),
        (0, 1) => {
            let (_, _, missing) = incomplete.into_iter().next().expect("len checked above");
            Err(EstEidError::IncompleteCard(missing.to_string()))
        }
        _ => {
            let mut seen: Vec<String> = complete
                .iter()
                .map(|card| describe(&card.auth.token_label, &card.auth.token_serial))
                .collect();
            seen.extend(
                incomplete
                    .into_iter()
                    .map(|(label, serial, _)| describe(&label, &serial)),
            );
            Err(EstEidError::MultipleCards(seen))
        }
    }
}

fn describe(token_label: &str, token_serial: &str) -> String {
    format!("{token_label} ({token_serial})")
}
