//! Diagnostic tool: reports whether an Estonian ID card is currently
//! connected, using the actual PKCS#11 module and reader on this machine.
//!
//! Run with:
//!   cargo run -p esteid-cryptoki --example detect_card

use esteid_cryptoki::{modules, EstEidError, IdCard};

fn main() {
    println!("Scanning for connected Estonian ID cards...\n");

    match resolve_module() {
        Some(path) => println!("Using PKCS#11 module: {}\n", path.display()),
        None => println!("Warning: no OpenSC PKCS#11 module found at any known path."),
    }

    match IdCard::find() {
        Ok(card) => print_card(&card),
        Err(EstEidError::NoCard) => {
            println!(
                "No Estonian ID card detected.\n  Make sure a card is inserted into the reader."
            );
        }
        Err(EstEidError::IncompleteCard(missing)) => {
            println!("A token was found, but it is missing {missing}.");
        }
        Err(EstEidError::MultipleCards(cards)) => {
            println!("Multiple Estonian ID cards detected; pin one by slot id:");
            for card in cards {
                println!("  - {card}");
            }
        }
        Err(EstEidError::Token(source)) => {
            println!("Failed to talk to the PKCS#11 module: {source}");
        }
    }
}

fn resolve_module() -> Option<std::path::PathBuf> {
    modules()
        .into_iter()
        .find_map(|spec| spec.paths.into_iter().find(|p| p.exists()))
}

fn print_card(card: &IdCard) {
    println!("Detected ID card {}", card.document_number());
    println!("  Auth token: {}", card.auth.token_label);
    println!("  Sign token: {}", card.sign.token_label);
    match card.auth.algorithm() {
        Ok(alg) => println!("  Algorithm : {alg:?}"),
        Err(e) => println!("  Algorithm : unknown ({e})"),
    }
}
