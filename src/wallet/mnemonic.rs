//! Functions to convert data to and from mnemonic words

use crate::util::{Bits, Error, Result};
use ring::digest::{digest, SHA256};
use std::str;

/// Wordlist language
pub enum Wordlist {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

/// Loads the word list for a given language
pub fn load_wordlist(wordlist: Wordlist) -> Vec<String> {
    match wordlist {
        Wordlist::ChineseSimplified => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_simplified.txt"))
        }
        Wordlist::ChineseTraditional => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_traditional.txt"))
        }
        Wordlist::English => load_wordlist_internal(include_bytes!("wordlists/english.txt")),
        Wordlist::French => load_wordlist_internal(include_bytes!("wordlists/french.txt")),
        Wordlist::Italian => load_wordlist_internal(include_bytes!("wordlists/italian.txt")),
        Wordlist::Japanese => load_wordlist_internal(include_bytes!("wordlists/japanese.txt")),
        Wordlist::Korean => load_wordlist_internal(include_bytes!("wordlists/korean.txt")),
        Wordlist::Spanish => load_wordlist_internal(include_bytes!("wordlists/spanish.txt")),
    }
}

fn load_wordlist_internal(bytes: &[u8]) -> Vec<String> {
    let text: String = str::from_utf8(bytes).unwrap().to_string();
    text.lines().map(|s| s.to_string()).collect()
}

/// Encodes data into a mnemonic using BIP-39
pub fn mnemonic_encode(data: &[u8], word_list: &[String]) -> Vec<String> {
    let hash = digest(&SHA256, &data);
    let mut words = Vec::with_capacity((data.len() * 8 + data.len() / 32 + 10) / 11);
    let mut bits = Bits::from_slice(data, data.len() * 8);
    bits.append(&Bits::from_slice(hash.as_ref(), data.len() / 4));
    for i in 0..bits.len / 11 {
        words.push(word_list[bits.extract(i * 11, 11) as usize].clone());
    }
    let rem = bits.len % 11;
    if rem != 0 {
        let n = bits.extract(bits.len / 11 * 11, rem) << (8 - rem);
        words.push(word_list[n as usize].clone());
    }
    words
}

/// Decodes a neumonic into data using BIP-39
pub fn mnemonic_decode(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>> {
    let mut bits = Bits::with_capacity(mnemonic.len() * 11);
    for word in mnemonic {
        let value = match word_list.binary_search(word) {
            Ok(value) => value,
            Err(_) => return Err(Error::BadArgument(format!("Bad word: {}", word))),
        };
        let word_bits = Bits::from_slice(&[(value >> 3) as u8, ((value & 7) as u8) << 5], 11);
        bits.append(&word_bits);
    }
    let data_len = bits.len * 32 / 33;
    let cs_len = bits.len / 33;
    let cs = digest(&SHA256, &bits.data[0..data_len / 8]);
    let cs_bits = Bits::from_slice(cs.as_ref(), cs_len);
    if cs_bits.extract(0, cs_len) != bits.extract(data_len, cs_len) {
        return Err(Error::BadArgument("Invalid checksum".to_string()));
    }
    Ok(bits.data[0..data_len / 8].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn wordlists() {
        assert!(load_wordlist(Wordlist::ChineseSimplified).len() == 2048);
        assert!(load_wordlist(Wordlist::ChineseTraditional).len() == 2048);
        assert!(load_wordlist(Wordlist::English).len() == 2048);
        assert!(load_wordlist(Wordlist::French).len() == 2048);
        assert!(load_wordlist(Wordlist::Italian).len() == 2048);
        assert!(load_wordlist(Wordlist::Japanese).len() == 2048);
        assert!(load_wordlist(Wordlist::Korean).len() == 2048);
        assert!(load_wordlist(Wordlist::Spanish).len() == 2048);
    }

    #[test]
    fn encode_decode() {
        let mut data = Vec::new();
        for i in 0..16 {
            data.push(i);
        }
        let wordlist = load_wordlist(Wordlist::English);
        assert!(mnemonic_decode(&mnemonic_encode(&data, &wordlist), &wordlist).unwrap() == data);
    }

    #[test]
    fn invalid() {
        let wordlist = load_wordlist(Wordlist::English);
        assert!(mnemonic_encode(&[], &wordlist).len() == 0);
        assert!(mnemonic_decode(&[], &wordlist).unwrap().len() == 0);

        let mut data = Vec::new();
        for i in 0..16 {
            data.push(i);
        }
        let mnemonic = mnemonic_encode(&data, &wordlist);

        let mut bad_checksum = mnemonic.clone();
        bad_checksum[0] = "hello".to_string();
        assert!(mnemonic_decode(&bad_checksum, &wordlist).is_err());

        let mut bad_word = mnemonic.clone();
        bad_word[0] = "123".to_string();
        assert!(mnemonic_decode(&bad_word, &wordlist).is_err());
    }

    #[test]
    fn test_vectors() {
        let wordlist = load_wordlist(Wordlist::English);

        let h = hex::decode("00000000000000000000000000000000").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank yellow");

        let h = hex::decode("80808080808080808080808080808080").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(
            n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        );

        let h = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");

        let h = hex::decode("000000000000000000000000000000000000000000000000").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will");

        let h = hex::decode("808080808080808080808080808080808080808080808080").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always");

        let h = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when");

        let h = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");

        let h = hex::decode("8080808080808080808080808080808080808080808080808080808080808080")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");

        let h = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");

        let h = hex::decode("9e885d952ad362caeb4efe34a8e91bd2").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(
            n == "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
        );

        let h = hex::decode("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog");

        let h = hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");

        let h = hex::decode("c0ba5a8e914111210f2bd131f3d5e08d").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "scheme spot photo card baby mountain device kick cradle pact join borrow");

        let h = hex::decode("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave");

        let h = hex::decode("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");

        let h = hex::decode("23db8160a31d3e0dca3688ed941adbf3").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "cat swing flag economy stadium alone churn speed unique patch report train");

        let h = hex::decode("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access");

        let h = hex::decode("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform");

        let h = hex::decode("f30f8c1da665478f49b001d94c5fc452").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(
            n == "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        );

        let h = hex::decode("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05").unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump");

        let h = hex::decode("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")
            .unwrap();
        let n = mnemonic_encode(&h, &wordlist).join(" ");
        assert!(n == "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold");
    }
}
