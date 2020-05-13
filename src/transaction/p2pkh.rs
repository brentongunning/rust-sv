//! Pay-to-public-key-hash transaction scripts

use crate::script::op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSH};
use crate::script::{next_op, Script};
use crate::util::{Error, Hash160, Result};

/// Creates the pubkey script to send to an address
pub fn create_lock_script(address: &Hash160) -> Script {
    let mut script = Script::new();
    script.append(OP_DUP);
    script.append(OP_HASH160);
    script.append_data(&address.0);
    script.append(OP_EQUALVERIFY);
    script.append(OP_CHECKSIG);
    script
}

/// Creates a sigscript to sign a p2pkh transaction
pub fn create_unlock_script(sig: &[u8], public_key: &[u8; 33]) -> Script {
    let mut unlock_script = Script::new();
    unlock_script.append_data(sig);
    unlock_script.append_data(public_key);
    unlock_script
}

/// Returns whether the lock_script is p2pkh
pub fn check_lock_script(lock_script: &[u8]) -> bool {
    lock_script.len() == 25
        && lock_script[0] == OP_DUP
        && lock_script[1] == OP_HASH160
        && lock_script[2] == OP_PUSH + 20
        && lock_script[23] == OP_EQUALVERIFY
        && lock_script[24] == OP_CHECKSIG
}

/// Returns whether the unlock_script is p2pkh
pub fn check_unlock_script(unlock_script: &[u8]) -> bool {
    if unlock_script.len() == 0
        || unlock_script[0] < OP_PUSH + 71
        || unlock_script[0] > OP_PUSH + 73
    {
        return false;
    }
    let i = next_op(0, &unlock_script);
    if i >= unlock_script.len()
        || unlock_script[i] != OP_PUSH + 33 && unlock_script[i] != OP_PUSH + 65
    {
        return false;
    }
    next_op(i, &unlock_script) >= unlock_script.len()
}

/// Returns whether the lock_script is a P2PKH send to the provided address
pub fn check_lock_script_addr(hash160: &Hash160, lock_script: &[u8]) -> bool {
    check_lock_script(lock_script) && lock_script[3..23] == hash160.0
}

/// Returns whether the unlock_script contains our public key
pub fn check_unlock_script_addr(pubkey: &[u8], unlock_script: &[u8]) -> bool {
    if !check_unlock_script(unlock_script) {
        return false;
    }
    let i = next_op(0, &unlock_script);
    unlock_script[i + 1..] == *pubkey
}

/// Returns the public key this unlock_script was sent from
pub fn extract_pubkey(unlock_script: &[u8]) -> Result<Vec<u8>> {
    if !check_unlock_script(unlock_script) {
        let msg = "Script is not a sigscript for P2PKH".to_string();
        return Err(Error::BadData(msg));
    }
    let i = next_op(0, &unlock_script);
    Ok(unlock_script[i + 1..].to_vec())
}

/// Returns the address this lock_script sends to
pub fn extract_pubkeyhash(lock_script: &[u8]) -> Result<Hash160> {
    if check_lock_script(lock_script) {
        let mut hash160 = Hash160([0; 20]);
        hash160.0.clone_from_slice(&lock_script[3..23]);
        return Ok(hash160);
    } else {
        return Err(Error::BadData("Script is not a standard P2PKH".to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::op_codes::OP_1;

    #[test]
    fn check_lock_script_test() {
        let mut s = Script::new();
        assert!(!check_lock_script(&s.0));
        s.append(OP_DUP);
        s.append(OP_HASH160);
        s.append_data(&Hash160([1; 20]).0);
        s.append(OP_EQUALVERIFY);
        s.append(OP_CHECKSIG);
        assert!(check_lock_script(&s.0));
        s.append(OP_1);
        assert!(!check_lock_script(&s.0));
    }

    #[test]
    fn check_unlock_script_test() {
        assert!(!check_unlock_script(&Script::new().0));

        let mut sig71pkh33 = Script::new();
        sig71pkh33.append_data(&[0; 71]);
        assert!(!check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append_data(&[0; 33]);
        assert!(check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append(OP_1);
        assert!(!check_unlock_script(&sig71pkh33.0));

        let mut sig73pkh65 = Script::new();
        sig73pkh65.append_data(&[0; 73]);
        sig73pkh65.append_data(&[0; 65]);
        assert!(check_unlock_script(&sig73pkh65.0));

        let mut sig72pkh30 = Script::new();
        sig72pkh30.append_data(&[0; 72]);
        sig72pkh30.append_data(&[0; 30]);
        assert!(!check_unlock_script(&sig72pkh30.0));
    }

    #[test]
    fn check_lock_script_addr_test() {
        let s = create_lock_script(&Hash160([5; 20]));
        assert!(check_lock_script_addr(&Hash160([5; 20]), &s.0));
    }

    #[test]
    fn check_unlock_script_addr_test() {
        let mut s = Script::new();
        s.append_data(&[5; 71]);
        s.append_data(&[6; 65]);
        assert!(check_unlock_script_addr(&[6; 65], &s.0));
        assert!(!check_unlock_script_addr(&[7; 65], &s.0));
    }
}
