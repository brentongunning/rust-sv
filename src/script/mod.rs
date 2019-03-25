//! Script opcodes and interpreter
//!
//! # Examples
//!
//! Evaluate a script that divides two numbers:
//!
//! ```rust
//! use sv::script::op_codes::*;
//! use sv::script::{Script, TransactionlessChecker};
//!
//! let mut script = Script::new();
//! script.append(OP_10);
//! script.append(OP_5);
//! script.append(OP_DIV);
//!
//! script.eval(&mut TransactionlessChecker {}).unwrap();
//! ```

use crate::script::op_codes::*;
use crate::util::Result;
use hex;
use std::fmt;

mod checker;
mod interpreter;
#[allow(dead_code)]
pub mod op_codes;
mod stack;

pub use self::checker::{Checker, TransactionChecker, TransactionlessChecker};
pub(crate) use self::interpreter::next_op;

/// Maximum number of bytes pushable to the stack
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of multisig keys
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum number of non-push operations per script
pub const MAX_OPS_PER_SCRIPT: usize = 500;

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10000;

/// Transaction script
#[derive(Default, Clone, PartialEq, Eq, Hash)]
pub struct Script(pub Vec<u8>);

impl Script {
    /// Creates a new empty script
    pub fn new() -> Script {
        Script(vec![])
    }

    /// Appends a single opcode or data byte
    pub fn append(&mut self, byte: u8) {
        self.0.push(byte);
    }

    /// Appends a slice of data
    pub fn append_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }

    /// Appends the opcodes and provided data that push it onto the stack
    pub fn append_data(&mut self, data: &[u8]) {
        let len = data.len();
        match len {
            0 => self.0.push(op_codes::OP_0),
            1...75 => {
                self.0.push(op_codes::OP_PUSH + len as u8);
                self.0.extend_from_slice(data);
            }
            76...255 => {
                self.0.push(op_codes::OP_PUSHDATA1);
                self.0.push(len as u8);
                self.0.extend_from_slice(data);
            }
            256...65535 => {
                self.0.push(op_codes::OP_PUSHDATA2);
                self.0.push((len >> 0) as u8);
                self.0.push((len >> 8) as u8);
                self.0.extend_from_slice(data);
            }
            _ => {
                self.0.push(op_codes::OP_PUSHDATA4);
                self.0.push((len >> 0) as u8);
                self.0.push((len >> 8) as u8);
                self.0.push((len >> 16) as u8);
                self.0.push((len >> 24) as u8);
                self.0.extend_from_slice(data);
            }
        }
    }

    /// Appends the opcodes to push a number to the stack
    ///
    /// The number must be in the range [2^-31+1,2^31-1].
    pub fn append_num(&mut self, n: i32) -> Result<()> {
        self.append_data(&stack::encode_num(n as i64)?);
        Ok(())
    }

    /// Evaluates a script using the provided checker
    pub fn eval<T: Checker>(&self, checker: &mut T) -> Result<()> {
        self::interpreter::eval(&self.0, checker)
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = &self.0;
        let mut ret = String::new();
        let mut i = 0;
        ret.push_str("[");
        while i < script.len() {
            if i != 0 {
                ret.push_str(" ")
            }
            match script[i] {
                OP_0 => ret.push_str("OP_0"),
                OP_1NEGATE => ret.push_str("OP_1NEGATE"),
                OP_1 => ret.push_str("OP_1"),
                OP_2 => ret.push_str("OP_2"),
                OP_3 => ret.push_str("OP_3"),
                OP_4 => ret.push_str("OP_4"),
                OP_5 => ret.push_str("OP_5"),
                OP_6 => ret.push_str("OP_6"),
                OP_7 => ret.push_str("OP_7"),
                OP_8 => ret.push_str("OP_8"),
                OP_9 => ret.push_str("OP_9"),
                OP_10 => ret.push_str("OP_10"),
                OP_11 => ret.push_str("OP_11"),
                OP_12 => ret.push_str("OP_12"),
                OP_13 => ret.push_str("OP_13"),
                OP_14 => ret.push_str("OP_14"),
                OP_15 => ret.push_str("OP_15"),
                OP_16 => ret.push_str("OP_16"),
                len @ 1...75 => {
                    ret.push_str(&format!("OP_PUSH+{} ", len));
                    if i + 1 + len as usize <= script.len() {
                        ret.push_str(&hex::encode(&script[i + 1..i + 1 + len as usize]));
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA1 => {
                    ret.push_str("OP_PUSHDATA1 ");
                    if i + 2 <= script.len() {
                        let len = script[i + 1] as usize;
                        ret.push_str(&format!("{} ", len));
                        if i + 2 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i + 2..i + 2 + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA2 => {
                    ret.push_str("OP_PUSHDATA2 ");
                    if i + 3 <= script.len() {
                        let len = ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8);
                        ret.push_str(&format!("{} ", len));
                        if i + 3 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i + 3..i + 3 + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA4 => {
                    ret.push_str("OP_PUSHDATA4 ");
                    if i + 5 <= script.len() {
                        let len = ((script[i + 1] as usize) << 0)
                            + ((script[i + 2] as usize) << 8)
                            + ((script[i + 3] as usize) << 16)
                            + ((script[i + 4] as usize) << 24);
                        ret.push_str(&format!("{} ", len));
                        if i + 5 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i..i + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_NOP => ret.push_str("OP_NOP"),
                OP_IF => ret.push_str("OP_IF"),
                OP_NOTIF => ret.push_str("OP_NOTIF"),
                OP_ELSE => ret.push_str("OP_ELSE"),
                OP_ENDIF => ret.push_str("OP_ENDIF"),
                OP_VERIFY => ret.push_str("OP_VERIFY"),
                OP_RETURN => ret.push_str("OP_RETURN"),
                OP_TOALTSTACK => ret.push_str("OP_TOALTSTACK"),
                OP_FROMALTSTACK => ret.push_str("OP_FROMALTSTACK"),
                OP_IFDUP => ret.push_str("OP_IFDUP"),
                OP_DEPTH => ret.push_str("OP_DEPTH"),
                OP_DROP => ret.push_str("OP_DROP"),
                OP_DUP => ret.push_str("OP_DUP"),
                OP_NIP => ret.push_str("OP_NIP"),
                OP_OVER => ret.push_str("OP_OVER"),
                OP_PICK => ret.push_str("OP_PICK"),
                OP_ROLL => ret.push_str("OP_ROLL"),
                OP_ROT => ret.push_str("OP_ROT"),
                OP_SWAP => ret.push_str("OP_SWAP"),
                OP_TUCK => ret.push_str("OP_TUCK"),
                OP_2DROP => ret.push_str("OP_2DROP"),
                OP_2DUP => ret.push_str("OP_2DUP"),
                OP_3DUP => ret.push_str("OP_3DUP"),
                OP_2OVER => ret.push_str("OP_2OVER"),
                OP_2ROT => ret.push_str("OP_2ROT"),
                OP_2SWAP => ret.push_str("OP_2SWAP"),
                OP_CAT => ret.push_str("OP_CAT"),
                OP_SPLIT => ret.push_str("OP_SPLIT"),
                OP_SIZE => ret.push_str("OP_SIZE"),
                OP_AND => ret.push_str("OP_AND"),
                OP_OR => ret.push_str("OP_OR"),
                OP_XOR => ret.push_str("OP_XOR"),
                OP_EQUAL => ret.push_str("OP_EQUAL"),
                OP_EQUALVERIFY => ret.push_str("OP_EQUALVERIFY"),
                OP_1ADD => ret.push_str("OP_1ADD"),
                OP_1SUB => ret.push_str("OP_1SUB"),
                OP_NEGATE => ret.push_str("OP_NEGATE"),
                OP_ABS => ret.push_str("OP_ABS"),
                OP_NOT => ret.push_str("OP_NOT"),
                OP_0NOTEQUAL => ret.push_str("OP_0NOTEQUAL"),
                OP_ADD => ret.push_str("OP_ADD"),
                OP_SUB => ret.push_str("OP_SUB"),
                OP_DIV => ret.push_str("OP_DIV"),
                OP_MOD => ret.push_str("OP_MOD"),
                OP_BOOLAND => ret.push_str("OP_BOOLAND"),
                OP_BOOLOR => ret.push_str("OP_BOOLOR"),
                OP_NUMEQUAL => ret.push_str("OP_NUMEQUAL"),
                OP_NUMEQUALVERIFY => ret.push_str("OP_NUMEQUALVERIFY"),
                OP_NUMNOTEQUAL => ret.push_str("OP_NUMNOTEQUAL"),
                OP_LESSTHAN => ret.push_str("OP_LESSTHAN"),
                OP_GREATERTHAN => ret.push_str("OP_GREATERTHAN"),
                OP_LESSTHANOREQUAL => ret.push_str("OP_LESSTHANOREQUAL"),
                OP_GREATERTHANOREQUAL => ret.push_str("OP_GREATERTHANOREQUAL"),
                OP_MIN => ret.push_str("OP_MIN"),
                OP_MAX => ret.push_str("OP_MAX"),
                OP_WITHIN => ret.push_str("OP_WITHIN"),
                OP_NUM2BIN => ret.push_str("OP_NUM2BIN"),
                OP_BIN2NUM => ret.push_str("OP_BIN2NUM"),
                OP_RIPEMD160 => ret.push_str("OP_RIPEMD160"),
                OP_SHA1 => ret.push_str("OP_SHA1"),
                OP_SHA256 => ret.push_str("OP_SHA256"),
                OP_HASH160 => ret.push_str("OP_HASH160"),
                OP_HASH256 => ret.push_str("OP_HASH256"),
                OP_CODESEPARATOR => ret.push_str("OP_CODESEPARATOR"),
                OP_CHECKSIG => ret.push_str("OP_CHECKSIG"),
                OP_CHECKSIGVERIFY => ret.push_str("OP_CHECKSIGVERIFY"),
                OP_CHECKMULTISIG => ret.push_str("OP_CHECKMULTISIG"),
                OP_CHECKMULTISIGVERIFY => ret.push_str("OP_CHECKMULTISIGVERIFY"),
                OP_CHECKLOCKTIMEVERIFY => ret.push_str("OP_CHECKLOCKTIMEVERIFY"),
                OP_CHECKSEQUENCEVERIFY => ret.push_str("OP_CHECKSEQUENCEVERIFY"),
                _ => ret.push_str(&format!("{}", script[i])),
            }
            i = next_op(i, script);
        }

        // Add whatever is remaining if we exited early
        if i < script.len() {
            for j in i..script.len() {
                ret.push_str(&format!(" {}", script[j]));
            }
        }
        ret.push_str("]");
        f.write_str(&ret)
    }
}

#[cfg(test)]
mod tests {
    use super::op_codes::*;
    use super::*;

    #[test]
    fn append_data() {
        let mut s = Script::new();
        s.append_data(&vec![]);
        assert!(s.0.len() == 1);

        let mut s = Script::new();
        s.append_data(&vec![0; 1]);
        assert!(s.0[0] == OP_PUSH + 1 && s.0.len() == 2);

        let mut s = Script::new();
        s.append_data(&vec![0; 75]);
        assert!(s.0[0] == OP_PUSH + 75 && s.0.len() == 76);

        let mut s = Script::new();
        s.append_data(&vec![0; 76]);
        assert!(s.0[0] == OP_PUSHDATA1 && s.0[1] == 76 && s.0.len() == 78);

        let mut s = Script::new();
        s.append_data(&vec![0; 255]);
        assert!(s.0[0] == OP_PUSHDATA1 && s.0[1] == 255 && s.0.len() == 257);

        let mut s = Script::new();
        s.append_data(&vec![0; 256]);
        assert!(s.0[0] == OP_PUSHDATA2 && s.0[1] == 0 && s.0[2] == 1 && s.0.len() == 259);

        let mut s = Script::new();
        s.append_data(&vec![0; 65535]);
        assert!(s.0[0] == OP_PUSHDATA2 && s.0[1] == 255 && s.0[2] == 255 && s.0.len() == 65538);

        let mut s = Script::new();
        s.append_data(&vec![0; 65536]);
        assert!(s.0[0] == OP_PUSHDATA4 && s.0[1] == 0 && s.0[2] == 0 && s.0[3] == 1);
        assert!(s.0.len() == 65541);
    }
}
