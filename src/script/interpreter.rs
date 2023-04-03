use crate::script::op_codes::*;
use crate::script::stack::{
    decode_bigint, decode_bool, encode_bigint, encode_num, pop_bigint, pop_bool, pop_num,
};
use crate::script::Checker;
use crate::transaction::sighash::SIGHASH_FORKID;
use crate::util::{hash160, lshift, rshift, sha256d, Error, Result};
use digest::{FixedOutput, Input};
use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ripemd160::{Digest, Ripemd160};

// Stack capacity defaults, which may exceeded
const STACK_CAPACITY: usize = 100;
const ALT_STACK_CAPACITY: usize = 10;

/// Execute the script with genesis rules
pub const NO_FLAGS: u32 = 0x00;

/// Flag to execute the script with pre-genesis rules
pub const PREGENESIS_RULES: u32 = 0x01;

/// Executes a script
pub fn eval<T: Checker>(script: &[u8], checker: &mut T, flags: u32) -> Result<()> {
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(STACK_CAPACITY);
    let mut alt_stack: Vec<Vec<u8>> = Vec::with_capacity(ALT_STACK_CAPACITY);
    // True if executing current if/else branch, false if next else
    let mut branch_exec: Vec<bool> = Vec::new();
    let mut check_index = 0;
    let mut i = 0;

    'outer: while i < script.len() {
        if branch_exec.len() > 0 && !branch_exec[branch_exec.len() - 1] {
            i = skip_branch(script, i);
            if i >= script.len() {
                break;
            }
        }

        match script[i] {
            OP_0 => stack.push(encode_num(0)?),
            OP_1NEGATE => stack.push(encode_num(-1)?),
            OP_1 => stack.push(encode_num(1)?),
            OP_2 => stack.push(encode_num(2)?),
            OP_3 => stack.push(encode_num(3)?),
            OP_4 => stack.push(encode_num(4)?),
            OP_5 => stack.push(encode_num(5)?),
            OP_6 => stack.push(encode_num(6)?),
            OP_7 => stack.push(encode_num(7)?),
            OP_8 => stack.push(encode_num(8)?),
            OP_9 => stack.push(encode_num(9)?),
            OP_10 => stack.push(encode_num(10)?),
            OP_11 => stack.push(encode_num(11)?),
            OP_12 => stack.push(encode_num(12)?),
            OP_13 => stack.push(encode_num(13)?),
            OP_14 => stack.push(encode_num(14)?),
            OP_15 => stack.push(encode_num(15)?),
            OP_16 => stack.push(encode_num(16)?),
            len @ 1..=75 => {
                remains(i + 1, len as usize, script)?;
                stack.push(script[i + 1..i + 1 + len as usize].to_vec());
            }
            OP_PUSHDATA1 => {
                remains(i + 1, 1, script)?;
                let len = script[i + 1] as usize;
                remains(i + 2, len, script)?;
                stack.push(script[i + 2..i + 2 + len].to_vec());
            }
            OP_PUSHDATA2 => {
                remains(i + 1, 2, script)?;
                let len = ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8);
                remains(i + 3, len, script)?;
                stack.push(script[i + 3..i + 3 + len].to_vec());
            }
            OP_PUSHDATA4 => {
                remains(i + 1, 4, script)?;
                let len = ((script[i + 1] as usize) << 0)
                    + ((script[i + 2] as usize) << 8)
                    + ((script[i + 3] as usize) << 16)
                    + ((script[i + 4] as usize) << 24);
                remains(i + 5, len, script)?;
                stack.push(script[i + 5..i + 5 + len].to_vec());
            }
            OP_NOP => {}
            OP_IF => branch_exec.push(pop_bool(&mut stack)?),
            OP_NOTIF => branch_exec.push(!pop_bool(&mut stack)?),
            OP_ELSE => {
                let len = branch_exec.len();
                if len == 0 {
                    let msg = "ELSE found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec[len - 1] = !branch_exec[len - 1];
            }
            OP_ENDIF => {
                if branch_exec.len() == 0 {
                    let msg = "ENDIF found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec.pop().unwrap();
            }
            OP_VERIFY => {
                if !pop_bool(&mut stack)? {
                    return Err(Error::ScriptError("OP_VERIFY failed".to_string()));
                }
            }
            OP_RETURN => {
                if flags & PREGENESIS_RULES == PREGENESIS_RULES {
                    return Err(Error::ScriptError("Hit OP_RETURN".to_string()));
                } else {
                    break 'outer;
                }
            }
            OP_TOALTSTACK => {
                check_stack_size(1, &stack)?;
                alt_stack.push(stack.pop().unwrap());
            }
            OP_FROMALTSTACK => {
                check_stack_size(1, &alt_stack)?;
                stack.push(alt_stack.pop().unwrap());
            }
            OP_IFDUP => {
                check_stack_size(1, &stack)?;
                if decode_bool(&stack[stack.len() - 1]) {
                    let copy = stack[stack.len() - 1].clone();
                    stack.push(copy);
                }
            }
            OP_DEPTH => {
                let depth = stack.len() as i64;
                stack.push(encode_num(depth)?);
            }
            OP_DROP => {
                check_stack_size(1, &stack)?;
                stack.pop().unwrap();
            }
            OP_DUP => {
                check_stack_size(1, &stack)?;
                let copy = stack[stack.len() - 1].clone();
                stack.push(copy);
            }
            OP_NIP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                stack.remove(index);
            }
            OP_OVER => {
                check_stack_size(2, &stack)?;
                let copy = stack[stack.len() - 2].clone();
                stack.push(copy);
            }
            OP_PICK => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_PICK failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let copy = stack[stack.len() - n as usize - 1].clone();
                stack.push(copy);
            }
            OP_ROLL => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_ROLL failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let index = stack.len() - n as usize - 1;
                let item = stack.remove(index);
                stack.push(item);
            }
            OP_ROT => {
                check_stack_size(3, &stack)?;
                let index = stack.len() - 3;
                let third = stack.remove(index);
                stack.push(third);
            }
            OP_SWAP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                let second = stack.remove(index);
                stack.push(second);
            }
            OP_TUCK => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                stack.insert(len - 2, top);
            }
            OP_2DROP => {
                check_stack_size(2, &stack)?;
                stack.pop().unwrap();
                stack.pop().unwrap();
            }
            OP_2DUP => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                stack.push(second);
                stack.push(top);
            }
            OP_3DUP => {
                check_stack_size(3, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                let third = stack[len - 3].clone();
                stack.push(third);
                stack.push(second);
                stack.push(top);
            }
            OP_2OVER => {
                check_stack_size(4, &stack)?;
                let len = stack.len();
                let third = stack[len - 3].clone();
                let fourth = stack[len - 4].clone();
                stack.push(fourth);
                stack.push(third);
            }
            OP_2ROT => {
                check_stack_size(6, &stack)?;
                let index = stack.len() - 6;
                let sixth = stack.remove(index);
                let fifth = stack.remove(index);
                stack.push(sixth);
                stack.push(fifth);
            }
            OP_2SWAP => {
                check_stack_size(4, &stack)?;
                let index = stack.len() - 4;
                let fourth = stack.remove(index);
                let third = stack.remove(index);
                stack.push(fourth);
                stack.push(third);
            }
            OP_CAT => {
                check_stack_size(2, &stack)?;
                let top = stack.pop().unwrap();
                let mut second = stack.pop().unwrap();
                second.extend_from_slice(&top);
                stack.push(second);
            }
            OP_SPLIT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let x = stack.pop().unwrap();
                if n < 0 {
                    let msg = "OP_SPLIT failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n > x.len() as i32 {
                    let msg = "OP_SPLIT failed, n out of range".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n == 0 {
                    stack.push(encode_num(0)?);
                    stack.push(x);
                } else if n as usize == x.len() {
                    stack.push(x);
                    stack.push(encode_num(0)?);
                } else {
                    stack.push(x[..n as usize].to_vec());
                    stack.push(x[n as usize..].to_vec());
                }
            }
            OP_SIZE => {
                check_stack_size(1, &stack)?;
                let len = stack[stack.len() - 1].len();
                stack.push(encode_num(len as i64)?);
            }
            OP_AND => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_AND failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] & b[i]);
                }
                stack.push(result);
            }
            OP_OR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_OR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] | b[i]);
                }
                stack.push(result);
            }
            OP_XOR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_XOR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] ^ b[i]);
                }
                stack.push(result);
            }
            OP_INVERT => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop().unwrap();
                for i in 0..v.len() {
                    v[i] = !v[i];
                }
                stack.push(v);
            }
            OP_LSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let v = stack.pop().unwrap();
                stack.push(lshift(&v, n as usize));
            }
            OP_RSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let v = stack.pop().unwrap();
                stack.push(rshift(&v, n as usize));
            }
            OP_EQUAL => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_EQUAL failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if a == b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_EQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_EQUALVERIFY failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if a != b {
                    let msg = "Operands are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_1ADD => {
                let mut x = pop_bigint(&mut stack)?;
                x += 1;
                stack.push(encode_bigint(x));
            }
            OP_1SUB => {
                let mut x = pop_bigint(&mut stack)?;
                x -= 1;
                stack.push(encode_bigint(x));
            }
            OP_NEGATE => {
                let mut x = pop_bigint(&mut stack)?;
                x = -x;
                stack.push(encode_bigint(x));
            }
            OP_ABS => {
                let mut x = pop_bigint(&mut stack)?;
                if x < BigInt::zero() {
                    x = -x;
                }
                stack.push(encode_bigint(x));
            }
            OP_NOT => {
                let mut x = pop_bigint(&mut stack)?;
                if x == BigInt::zero() {
                    x = BigInt::one();
                } else {
                    x = BigInt::zero();
                }
                stack.push(encode_bigint(x));
            }
            OP_0NOTEQUAL => {
                let mut x = pop_bigint(&mut stack)?;
                if x == BigInt::zero() {
                    x = BigInt::zero();
                } else {
                    x = BigInt::one();
                }
                stack.push(encode_bigint(x));
            }
            OP_ADD => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let sum = a + b;
                stack.push(encode_bigint(sum));
            }
            OP_SUB => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let difference = b - a;
                stack.push(encode_bigint(difference));
            }
            OP_MUL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let product = a * b;
                stack.push(encode_bigint(product));
            }
            OP_DIV => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_DIV failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let quotient = a / b;
                stack.push(encode_bigint(quotient));
            }
            OP_MOD => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_MOD failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let remainder = a % b;
                stack.push(encode_bigint(remainder));
            }
            OP_BOOLAND => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != BigInt::zero() && b != BigInt::zero() {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_BOOLOR => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != BigInt::zero() || b != BigInt::zero() {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUMEQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a == b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUMEQUALVERIFY => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != b {
                    let msg = "Numbers are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NUMNOTEQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_LESSTHAN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a < b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_GREATERTHAN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a > b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_LESSTHANOREQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a <= b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_GREATERTHANOREQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a >= b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_MIN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a < b {
                    stack.push(encode_bigint(a));
                } else {
                    stack.push(encode_bigint(b));
                }
            }
            OP_MAX => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a > b {
                    stack.push(encode_bigint(a));
                } else {
                    stack.push(encode_bigint(b));
                }
            }
            OP_WITHIN => {
                let max = pop_bigint(&mut stack)?;
                let min = pop_bigint(&mut stack)?;
                let x = pop_bigint(&mut stack)?;
                if x >= min && x < max {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUM2BIN => {
                check_stack_size(2, &stack)?;
                let m = pop_bigint(&mut stack)?;
                let mut n = stack.pop().unwrap();
                if m < BigInt::one() {
                    let msg = format!("OP_NUM2BIN failed. m too small: {}", m);
                    return Err(Error::ScriptError(msg));
                }
                let nlen = n.len();
                if m < BigInt::from(nlen) {
                    let msg = "OP_NUM2BIN failed. n longer than m".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if m > BigInt::from(2147483647) {
                    let msg = "OP_NUM2BIN failed. m too big".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut v = Vec::with_capacity(m.to_usize().unwrap());
                let mut neg = 0;
                if nlen > 0 {
                    neg = n[nlen - 1] & 128;
                    n[nlen - 1] &= 127;
                }
                for _ in n.len()..m.to_usize().unwrap() {
                    v.push(0);
                }
                for b in n.iter().rev() {
                    v.push(*b);
                }
                v[0] |= neg;
                stack.push(v);
            }
            OP_BIN2NUM => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop().unwrap();
                v.reverse();
                let n = decode_bigint(&mut v);
                let e = encode_bigint(n);
                stack.push(e);
            }
            OP_RIPEMD160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let mut ripemd160 = Ripemd160::new();
                ripemd160.process(v.as_ref());
                let result = ripemd160.fixed_result().to_vec();
                stack.push(result);
            }
            OP_SHA1 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = digest(&SHA1_FOR_LEGACY_USE_ONLY, &v);
                stack.push(result.as_ref().to_vec());
            }
            OP_SHA256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = digest(&SHA256, &v);
                stack.push(result.as_ref().to_vec());
            }
            OP_HASH160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let hash160 = hash160(&v).0;
                stack.push(hash160.to_vec());
            }
            OP_HASH256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = sha256d(&v).0;
                stack.push(result.as_ref().to_vec());
            }
            OP_CODESEPARATOR => {
                check_index = i + 1;
            }
            OP_CHECKSIG => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop().unwrap();
                let sig = stack.pop().unwrap();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                match checker.check_sig(&sig, &pubkey, &cleaned_script)? {
                    true => stack.push(encode_num(1)?),
                    false => stack.push(encode_num(0)?),
                }
            }
            OP_CHECKSIGVERIFY => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop().unwrap();
                let sig = stack.pop().unwrap();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                if !checker.check_sig(&sig, &pubkey, &cleaned_script)? {
                    return Err(Error::ScriptError("OP_CHECKSIGVERIFY failed".to_string()));
                }
            }
            OP_CHECKMULTISIG => {
                match check_multisig(&mut stack, checker, &script[check_index..])? {
                    true => stack.push(encode_num(1)?),
                    false => stack.push(encode_num(0)?),
                }
            }
            OP_CHECKMULTISIGVERIFY => {
                if !check_multisig(&mut stack, checker, &script[check_index..])? {
                    let msg = "OP_CHECKMULTISIGVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_CHECKLOCKTIMEVERIFY => {
                if flags & PREGENESIS_RULES == PREGENESIS_RULES {
                    let locktime = pop_num(&mut stack)?;
                    if !checker.check_locktime(locktime)? {
                        let msg = "OP_CHECKLOCKTIMEVERIFY failed".to_string();
                        return Err(Error::ScriptError(msg));
                    }
                }
            }
            OP_CHECKSEQUENCEVERIFY => {
                if flags & PREGENESIS_RULES == PREGENESIS_RULES {
                    let sequence = pop_num(&mut stack)?;
                    if !checker.check_sequence(sequence)? {
                        let msg = "OP_CHECKSEQUENCEVERIFY failed".to_string();
                        return Err(Error::ScriptError(msg));
                    }
                }
            }
            OP_NOP1 => {}
            OP_NOP4 => {}
            OP_NOP5 => {}
            OP_NOP6 => {}
            OP_NOP7 => {}
            OP_NOP8 => {}
            OP_NOP9 => {}
            OP_NOP10 => {}
            _ => {
                let msg = format!("Bad opcode: {}, index {}", script[i], i);
                return Err(Error::ScriptError(msg));
            }
        }

        i = next_op(i, script);
    }

    if branch_exec.len() != 0 {
        return Err(Error::ScriptError("ENDIF missing".to_string()));
    }
    // We don't call pop_bool here because the final stack element can be longer than 4 bytes
    check_stack_size(1, &stack)?;
    if !decode_bool(&stack[stack.len() - 1]) {
        return Err(Error::ScriptError("Top of stack is false".to_string()));
    }
    Ok(())
}

#[inline]
fn check_multisig<T: Checker>(
    stack: &mut Vec<Vec<u8>>,
    checker: &mut T,
    script: &[u8],
) -> Result<bool> {
    // Pop the keys
    let total = pop_num(stack)?;
    if total < 0 {
        return Err(Error::ScriptError("total out of range".to_string()));
    }
    check_stack_size(total as usize, &stack)?;
    let mut keys = Vec::with_capacity(total as usize);
    for _i in 0..total {
        keys.push(stack.pop().unwrap());
    }

    // Pop the sigs
    let required = pop_num(stack)?;
    if required < 0 || required > total {
        return Err(Error::ScriptError("required out of range".to_string()));
    }
    check_stack_size(required as usize, &stack)?;
    let mut sigs = Vec::with_capacity(required as usize);
    for _i in 0..required {
        sigs.push(stack.pop().unwrap());
    }

    // Pop one more off. This isn't used and can't be changed.
    check_stack_size(1, &stack)?;
    stack.pop().unwrap();

    // Remove signature for pre-fork scripts
    let mut cleaned_script = script.to_vec();
    for sig in sigs.iter() {
        if prefork(sig) {
            cleaned_script = remove_sig(sig, &cleaned_script);
        }
    }

    let mut key = 0;
    let mut sig = 0;
    while sig < sigs.len() {
        if key == keys.len() {
            return Ok(false);
        }
        if checker.check_sig(&sigs[sig], &keys[key], &cleaned_script)? {
            sig += 1;
        }
        key += 1;
    }
    Ok(true)
}

fn prefork(sig: &[u8]) -> bool {
    sig.len() > 0 && sig[sig.len() - 1] & SIGHASH_FORKID == 0
}

/// Removes any instances of the signature from the lock_script in pre-fork transactions
fn remove_sig<'a>(sig: &[u8], script: &[u8]) -> Vec<u8> {
    if sig.len() == 0 {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    let mut start = 0;
    while i + sig.len() <= script.len() {
        if script[i..i + sig.len()] == *sig {
            result.extend_from_slice(&script[start..i]);
            start = i + sig.len();
            i = start;
        } else {
            i = next_op(i, script);
        }
    }
    result.extend_from_slice(&script[start..]);
    result
}

#[inline]
fn check_stack_size(minsize: usize, stack: &Vec<Vec<u8>>) -> Result<()> {
    if stack.len() < minsize {
        let msg = format!("Stack too small: {}", minsize);
        return Err(Error::ScriptError(msg));
    }
    Ok(())
}

#[inline]
fn remains(i: usize, len: usize, script: &[u8]) -> Result<()> {
    if i + len > script.len() {
        Err(Error::ScriptError("Not enough data remaining".to_string()))
    } else {
        Ok(())
    }
}

/// Gets the next operation index in the script, or the script length if at the end
pub fn next_op(i: usize, script: &[u8]) -> usize {
    if i >= script.len() {
        return script.len();
    }
    let next = match script[i] {
        len @ 1..=75 => i + 1 + len as usize,
        OP_PUSHDATA1 => {
            if i + 2 > script.len() {
                return script.len();
            }
            i + 2 + script[i + 1] as usize
        }
        OP_PUSHDATA2 => {
            if i + 3 > script.len() {
                return script.len();
            }
            i + 3 + ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8)
        }
        OP_PUSHDATA4 => {
            if i + 5 > script.len() {
                return script.len();
            }
            let len = ((script[i + 1] as usize) << 0)
                + ((script[i + 2] as usize) << 8)
                + ((script[i + 3] as usize) << 16)
                + ((script[i + 4] as usize) << 24);
            i + 5 + len
        }
        _ => i + 1,
    };
    let overflow = next > script.len();
    return if overflow { script.len() } else { next };
}

/// Skips over a branch of if/else and return the index of the next else or endif opcode
fn skip_branch(script: &[u8], mut i: usize) -> usize {
    let mut sub = 0;
    while i < script.len() {
        match script[i] {
            OP_IF => sub += 1,
            OP_NOTIF => sub += 1,
            OP_ELSE => {
                if sub == 0 {
                    return i;
                }
            }
            OP_ENDIF => {
                if sub == 0 {
                    return i;
                }
                sub -= 1;
            }
            _ => {}
        }
        i = next_op(i, script);
    }
    script.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::Script;
    use hex;
    use std::cell::RefCell;

    #[test]
    fn valid() {
        pass(&[OP_TRUE]);
        pass(&[OP_16]);
        pass(&[OP_PUSH + 1, 1]);
        pass(&[OP_PUSHDATA1, 2, 0, 1]);
        pass(&[OP_PUSHDATA2, 2, 0, 0, 1]);
        pass(&[OP_PUSHDATA4, 2, 0, 0, 0, 0, 1]);
        pass(&[OP_NOP, OP_NOP, OP_NOP, OP_1]);
        pass(&[OP_1, OP_1, OP_IF, OP_ELSE, OP_ENDIF]);
        pass(&[OP_1, OP_1, OP_1, OP_IF, OP_IF, OP_ENDIF, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]);
        pass(&[OP_0, OP_IF, OP_0, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_0, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_0, OP_IF, OP_ELSE, OP_1, OP_ENDIF, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_PUSHDATA1, 1, 0, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[
            OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_ELSE, OP_ELSE, OP_1, OP_ENDIF,
        ]);
        pass(&[OP_1, OP_VERIFY, OP_1]);
        pass(&[OP_1, OP_RETURN]);
        pass(&[OP_FALSE, OP_TRUE, OP_RETURN]);
        pass(&[OP_1, OP_0, OP_TOALTSTACK]);
        pass(&[OP_1, OP_TOALTSTACK, OP_FROMALTSTACK]);
        pass(&[OP_1, OP_IFDUP, OP_DROP, OP_DROP, OP_1]);
        pass(&[OP_DEPTH, OP_1]);
        pass(&[OP_0, OP_DEPTH]);
        pass(&[OP_1, OP_0, OP_DROP]);
        pass(&[OP_0, OP_DUP, OP_DROP, OP_DROP, OP_1]);
        pass(&[OP_1, OP_0, OP_0, OP_NIP, OP_DROP]);
        pass(&[OP_1, OP_0, OP_OVER]);
        pass(&[OP_1, OP_0, OP_PICK]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_4, OP_PICK]);
        pass(&[OP_1, OP_0, OP_ROLL]);
        pass(&[OP_1, OP_0, OP_0, OP_ROLL, OP_DROP]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_4, OP_ROLL]);
        pass(&[OP_1, OP_0, OP_0, OP_ROT]);
        pass(&[OP_0, OP_1, OP_0, OP_ROT, OP_ROT]);
        pass(&[OP_0, OP_0, OP_1, OP_ROT, OP_ROT, OP_ROT]);
        pass(&[OP_1, OP_0, OP_SWAP]);
        pass(&[OP_0, OP_1, OP_TUCK, OP_DROP, OP_DROP]);
        pass(&[OP_1, OP_0, OP_0, OP_2DROP]);
        pass(&[OP_0, OP_1, OP_2DUP]);
        pass(&[OP_0, OP_1, OP_2DUP, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_0, OP_1, OP_3DUP]);
        pass(&[OP_0, OP_0, OP_1, OP_3DUP, OP_DROP, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_2OVER]);
        pass(&[OP_0, OP_0, OP_0, OP_1, OP_2OVER, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_0, OP_0, OP_2ROT]);
        pass(&[OP_0, OP_0, OP_0, OP_1, OP_0, OP_0, OP_2ROT, OP_2ROT]);
        pass(&[
            OP_0, OP_0, OP_0, OP_0, OP_0, OP_1, OP_2ROT, OP_2ROT, OP_2ROT,
        ]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_0, OP_2ROT, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_2SWAP]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_2SWAP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_CAT]);
        pass(&[OP_1, OP_0, OP_0, OP_2, OP_0, OP_CAT, OP_PICK]);
        pass(&[OP_0, OP_0, OP_CAT, OP_IF, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_1, OP_SPLIT]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_2, OP_SPLIT, OP_DROP]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_0, OP_SPLIT]);
        pass(&[OP_0, OP_0, OP_SPLIT, OP_1]);
        pass(&[OP_1, OP_1, OP_SPLIT, OP_DROP]);
        pass(&[OP_1, OP_SIZE]);
        pass(&[OP_1, OP_SIZE, OP_DROP]);
        pass(&[OP_1, OP_1, OP_AND]);
        pass(&[OP_1, OP_1, OP_OR]);
        pass(&[OP_1, OP_1, OP_XOR, OP_IF, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[
            OP_PUSH + 3,
            0xFF,
            0x01,
            0x00,
            OP_INVERT,
            OP_PUSH + 3,
            0x00,
            0xFE,
            0xFF,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_LSHIFT, OP_0, OP_EQUAL]);
        pass(&[OP_4, OP_2, OP_LSHIFT, OP_16, OP_EQUAL]);
        pass(&[
            OP_PUSH + 2,
            0x12,
            0x34,
            OP_4,
            OP_LSHIFT,
            OP_PUSH + 2,
            0x23,
            0x40,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_RSHIFT, OP_0, OP_EQUAL]);
        pass(&[OP_4, OP_2, OP_RSHIFT, OP_1, OP_EQUAL]);
        pass(&[
            OP_PUSH + 2,
            0x12,
            0x34,
            OP_4,
            OP_RSHIFT,
            OP_PUSH + 2,
            0x01,
            0x23,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_EQUAL]);
        pass(&[OP_1, OP_0, OP_0, OP_EQUALVERIFY]);
        pass(&[OP_0, OP_1ADD]);
        pass(&[OP_1, OP_1ADD, OP_2, OP_EQUAL]);
        pass(&[OP_2, OP_1SUB]);
        pass(&[OP_0, OP_1SUB, OP_1NEGATE, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_1ADD, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_1SUB, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        pass(&[OP_1, OP_NEGATE, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_NEGATE, OP_1, OP_EQUAL]);
        pass(&[OP_1, OP_ABS, OP_1, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_ABS, OP_1, OP_EQUAL]);
        pass(&[OP_0, OP_NOT]);
        pass(&[OP_1, OP_NOT, OP_0, OP_EQUAL]);
        pass(&[OP_2, OP_NOT, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_NOT, OP_NOT]);
        pass(&[OP_1, OP_0NOTEQUAL]);
        pass(&[OP_0, OP_0NOTEQUAL, OP_0, OP_EQUAL]);
        pass(&[OP_2, OP_0NOTEQUAL]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_1ADD]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_1SUB]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NEGATE, OP_1]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_ABS, OP_1]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NOT]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_0NOTEQUAL, OP_1]);
        pass(&[OP_0, OP_1, OP_ADD]);
        pass(&[OP_1, OP_0, OP_ADD]);
        pass(&[OP_1, OP_2, OP_ADD, OP_3, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_SIZE, OP_6, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_0, OP_EQUAL]);
        pass(&v);
        pass(&[OP_2, OP_1, OP_SUB]);
        pass(&[OP_1, OP_1, OP_SUB, OP_0, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F]);
        v.extend_from_slice(&[OP_SUB, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F]);
        v.extend_from_slice(&[OP_SUB, OP_0, OP_EQUAL]);
        pass(&v);
        pass(&[OP_1, OP_1, OP_MUL, OP_1, OP_EQUAL]);
        pass(&[OP_2, OP_3, OP_MUL, OP_6, OP_EQUAL]);
        pass(&[
            OP_PUSH + 4,
            0xFF,
            0xFF,
            0xFF,
            0x7F,
            OP_PUSH + 4,
            0xFF,
            0xFF,
            0xFF,
            0x7F,
            OP_MUL,
        ]);
        pass(&[OP_1, OP_1NEGATE, OP_MUL, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_DIV, OP_1, OP_EQUAL]);
        pass(&[OP_5, OP_2, OP_DIV, OP_2, OP_EQUAL]);
        pass(&[OP_2, OP_1NEGATE, OP_DIV, OP_PUSH + 1, 130, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_MOD, OP_0, OP_EQUAL]);
        pass(&[OP_5, OP_2, OP_MOD, OP_1, OP_EQUAL]);
        pass(&[OP_5, OP_PUSH + 1, 130, OP_MOD, OP_1, OP_EQUAL]);
        pass(&[OP_PUSH + 1, 133, OP_2, OP_MOD, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_BOOLAND]);
        pass(&[OP_0, OP_1, OP_BOOLAND, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_0, OP_BOOLOR]);
        pass(&[OP_0, OP_0, OP_BOOLOR, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_NUMEQUAL]);
        pass(&[OP_0, OP_1, OP_NUMEQUAL, OP_NOT]);
        pass(&[OP_1, OP_1, OP_NUMEQUALVERIFY, OP_1]);
        pass(&[OP_1, OP_0, OP_NUMNOTEQUAL]);
        pass(&[OP_1, OP_1, OP_NUMNOTEQUAL, OP_NOT]);
        pass(&[OP_0, OP_1, OP_LESSTHAN]);
        pass(&[OP_1NEGATE, OP_0, OP_LESSTHAN]);
        pass(&[OP_0, OP_0, OP_LESSTHAN, OP_NOT]);
        pass(&[OP_1, OP_0, OP_GREATERTHAN]);
        pass(&[OP_0, OP_1NEGATE, OP_GREATERTHAN]);
        pass(&[OP_0, OP_0, OP_GREATERTHAN, OP_NOT]);
        pass(&[OP_0, OP_1, OP_LESSTHANOREQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_LESSTHANOREQUAL]);
        pass(&[OP_0, OP_0, OP_LESSTHANOREQUAL]);
        pass(&[OP_1, OP_0, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_1NEGATE, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_0, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_1, OP_MIN, OP_0, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_MIN, OP_0, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_MIN, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_0, OP_1, OP_MAX, OP_1, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_MAX, OP_0, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_MAX, OP_0, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_1, OP_WITHIN]);
        pass(&[OP_0, OP_1NEGATE, OP_1, OP_WITHIN]);
        pass(&[OP_PUSH + 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, OP_BIN2NUM]);
        pass(&[OP_PUSH + 4, 128, 0, 0, 1, OP_BIN2NUM, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_PUSH + 7, 0, 0, 0, 0, 0, 0, 0, OP_BIN2NUM, OP_0, OP_EQUAL]);
        pass(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_BIN2NUM]);
        pass(&[OP_1, OP_16, OP_NUM2BIN]);
        pass(&[OP_0, OP_4, OP_NUM2BIN, OP_0, OP_NUMEQUAL]);
        pass(&[OP_1, OP_DUP, OP_16, OP_NUM2BIN, OP_BIN2NUM, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_DUP, OP_16, OP_NUM2BIN, OP_BIN2NUM, OP_EQUAL]);
        pass(&[OP_1, OP_PUSH + 5, 129, 0, 0, 0, 0, OP_NUM2BIN]);
        let mut v = Vec::new();
        v.push(OP_1);
        v.push(OP_PUSH + 2);
        v.extend_from_slice(&encode_num(520).unwrap());
        v.push(OP_NUM2BIN);
        pass(&v);
        pass(&[OP_1, OP_RIPEMD160]);
        pass(&[OP_0, OP_RIPEMD160]);
        let mut s = Script::new();
        let h = "cea1b21f1a739fba68d1d4290437d2c5609be1d3";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_RIPEMD160, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_SHA1]);
        pass(&[OP_0, OP_SHA1]);
        let mut s = Script::new();
        let h = "0ca2eadb529ac2e63abf9b4ae3df8ee121f10547";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_SHA1, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_SHA256]);
        pass(&[OP_0, OP_SHA256]);
        let mut s = Script::new();
        let h = "55c53f5d490297900cefa825d0c8e8e9532ee8a118abe7d8570762cd38be9818";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_SHA256, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_HASH160]);
        pass(&[OP_0, OP_HASH160]);
        let mut s = Script::new();
        let h = "a956ed79819901b1b2c7b3ec045081f749c588ed";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_HASH160, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_HASH256]);
        pass(&[OP_0, OP_HASH256]);
        let mut s = Script::new();
        let h = "137ad663f79da06e282ed0abbec4d70523ced5ff8e39d5c2e5641d978c5925aa";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_HASH256, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_1, OP_CHECKSIG]);
        pass(&[OP_1, OP_1, OP_CHECKSIGVERIFY, OP_1]);
        pass(&[OP_0, OP_0, OP_0, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_0, OP_9, OP_9, OP_9, OP_3, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_9, OP_1, OP_9, OP_9, OP_9, OP_3, OP_CHECKMULTISIG]);
        let mut c = MockChecker::sig_checks(vec![true]);
        assert!(eval(
            &[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG],
            &mut c,
            NO_FLAGS
        )
        .is_ok());
        let mut c = MockChecker::sig_checks(vec![false, true, true]);
        let mut s = vec![OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_9, OP_3];
        s.push(OP_CHECKMULTISIG);
        assert!(eval(&s, &mut c, NO_FLAGS).is_ok());
        pass_pregenesis(&[OP_0, OP_CHECKLOCKTIMEVERIFY, OP_1]);
        pass(&[OP_CHECKLOCKTIMEVERIFY, OP_1]);
        pass_pregenesis(&[OP_0, OP_CHECKSEQUENCEVERIFY, OP_1]);
        pass(&[OP_CHECKSEQUENCEVERIFY, OP_1]);
        pass(&[OP_NOP1, OP_1]);
        pass(&[OP_NOP4, OP_1]);
        pass(&[OP_NOP5, OP_1]);
        pass(&[OP_NOP6, OP_1]);
        pass(&[OP_NOP7, OP_1]);
        pass(&[OP_NOP8, OP_1]);
        pass(&[OP_NOP9, OP_1]);
        pass(&[OP_NOP10, OP_1]);
        let mut v = vec![OP_DEPTH; 501];
        v.push(OP_1);
        pass(&v);
        pass(&vec![OP_1; 10001]);
    }

    #[test]
    fn invalid() {
        fail(&[]);
        fail(&[OP_FALSE]);
        fail(&[OP_PUSH + 1]);
        fail(&[OP_PUSH + 3, 0, 1]);
        fail(&[OP_PUSHDATA1, 0]);
        fail(&[OP_PUSHDATA1, 1]);
        fail(&[OP_PUSHDATA1, 10, 0]);
        fail(&[OP_PUSHDATA2, 20, 0]);
        fail(&[OP_PUSHDATA4, 30, 0]);
        fail(&[OP_IF, OP_ENDIF]);
        fail(&[OP_1, OP_1, OP_IF]);
        fail(&[OP_1, OP_1, OP_NOTIF]);
        fail(&[OP_1, OP_ELSE]);
        fail(&[OP_1, OP_ENDIF]);
        fail(&[OP_1, OP_1, OP_IF, OP_ELSE]);
        fail(&[OP_1, OP_1, OP_IF, OP_IF, OP_ENDIF]);
        fail(&[OP_0, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]);
        fail(&[OP_0, OP_IF, OP_PUSHDATA1, 1, 1, OP_1, OP_ENDIF]);
        fail(&[OP_VERIFY]);
        fail(&[OP_0, OP_VERIFY]);
        fail(&[OP_RETURN]);
        fail(&[OP_FALSE, OP_RETURN]);
        fail_pregenesis(&[OP_RETURN]);
        fail_pregenesis(&[OP_1, OP_RETURN, OP_1]);
        fail(&[OP_TOALTSTACK]);
        fail(&[OP_FROMALTSTACK]);
        fail(&[OP_0, OP_TOALTSTACK, OP_1, OP_FROMALTSTACK]);
        fail(&[OP_IFDUP]);
        fail(&[OP_DROP]);
        fail(&[OP_1, OP_DROP, OP_DROP]);
        fail(&[OP_DUP]);
        fail(&[OP_NIP]);
        fail(&[OP_1, OP_NIP]);
        fail(&[OP_OVER]);
        fail(&[OP_1, OP_OVER]);
        fail(&[OP_PICK]);
        fail(&[OP_0, OP_PICK]);
        fail(&[OP_0, OP_1, OP_PICK]);
        fail(&[OP_ROLL]);
        fail(&[OP_0, OP_ROLL]);
        fail(&[OP_0, OP_1, OP_ROLL]);
        fail(&[OP_ROT]);
        fail(&[OP_1, OP_ROT]);
        fail(&[OP_1, OP_1, OP_ROT]);
        fail(&[OP_0, OP_1, OP_1, OP_ROT]);
        fail(&[OP_SWAP]);
        fail(&[OP_1, OP_SWAP]);
        fail(&[OP_0, OP_1, OP_SWAP]);
        fail(&[OP_TUCK]);
        fail(&[OP_1, OP_TUCK]);
        fail(&[OP_1, OP_0, OP_TUCK]);
        fail(&[OP_2DROP]);
        fail(&[OP_1, OP_2DROP]);
        fail(&[OP_1, OP_1, OP_2DROP]);
        fail(&[OP_2DUP]);
        fail(&[OP_1, OP_2DUP]);
        fail(&[OP_1, OP_0, OP_2DUP]);
        fail(&[OP_3DUP]);
        fail(&[OP_1, OP_3DUP]);
        fail(&[OP_1, OP_1, OP_3DUP]);
        fail(&[OP_1, OP_1, OP_0, OP_3DUP]);
        fail(&[OP_2OVER]);
        fail(&[OP_1, OP_2OVER]);
        fail(&[OP_1, OP_1, OP_2OVER]);
        fail(&[OP_1, OP_1, OP_1, OP_2OVER]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_2OVER]);
        fail(&[OP_2ROT]);
        fail(&[OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_2SWAP]);
        fail(&[OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_CAT]);
        fail(&[OP_1, OP_CAT]);
        fail(&[OP_1, OP_0, OP_0, OP_CAT]);
        fail(&[OP_SPLIT]);
        fail(&[OP_1, OP_SPLIT]);
        fail(&[OP_0, OP_1, OP_SPLIT]);
        fail(&[OP_1, OP_2, OP_SPLIT]);
        fail(&[OP_1, OP_1NEGATE, OP_SPLIT]);
        fail(&[OP_0, OP_SIZE]);
        fail(&[OP_AND]);
        fail(&[OP_0, OP_AND]);
        fail(&[OP_0, OP_1, OP_AND]);
        fail(&[OP_OR]);
        fail(&[OP_0, OP_OR]);
        fail(&[OP_0, OP_1, OP_OR]);
        fail(&[OP_XOR]);
        fail(&[OP_0, OP_XOR]);
        fail(&[OP_0, OP_1, OP_XOR]);
        fail(&[OP_LSHIFT]);
        fail(&[OP_1, OP_LSHIFT]);
        fail(&[OP_1, OP_1NEGATE, OP_LSHIFT]);
        fail(&[OP_RSHIFT]);
        fail(&[OP_1, OP_RSHIFT]);
        fail(&[OP_1, OP_1NEGATE, OP_RSHIFT]);
        fail(&[OP_INVERT]);
        fail(&[OP_EQUAL]);
        fail(&[OP_0, OP_EQUAL]);
        fail(&[OP_1, OP_0, OP_EQUAL]);
        fail(&[OP_1, OP_0, OP_EQUALVERIFY, OP_1]);
        fail(&[OP_1ADD]);
        fail(&[OP_1SUB]);
        fail(&[OP_NEGATE]);
        fail(&[OP_ABS]);
        fail(&[OP_NOT]);
        fail(&[OP_0NOTEQUAL]);
        fail(&[OP_ADD]);
        fail(&[OP_1, OP_ADD]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_ADD]);
        fail(&[OP_SUB]);
        fail(&[OP_1, OP_SUB]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_SUB]);
        fail(&[OP_MUL]);
        fail(&[OP_1, OP_MUL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MUL]);
        fail(&[OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_MUL]);
        fail(&[OP_DIV]);
        fail(&[OP_1, OP_DIV]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_DIV]);
        fail(&[OP_1, OP_0, OP_DIV]);
        fail(&[OP_MOD]);
        fail(&[OP_1, OP_MOD]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MOD]);
        fail(&[OP_1, OP_0, OP_MOD]);
        fail(&[OP_BOOLAND]);
        fail(&[OP_1, OP_BOOLAND]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_BOOLAND]);
        fail(&[OP_BOOLOR]);
        fail(&[OP_1, OP_BOOLOR]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_BOOLOR]);
        fail(&[OP_NUMEQUAL]);
        fail(&[OP_1, OP_NUMEQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMEQUAL]);
        fail(&[OP_0, OP_1, OP_NUMEQUAL]);
        fail(&[OP_NUMEQUALVERIFY]);
        fail(&[OP_1, OP_NUMEQUALVERIFY]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMEQUALVERIFY]);
        fail(&[OP_1, OP_2, OP_NUMEQUALVERIFY]);
        fail(&[OP_NUMNOTEQUAL]);
        fail(&[OP_1, OP_NUMNOTEQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMNOTEQUAL]);
        fail(&[OP_1, OP_1, OP_NUMNOTEQUAL]);
        fail(&[OP_LESSTHAN]);
        fail(&[OP_1, OP_LESSTHAN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_LESSTHAN]);
        fail(&[OP_1, OP_0, OP_LESSTHAN]);
        fail(&[OP_GREATERTHAN]);
        fail(&[OP_1, OP_GREATERTHAN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_GREATERTHAN]);
        fail(&[OP_0, OP_1, OP_GREATERTHAN]);
        fail(&[OP_LESSTHANOREQUAL]);
        fail(&[OP_1, OP_LESSTHANOREQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_LESSTHANOREQUAL]);
        fail(&[OP_1, OP_0, OP_LESSTHANOREQUAL]);
        fail(&[OP_GREATERTHANOREQUAL]);
        fail(&[OP_1, OP_GREATERTHANOREQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_GREATERTHANOREQUAL]);
        fail(&[OP_0, OP_1, OP_GREATERTHANOREQUAL]);
        fail(&[OP_MIN]);
        fail(&[OP_1, OP_MIN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MIN]);
        fail(&[OP_MAX]);
        fail(&[OP_1, OP_MAX]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MAX]);
        fail(&[OP_WITHIN]);
        fail(&[OP_1, OP_WITHIN]);
        fail(&[OP_1, OP_1, OP_WITHIN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_WITHIN]);
        fail(&[OP_0, OP_1, OP_2, OP_WITHIN]);
        fail(&[OP_0, OP_1NEGATE, OP_0, OP_WITHIN]);
        fail(&[OP_BIN2NUM]);
        fail(&[OP_NUM2BIN]);
        fail(&[OP_1, OP_NUM2BIN]);
        fail(&[OP_1, OP_0, OP_NUM2BIN]);
        fail(&[OP_1, OP_1NEGATE, OP_NUM2BIN]);
        fail(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_1, OP_NUM2BIN]);
        fail(&[OP_RIPEMD160]);
        fail(&[OP_SHA1]);
        fail(&[OP_SHA256]);
        fail(&[OP_HASH160]);
        fail(&[OP_HASH256]);
        fail(&[OP_CHECKSIG]);
        fail(&[OP_1, OP_CHECKSIG]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(&[OP_1, OP_1, OP_CHECKSIG], &mut c, NO_FLAGS).is_err());
        fail(&[OP_CHECKSIGVERIFY]);
        fail(&[OP_1, OP_CHECKSIGVERIFY]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(&[OP_1, OP_1, OP_CHECKSIGVERIFY, OP_1], &mut c, NO_FLAGS).is_err());
        fail(&[OP_CHECKMULTISIG]);
        fail(&[OP_1, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_1NEGATE, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_1NEGATE, OP_0, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_1, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_PUSH + 1, 21, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_9, OP_9, OP_2, OP_9, OP_1, OP_CHECKMULTISIG]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(
            &[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG],
            &mut c,
            NO_FLAGS
        )
        .is_err());
        let mut c = MockChecker::sig_checks(vec![true, false]);
        let s = [OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_2, OP_CHECKMULTISIG];
        assert!(eval(&s, &mut c, NO_FLAGS).is_err());
        let mut c = MockChecker::sig_checks(vec![false, true, false]);
        let mut s = vec![OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_9, OP_3];
        s.push(OP_CHECKMULTISIG);
        assert!(eval(&s, &mut c, NO_FLAGS).is_err());
        fail_pregenesis(&[OP_CHECKLOCKTIMEVERIFY, OP_1]);
        fail_pregenesis(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_CHECKLOCKTIMEVERIFY, OP_1]);
        let mut c = MockChecker::locktime_checks(vec![false]);
        assert!(eval(
            &vec![OP_0, OP_CHECKLOCKTIMEVERIFY, OP_1],
            &mut c,
            PREGENESIS_RULES
        )
        .is_err());
        fail_pregenesis(&[OP_CHECKSEQUENCEVERIFY, OP_1]);
        fail_pregenesis(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_CHECKSEQUENCEVERIFY, OP_1]);
        let mut c = MockChecker::sequence_checks(vec![false]);
        assert!(eval(
            &vec![OP_0, OP_CHECKSEQUENCEVERIFY, OP_1],
            &mut c,
            PREGENESIS_RULES
        )
        .is_err());
        fail(&[OP_RESERVED, OP_1]);
        fail(&[OP_VER, OP_1]);
        fail(&[OP_VERIF, OP_1]);
        fail(&[OP_VERNOTIF, OP_1]);
        fail(&[OP_RESERVED1, OP_1]);
        fail(&[OP_RESERVED2, OP_1]);
        fail(&[OP_INVERT, OP_1]);
        fail(&[OP_2MUL, OP_1]);
        fail(&[OP_2DIV, OP_1]);
        fail(&[OP_MUL, OP_1]);
        fail(&[OP_LSHIFT, OP_1]);
        fail(&[OP_RSHIFT, OP_1]);
        fail(&[OP_INVALID_ABOVE, OP_1]);
        fail(&[OP_PUBKEYHASH, OP_1]);
        fail(&[OP_PUBKEY, OP_1]);
        fail(&[OP_INVALIDOPCODE, OP_1]);
    }

    #[test]
    fn next_op_tests() {
        let script = [];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_0, OP_CHECKSIG, OP_ADD];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 2);
        assert!(next_op(2, &script) == script.len());

        let script = [OP_1, OP_PUSH + 4, 1, 2, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 6);
        assert!(next_op(6, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA1, 2, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 5);
        assert!(next_op(5, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA2, 2, 0, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 6);
        assert!(next_op(6, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA4, 2, 0, 0, 0, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 8);
        assert!(next_op(8, &script) == script.len());

        // Parse failures

        let script = [OP_PUSH + 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSH + 3, 1, 2];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA1, 2, 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2, 0];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2, 2, 0, 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4, 1, 2, 3];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4, 2, 0, 0, 0, 1];
        assert!(next_op(0, &script) == script.len());
    }

    #[test]
    fn remove_sig_tests() {
        assert!(remove_sig(&[], &[]) == vec![]);
        assert!(remove_sig(&[], &[OP_0]) == vec![OP_0]);
        assert!(remove_sig(&[OP_0], &[OP_0]) == vec![]);
        let v = [OP_0, OP_1, OP_2, OP_3, OP_4, OP_0, OP_1, OP_2, OP_3, OP_4];
        assert!(remove_sig(&[OP_2, OP_3], &v) == vec![OP_0, OP_1, OP_4, OP_0, OP_1, OP_4]);
    }

    /// A test run that doesn't do signature checks and expects failure
    fn pass(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, NO_FLAGS).is_ok());
    }

    /// A test run that doesn't do signature checks and expects failure
    fn fail(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, NO_FLAGS).is_err());
    }

    /// Pre-genesis versions of the above checks
    fn pass_pregenesis(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, PREGENESIS_RULES).is_ok());
    }

    /// A test run that doesn't do signature checks and expects failure
    fn fail_pregenesis(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, PREGENESIS_RULES).is_err());
    }

    /// Mocks a transaction checker to always return a set of values
    struct MockChecker {
        sig_checks: RefCell<Vec<bool>>,
        locktime_checks: RefCell<Vec<bool>>,
        sequence_checks: RefCell<Vec<bool>>,
    }

    impl MockChecker {
        fn sig_checks(sig_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(sig_checks),
                locktime_checks: RefCell::new(vec![true; 32]),
                sequence_checks: RefCell::new(vec![true; 32]),
            }
        }

        fn locktime_checks(locktime_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(vec![true; 32]),
                locktime_checks: RefCell::new(locktime_checks),
                sequence_checks: RefCell::new(vec![true; 32]),
            }
        }

        fn sequence_checks(sequence_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(vec![true; 32]),
                locktime_checks: RefCell::new(vec![true; 32]),
                sequence_checks: RefCell::new(sequence_checks),
            }
        }
    }

    impl Checker for MockChecker {
        fn check_sig(&mut self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
            Ok(self.sig_checks.borrow_mut().pop().unwrap())
        }

        fn check_locktime(&self, _locktime: i32) -> Result<bool> {
            Ok(self.locktime_checks.borrow_mut().pop().unwrap())
        }

        fn check_sequence(&self, _sequence: i32) -> Result<bool> {
            Ok(self.sequence_checks.borrow_mut().pop().unwrap())
        }
    }
}
