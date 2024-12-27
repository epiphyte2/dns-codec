use num_bigint::BigUint;
use thiserror::Error;

const FORWARD: &[u8] = &[
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
    b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5',
    b'6', b'7', b'8', b'9', b'-', b'.',
];

const REVERSE: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 37, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const RADIX_ANY: usize = 38;
const RADIX_BEGIN: usize = 26;
const RADIX_END: usize = 36;

const MAX_LABEL: usize = 61;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("invalid data")]
    InvalidData,
}

fn encode(data: &[u8]) -> Vec<u8> {
    let mut value = BigUint::from_bytes_le(data);
    value |= BigUint::from(1u8) << data.len() * 8;
    let mut result = Vec::new();
    let mut radix = RADIX_BEGIN;
    let mut len = 0;
    while value != BigUint::ZERO {
        let rem: usize = (&value % radix).try_into().unwrap();
        value /= radix;
        let mut c = FORWARD[rem];
        result.push(c);
        len += 1;
        if len == MAX_LABEL {
            c = b'.';
            result.push(c);
        };
        if c == b'.' {
            radix = RADIX_BEGIN;
            len = 0;
        } else if c == b'-' || len == MAX_LABEL - 1 {
            radix = RADIX_END;
        } else {
            radix = RADIX_ANY;
        };
    }
    result.push(FORWARD[0]);
    result
}

pub fn encode_string(data: &[u8]) -> String {
    encode(data).into_iter().map(|x| char::from(x)).collect()
}

pub fn decode(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    let len = data.len();
    if len < 2 {
        return Err(CodecError::InvalidData);
    }
    if data[len - 1] != b'a' && data[len - 1] != b'A' {
        return Err(CodecError::InvalidData);
    }
    let mut value = BigUint::ZERO;
    let mut radix = RADIX_ANY;
    for idx in (0..len - 1).rev() {
        if data[idx] == b'.' && idx >= MAX_LABEL && !data[idx - MAX_LABEL..idx].contains(&b'.') {
            radix = RADIX_END;
            continue;
        }
        if idx > 0 && data[idx - 1] == b'-' {
            radix = RADIX_END;
        }
        if idx == 0 || data[idx - 1] == b'.' {
            radix = RADIX_BEGIN;
        }
        value *= radix;
        value += REVERSE[data[idx] as usize];
        radix = RADIX_ANY;
    }
    let mut result = value.to_bytes_le();
    result.pop();
    Ok(result)
}

pub fn decode_string(string: &str) -> Result<Vec<u8>, CodecError> {
    decode(string.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng};

    fn validate_encoding(value: &[u8]) {
        let encoded = encode_string(&value);
        let decoded = decode_string(&encoded).unwrap();
        assert_eq!(value, decoded, "{value:?} => {encoded} => {decoded:?}");
        assert!(
            encoded.len() <= 248,
            "encoded length exceeds 248: {value:?} ({}) => {encoded} ({})",
            value.len(),
            encoded.len()
        );

        let upper = encoded.to_uppercase();
        let decoded = decode_string(&upper).unwrap();
        assert_eq!(value, decoded, "{value:?} => {upper} => {decoded:?}");

        let mut prev = '.';
        let mut len = 0;
        for c in encoded.chars() {
            if prev == '.' {
                assert!(
                    c.is_ascii_alphabetic(),
                    "label start is not alphabetic: {encoded}"
                );
                len = -1;
            };
            if prev == '-' {
                assert_ne!(c, '-', "consecutive '-': {encoded}");
            }

            if c == '.' {
                assert!(
                    prev.is_ascii_alphanumeric(),
                    "label end is not alphanumeric: {encoded}"
                );
            } else if c != '-' {
                assert!(c.is_ascii_alphanumeric(), "invalid characters: {encoded}");
            }

            prev = c;
            len += 1;
            assert!(
                len as usize <= MAX_LABEL,
                "label exceeds max length of {MAX_LABEL}: {encoded}"
            );
        }
        assert_ne!(prev, '-', "encoding ends in '-': {encoded}");
        assert_ne!(prev, '.', "encoding ends in '.': {encoded}");
    }

    #[test]
    fn can_encode_and_decode_empty_vector() {
        validate_encoding(&vec![]);
    }

    #[test]
    fn can_encode_and_decode_all_1_byte_values() {
        for i in 0u8..=255u8 {
            validate_encoding(&vec![i]);
        }
    }

    #[test]
    fn can_encode_and_decode_all_2_byte_values() {
        for i in 0..65536 {
            let value = vec![(i / 256) as u8, (i % 256) as u8];
            validate_encoding(&value);
        }
    }

    #[test]
    fn can_encode_and_decode_the_first_million_3_byte_values() {
        for i in 0..1_000_000 {
            let value = vec![(i / 65536) as u8, (i / 256) as u8, (i % 256) as u8];
            validate_encoding(&value);
        }
    }

    #[test]
    fn can_encode_and_decode_100k_random_values() {
        for _ in 0..100_000 {
            let len = thread_rng().gen_range(3..159);
            let value: Vec<u8> = thread_rng().sample_iter(Standard).take(len).collect();
            validate_encoding(&value);
        }
    }

    #[test]
    fn can_encode_and_decode_100k_max_len_random_values() {
        for _ in 0..100_000 {
            let value: Vec<u8> = thread_rng().sample_iter(Standard).take(158).collect();
            validate_encoding(&value);
        }
    }

    #[test]
    fn can_encode_and_decode_all_scaled_unit_vectors() {
        for len in 3..160 {
            for value in 0u8..=255u8 {
                let data = vec![value; len];
                validate_encoding(&data);
            }
        }
    }

    #[test]
    fn can_decode_and_reencode_max_len_short_labels() {
        for s in [
            "a.", "b.", "c.", "d.", "e.", "f.", "g.", "h.", "i.", "j.", "k.", "l.", "m.", "n.",
            "o.", "p.", "q.", "r.", "s.", "t.", "u.", "v.", "w.", "x.", "y.", "z.",
        ] {
            let mut encoded = String::from(s.repeat(124).strip_suffix(".").unwrap());
            encoded.push('a');
            let decoded = decode_string(&encoded).unwrap();
            assert!(
                decoded.len() >= 152,
                "{encoded} => {decoded:?} ({})",
                decoded.len()
            );
            let reencoded = encode_string(&decoded);
            if encoded.starts_with("b") {
                assert_eq!(encoded, reencoded);
                assert_eq!(decoded.len(), 153);
            } else {
                assert_ne!(encoded, reencoded);
            }
            let redecoded = decode_string(&reencoded).unwrap();
            assert_eq!(
                decoded, redecoded,
                "{encoded} => {decoded:?} => {reencoded} => {redecoded:?}"
            );
            assert!(
                reencoded.len() <= 248,
                "{encoded} => {decoded:?} => {reencoded} ({})",
                reencoded.len()
            );
        }
    }
}
