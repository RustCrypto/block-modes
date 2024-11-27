use cipher::{crypto_common::BlockSizes, Array};

/// Derived from the polynomial x^128 + x^5 + x + 1
const GF_MOD: u8 = 0x87;

pub fn gf_mul<BS>(tweak: &mut Array<u8, BS>) -> u8
where
    BS: BlockSizes,
{
    let mut carry = 0;

    for i in 0..BS::to_usize() {
        // Save carry from previous byte
        let old_carry = carry;

        // Check if there is a carry for this shift
        carry = (tweak[i] & 0x80) >> 7;

        // Shift left
        tweak[i] <<= 1;

        // Carry over bit from last carry
        tweak[i] |= old_carry;
    }

    // If there is a carry, we mod by the polynomial
    tweak[0] ^= 0u8.wrapping_sub(carry) & GF_MOD;

    carry
}

// This is only used once when decrypting with ciphertext stealing
pub fn gf_reverse_mul<BS>(tweak: &mut Array<u8, BS>, carry: u8)
where
    BS: BlockSizes,
{
    tweak[0] ^= 0u8.wrapping_sub(carry) & GF_MOD;

    let mut new_carry = 0;

    for i in (0..BS::to_usize()).rev() {
        // Save carry from previous byte
        let old_carry = new_carry;

        // Check if there is a carry for this shift
        new_carry = tweak[i] & 1;

        // Shift right
        tweak[i] >>= 1;

        // Carry over bit from last carry
        tweak[i] |= old_carry << 7;
    }

    // If there is a carry, we mod by the polynomial
    *tweak.last_mut().expect("tweak should never be empty") |= carry << 7;
}

#[cfg(test)]
mod tests {
    use cipher::{consts::U16, Array};

    use crate::gf::{gf_mul, gf_reverse_mul};

    #[test]
    fn test_gf_mul() {
        let mut input = Array::<u8, U16>::from([0x55; 16]);
        let expected_output = [0xAA; 16];

        let carry = gf_mul(&mut input);

        assert_eq!(carry, 0);
        assert_eq!(input, expected_output);
    }

    #[test]
    fn test_gf_mul_overflow() {
        let mut input = Array::<u8, U16>::from([0xAA; 16]);
        let mut expected_output = [0x55; 16];
        expected_output[0] = 0xd3;

        let carry = gf_mul(&mut input);

        assert_eq!(carry, 1);
        assert_eq!(input, expected_output)
    }

    #[test]
    fn test_gf_reverse_mul() {
        let mut input = Array::<u8, U16>::from([0xAA; 16]);
        let expected_output = [0x55; 16];

        gf_reverse_mul(&mut input, 0);

        assert_eq!(input, expected_output);
    }

    #[test]
    fn test_gf_reverse_mul_overflow() {
        let mut input = Array::<u8, U16>::from([0xAA; 16]);
        let mut expected_output = [0x55; 16];
        expected_output[0] = 0x16;
        expected_output[15] = 0xd5;

        gf_reverse_mul(&mut input, 1);

        assert_eq!(input, expected_output);
    }
}
