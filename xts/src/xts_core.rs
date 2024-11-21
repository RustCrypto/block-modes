use cipher::{
    crypto_common::BlockSizes, Array, Block, BlockCipherEncrypt, BlockSizeUser, InOut, InOutBuf,
    ParBlocks, ParBlocksSizeUser,
};

use crate::xor;

/// Derived from the polynomial x^128 + x^5 + x + 1
const GF_MOD: u8 = 0x87;

/// Since the traits does not allow using two engines, this is used to pre-compute the IV.
pub fn precompute_iv<BS, BC>(cipher: &BC, iv: &mut Array<u8, BS>)
where
    BS: BlockSizes,
    BC: BlockCipherEncrypt<BlockSize = BS>,
{
    cipher.encrypt_block(iv);
}

pub fn gf_mul<BS>(tweak: &mut Array<u8, BS>) -> bool
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
    if carry == 1 {
        tweak[0] ^= GF_MOD;
    }

    carry == 1
}

/// Core implementation of XTS mode
pub trait Xts: ParBlocksSizeUser + BlockSizeUser {
    /// Method to encrypt/decrypt a single block without mode.
    fn process_inplace(&self, block: &mut Block<Self>); // Array<u8, Self::BlockSize>);

    /// Method to encrypt/decrypt multiple blocks in parallel without mode.
    fn process_par_inplace(&self, blocks: &mut ParBlocks<Self>);

    /// Gets the IV reference.
    fn get_iv_mut(&mut self) -> &mut Array<u8, Self::BlockSize>;

    // Unused but keeping for now just in case
    // fn process(&self, mut block: InOut<'_, '_, Block<Self>>) {
    //     let mut b = block.clone_in();
    //     self.process_inplace(&mut b);

    //     *block.get_out() = b;
    // }

    // fn process_par(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
    //     let mut blocks = blocks.clone_in();
    //     self.process_par_inplace(&mut blocks);
    // }

    fn process_block_inplace(&mut self, block: &mut Block<Self>) {
        {
            let iv = self.get_iv_mut();
            xor(block, iv);
        }

        self.process_inplace(block);

        let iv = self.get_iv_mut();
        xor(block, iv);

        let _ = gf_mul(iv);
    }

    /// Encrypt/decrypt a block using XTS and update the tweak
    fn process_block(&mut self, mut block: InOut<'_, '_, Array<u8, Self::BlockSize>>) {
        let mut b = block.clone_in();
        self.process_block_inplace(&mut b);

        *block.get_out() = b;
    }

    /// Encrypt/decrypt multiple blocks in parrallel using XTS and update the tweak
    fn process_par_blocks_inplace(&mut self, blocks: &mut ParBlocks<Self>) {
        let mut iv_array: ParBlocks<Self> = Default::default();
        {
            let iv = self.get_iv_mut();

            for (b, i) in blocks.iter_mut().zip(iv_array.iter_mut()) {
                *i = iv.clone();
                xor(b, iv);

                let _ = gf_mul(iv);
            }
        }

        self.process_par_inplace(blocks);

        for (b, i) in blocks.iter_mut().zip(iv_array.iter_mut()) {
            xor(b, i);
        }
    }

    fn process_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let mut b = blocks.clone_in();
        self.process_par_blocks_inplace(&mut b);

        *blocks.get_out() = b;
    }

    fn process_tail_blocks_inplace(&mut self, blocks: &mut [Block<Self>]) {
        for b in blocks {
            {
                let iv = self.get_iv_mut();
                xor(b, iv);
            }

            self.process_block_inplace(b);

            let iv = self.get_iv_mut();
            xor(b, iv);

            let _ = gf_mul(iv);
        }
    }

    fn process_tail_blocks(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        for mut block in blocks {
            let mut b = block.clone_in();
            self.process_inplace(&mut b);
            *block.get_out() = b;
        }
    }
}
