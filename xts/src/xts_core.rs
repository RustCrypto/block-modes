use cipher::typenum::Unsigned;
use cipher::BlockCipherDecrypt;
use cipher::{
    crypto_common::BlockSizes, Array, Block, BlockCipherEncrypt, BlockSizeUser, InOut, InOutBuf,
    ParBlocks, ParBlocksSizeUser,
};

use crate::{Error, Result};

use crate::gf::{gf_mul, gf_reverse_mul};
use crate::xor;

/// Since the traits does not allow using two engines, this is used to pre-compute the IV.
pub fn precompute_iv<BS, BC>(cipher: &BC, iv: &Block<BC>) -> Block<BC>
where
    BS: BlockSizes,
    BC: BlockCipherEncrypt<BlockSize = BS>,
{
    let mut output = iv.clone();
    cipher.encrypt_block(&mut output);
    output
}

/// Core implementation of XTS mode
pub trait Xts: ParBlocksSizeUser + BlockSizeUser {
    /// Method to encrypt/decrypt a single block without mode.
    fn process_inplace(&self, block: &mut Block<Self>); // Array<u8, Self::BlockSize>);

    /// Method to encrypt/decrypt multiple blocks in parallel without mode.
    fn process_par_inplace(&self, blocks: &mut ParBlocks<Self>);

    /// Gets the IV reference.
    fn get_iv_mut(&mut self) -> &mut Array<u8, Self::BlockSize>;

    //Unused but keeping for now just in case
    fn _process(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut b = block.clone_in();
        self.process_inplace(&mut b);

        *block.get_out() = b;
    }

    fn _process_par(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let mut blocks = blocks.clone_in();
        self.process_par_inplace(&mut blocks);
    }

    fn process_block_inplace(&mut self, block: &mut Block<Self>) {
        {
            let iv = self.get_iv_mut();
            xor(block, iv);
        }

        self.process_inplace(block);

        let iv = self.get_iv_mut();
        xor(block, iv);

        gf_mul(iv);
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

                gf_mul(iv);
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
            self.process_block_inplace(&mut b);
            *block.get_out() = b;
        }
    }
}

pub(crate) trait Stealer: BlockSizeUser {
    /// Encrypt/Decrypt the block
    fn process_block(&self, block: &mut Block<Self>);

    /// Gets the IV reference.
    fn get_iv_mut(&mut self) -> &mut Array<u8, Self::BlockSize>;

    /// There is a slight difference regarding the tweak during decryption
    fn is_decrypt() -> bool;

    /// Perform the ciphertext stealing phase
    fn ciphertext_stealing(&mut self, buffer: &mut [u8]) {
        let remaining_bytes = buffer.len() - Self::block_size();

        let second_to_last_block: &mut Block<Self> = (&mut buffer[0..Self::block_size()])
            .try_into()
            .expect("Not a full block on second to last block!");

        if Self::is_decrypt() {
            // We fast forward the multiplication here
            let carry = {
                let mut iv = self.get_iv_mut();
                let carry = gf_mul(&mut iv);

                xor(second_to_last_block, iv);

                carry
            };

            self.process_block(second_to_last_block);

            {
                let iv = self.get_iv_mut();
                xor(second_to_last_block, iv);

                gf_reverse_mul(iv, carry);
            }
        } else {
            // Process normally
            self.process_block(second_to_last_block);
        }

        // We first swap the remaining bytes with the previous block's
        {
            let (previous_block, current_block) = buffer.split_at_mut(Self::block_size());
            previous_block[..remaining_bytes]
                .swap_with_slice(&mut current_block[..remaining_bytes]);
        }

        // We can then decrypt the final block, which is not located at the second to last block
        let second_to_last_block: &mut Block<Self> = (&mut buffer[0..Self::block_size()])
            .try_into()
            .expect("Not a full block on second to last block!");
        self.process_block(second_to_last_block);
    }
}
