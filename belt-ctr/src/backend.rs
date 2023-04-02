use cipher::{
    consts::U16, generic_array::GenericArray, Block, BlockBackend, BlockClosure, BlockSizeUser,
    ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
};

struct Backend<'a, B>
where
    B: BlockBackend<BlockSize = U16>,
{
    s: &'a mut u128,
    backend: &'a mut B,
}

impl<'a, B> BlockSizeUser for Backend<'a, B>
where
    B: BlockBackend<BlockSize = U16>,
{
    type BlockSize = B::BlockSize;
}

impl<'a, B> ParBlocksSizeUser for Backend<'a, B>
where
    B: BlockBackend<BlockSize = U16>,
{
    type ParBlocksSize = B::ParBlocksSize;
}

#[inline(always)]
fn next_block(s: &mut u128) -> GenericArray<u8, U16> {
    *s = s.wrapping_add(1);
    s.to_le_bytes().into()
}

impl<'a, B> StreamBackend for Backend<'a, B>
where
    B: BlockBackend<BlockSize = U16>,
{
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let tmp = next_block(self.s);
        self.backend.proc_block((&tmp, block).into());
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut ParBlocks<Self>) {
        let mut tmp = ParBlocks::<Self>::default();
        for block in tmp.iter_mut() {
            *block = next_block(self.s);
        }
        self.backend.proc_par_blocks((&tmp, blocks).into());
    }
}

pub(crate) struct Closure<'a, SC>
where
    SC: StreamClosure<BlockSize = U16>,
{
    pub(crate) s: &'a mut u128,
    pub(crate) f: SC,
}

impl<'a, SC> BlockSizeUser for Closure<'a, SC>
where
    SC: StreamClosure<BlockSize = U16>,
{
    type BlockSize = U16;
}

impl<'a, SC> BlockClosure for Closure<'a, SC>
where
    SC: StreamClosure<BlockSize = U16>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        let Self { s, f } = self;
        f.call(&mut Backend::<B> { s, backend })
    }
}
