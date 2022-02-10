use cipher::{
    consts::U1,
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
    Block, BlockBackend, BlockClosure, BlockSizeUser, ParBlocksSizeUser, StreamBackend,
    StreamClosure,
};

pub(crate) struct Closure1<'a, BS, SC>
where
    BS: ArrayLength<u8>,
    SC: StreamClosure<BlockSize = BS>,
{
    pub(crate) iv: &'a mut GenericArray<u8, BS>,
    pub(crate) f: SC,
}

impl<'a, BS, SC> BlockSizeUser for Closure1<'a, BS, SC>
where
    BS: ArrayLength<u8>,
    SC: StreamClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, SC> BlockClosure for Closure1<'a, BS, SC>
where
    BS: ArrayLength<u8>,
    SC: StreamClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f } = self;
        f.call(&mut Backend { iv, backend });
    }
}

pub(crate) struct Closure2<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    pub(crate) iv: &'a mut GenericArray<u8, BS>,
    pub(crate) f: BC,
}

impl<'a, BS, BC> BlockSizeUser for Closure2<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BC> BlockClosure for Closure2<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f } = self;
        f.call(&mut Backend { iv, backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.backend.proc_block(self.iv.into());
        block.xor_in2out(self.iv);
    }
}

impl<'a, BS, BK> StreamBackend for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        self.backend.proc_block(self.iv.into());
        *block = self.iv.clone();
    }
}
