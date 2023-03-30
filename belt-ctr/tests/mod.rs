use cipher::{KeyIvInit, StreamCipher};
use hex_literal::hex;
use belt_ctr::BeltCtr;
use belt_ctr::flavor::ctr128::Ctr128;

#[test]
fn belt_ctr_a7() {
    let key = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let iv = hex!("BE329713 43FC9A48 A02A885F 194B09A1");
    let x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
    let y = hex!("52C9AF96 FF50F644 35FC43DE F56BD797 D5B5B1FF 79FB4125 7AB9CDF6 E63E81F8 F0034147 3EAE4098 33622DE0 5213773A");
    let mut buf = x.to_vec();

    let mut ctr: BeltCtr = BeltCtr::new_from_slices(&key, &iv).unwrap();
    ctr.apply_keystream(&mut buf);
    assert_eq!(buf, y);

    ctr.apply_keystream(&mut buf);
    assert_eq!(buf, x);
}

#[test]
fn belt_ctr_a8() {
    let x = hex!("DF181ED0 08A20F43 DCBBB936 50DAD34B 389CDEE5 826D40E2 D4BD80F4 9A93F5D2 12F63331 66456F16 9043CC5F");
    let iv = hex!("7ECDA4D0 1544AF8C A58450BF 66D2E88A");
    let key = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let y = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779");
    let mut buf = y.to_vec();

    let mut ctr: BeltCtr = BeltCtr::new_from_slices(&key, &iv).unwrap();
    ctr.apply_keystream(&mut buf);
    assert_eq!(buf, x);

    ctr.apply_keystream(&mut buf);
    assert_eq!(buf, y);
}