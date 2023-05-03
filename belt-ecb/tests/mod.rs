use belt_block::BeltBlock;
use belt_ecb::{BufDecryptor, BufEncryptor};
use cipher::KeyInit;
use hex_literal::hex;

#[test]
fn test_enc() {
    let key = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let mut x1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
    let y1 = hex!("69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E 5F23102E F1097107 75017F73 806DA9DC 46FB2ED2 CE771F26 DCB5E5D1 569F9AB0");

    let mut x2 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B89");
    let y2 = hex!("69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E 36F00CFE D6D1CA14 98C12798 F4BEB207 5F23102E F1097107 75017F73 806DA9");

    let mut encryptor = BufEncryptor::<BeltBlock>::new_from_slice(&key).unwrap();
    for (pt, ct) in [(&mut x1[..], &y1[..]), (&mut x2[..], &y2[..])] {
        encryptor.encrypt(pt);
        assert_eq!(pt, ct);
    }
}

#[test]
fn test_dec() {
    let key = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let mut y1 = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779 9EB23D31");
    let x1 = hex!("0DC53006 00CAB840 B38448E5 E993F421 E55A239F 2AB5C5D5 FDB6E81B 40938E2A 54120CA3 E6E19C7A D750FC35 31DAEAB7");

    let mut y2 =
        hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B");
    let x2 =
        hex!("0DC53006 00CAB840 B38448E5 E993F421 5780A6E2 B69EAFBB 258726D7 B6718523 E55A239F");

    let mut decryptor = BufDecryptor::<BeltBlock>::new_from_slice(&key).unwrap();
    for (ct, pt) in [(&mut y1[..], &x1[..]), (&mut y2[..], &x2[..])] {
        decryptor.decrypt(ct);
        assert_eq!(ct, pt);
    }
}
