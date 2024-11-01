//! Test vectors from STB 34.101.31-2020 (section А.4, tables A.9-10):
//! https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
use belt_block::BeltBlock;
use cts::{Decrypt, Encrypt, KeyInit};
use hex_literal::hex;

type BeltEcb = cts::EcbCs2<BeltBlock>;

struct TestVector {
    key: &'static [u8; 32],
    pt: &'static [u8],
    ct: &'static [u8],
}

static TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: &hex!(
            "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647"
            "06075316 ED247A37 39CBA383 03A98BF6"
        ),
        pt: &hex!(
            "B194BAC8 0A08F53B 366D008E 584A5DE4"
            "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
            "5BE3D612 17B96181 FE6786AD 716B890B"
        ),
        ct: &hex!(
            "69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E"
            "5F23102E F1097107 75017F73 806DA9DC"
            "46FB2ED2 CE771F26 DCB5E5D1 569F9AB0"
        ),
    },
    TestVector {
        key: &hex!(
            "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647"
            "06075316 ED247A37 39CBA383 03A98BF6"
        ),
        pt: &hex!(
            "B194BAC8 0A08F53B 366D008E 584A5DE4"
            "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
            "5BE3D612 17B96181 FE6786AD 716B89"
        ),
        ct: &hex!(
            "69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E"
            "36F00CFE D6D1CA14 98C12798 F4BEB207"
            "5F23102E F1097107 75017F73 806DA9"
        ),
    },
    TestVector {
        key: &hex!(
            "92BD9B1C E5D14101 5445FBC9 5E4D0EF2"
            "682080AA 227D642F 2687F934 90405511"
        ),
        pt: &hex!(
            "0DC53006 00CAB840 B38448E5 E993F421"
            "E55A239F 2AB5C5D5 FDB6E81B 40938E2A"
            "54120CA3 E6E19C7A D750FC35 31DAEAB7"
        ),
        ct: &hex!(
            "E12BDC1A E28257EC 703FCCF0 95EE8DF1"
            "C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
            "F33C657B 637C306A DD4EA779 9EB23D31"
        ),
    },
    TestVector {
        key: &hex!(
            "92BD9B1C E5D14101 5445FBC9 5E4D0EF2"
            "682080AA 227D642F 2687F934 90405511"
        ),
        pt: &hex!(
            "0DC53006 00CAB840 B38448E5 E993F421"
            "5780A6E2 B69EAFBB 258726D7 B6718523"
            "E55A239F"
        ),
        ct: &hex!(
            "E12BDC1A E28257EC 703FCCF0 95EE8DF1"
            "C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
            "F33C657B"
        ),
    },
];

#[test]
fn belt_ecb() {
    let mut buf = [0u8; 48];
    for &TestVector { key, pt, ct } in TEST_VECTORS {
        let buf = &mut buf[..pt.len()];
        BeltEcb::new(key.into()).encrypt_b2b(pt, buf).unwrap();
        assert_eq!(buf, ct);

        BeltEcb::new(key.into()).decrypt(buf).unwrap();
        assert_eq!(buf, pt);
    }
}
