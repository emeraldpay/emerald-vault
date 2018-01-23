//! RLP (Recursive Length Prefix) is to encode arbitrarily nested arrays of binary data,
//! RLP is the main encoding method used to serialize objects in Ethereum.
//!
//! See [RLP spec](https://github.com/ethereumproject/wiki/wiki/RLP)

use super::{bytes_count, to_bytes, trim_bytes};

/// The `WriteRLP` trait is used to specify functionality of serializing data to RLP bytes
pub trait WriteRLP {
    /// Writes itself as RLP bytes into specified buffer
    fn write_rlp(&self, buf: &mut Vec<u8>);
}

/// A list serializable to RLP
#[derive(Debug)]
pub struct RLPList {
    tail: Vec<u8>,
}

impl RLPList {
    /// Start with provided vector
    pub fn from_slice<T: WriteRLP>(items: &[T]) -> RLPList {
        let mut start = RLPList { tail: Vec::new() };
        for i in items {
            start.push(i)
        }
        start
    }

    /// Add an item to the list
    pub fn push<T: WriteRLP + ?Sized>(&mut self, item: &T) {
        item.write_rlp(&mut self.tail);
    }
}

impl Default for RLPList {
    fn default() -> RLPList {
        RLPList { tail: Vec::new() }
    }
}

impl Into<Vec<u8>> for RLPList {
    fn into(self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        match self.tail.len() {
            s @ 0...55 => {
                res.push((s + 192) as u8);
                res.extend(self.tail.as_slice());
            }
            v => {
                let sb = to_bytes(v as u64, 8);
                let size_arr = trim_bytes(&sb);
                res.push((size_arr.len() + 247) as u8);
                res.extend(size_arr);
                res.extend(self.tail.as_slice());
            }
        }
        res
    }
}

impl WriteRLP for str {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        let bytes = self.as_bytes();

        if self.len() == 1 && bytes[0] <= 0x7f {
            buf.push(bytes[0]);
        } else {
            bytes.write_rlp(buf);
        }
    }
}

impl WriteRLP for String {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        let bytes = self.as_bytes();

        if self.len() == 1 && bytes[0] <= 0x7f {
            buf.push(bytes[0]);
        } else {
            bytes.write_rlp(buf);
        }
    }
}

impl WriteRLP for u8 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        if *self == 0 {
            buf.push(0x80);
        } else if *self <= 0x7f {
            buf.push(*self);
        } else {
            trim_bytes(&to_bytes(u64::from(*self), 1)).write_rlp(buf);
        }
    }
}

impl WriteRLP for u16 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        if *self == 0 {
            buf.push(0x80);
        } else if *self <= 0x7f {
            buf.push(*self as u8);
        } else {
            trim_bytes(&to_bytes(u64::from(*self), 2)).write_rlp(buf);
        }
    }
}

impl WriteRLP for u32 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        if *self == 0 {
            buf.push(0x80);
        } else if *self <= 0x7f {
            buf.push(*self as u8);
        } else {
            trim_bytes(&to_bytes(u64::from(*self), 4)).write_rlp(buf);
        }
    }
}

impl WriteRLP for u64 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        if *self == 0 {
            buf.push(0x80);
        } else if *self <= 0x7f {
            buf.push(*self as u8);
        } else {
            trim_bytes(&to_bytes(*self, 8)).write_rlp(buf);
        }
    }
}

impl<'a, T: WriteRLP + ?Sized> WriteRLP for Option<&'a T> {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        match *self {
            Some(x) => x.write_rlp(buf),
            None => [].write_rlp(buf),
        };
    }
}

impl<T: WriteRLP> WriteRLP for Vec<T> {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        RLPList::from_slice(self).write_rlp(buf);
    }
}

impl WriteRLP for [u8] {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        let len = self.len();
        if len <= 55 {
            // Otherwise, if a string is 0-55 bytes long, the RLP encoding consists of a single byte
            // with value 0x80 plus the length of the string followed by the string. The range of
            // the first byte is thus [0x80, 0xb7].
            buf.push(0x80 + len as u8);
            buf.extend_from_slice(self);
        } else {
            // If a string is more than 55 bytes long, the RLP encoding consists of a single byte
            // with value 0xb7 plus the length in bytes of the length of the string in binary form,
            // followed by the length of the string, followed by the string. For example, a
            // length-1024 string would be encoded as \xb9\x04\x00 followed by the string. The
            // range of the first byte is thus [0xb8, 0xbf].
            let len_bytes = bytes_count(len);
            buf.push(0xb7 + len_bytes);
            buf.extend_from_slice(&to_bytes(len as u64, len_bytes));
            buf.extend_from_slice(self);
        }
    }
}

impl WriteRLP for RLPList {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        let len = self.tail.len();
        if len <= 55 {
            // If the total payload of a list (i.e. the combined length of all its items) is 0-55
            // bytes long, the RLP encoding consists of a single byte with value 0xc0 plus the
            // length of the list followed by the concatenation of the RLP encodings of the items.
            // The range of the first byte is thus [0xc0, 0xf7].
            buf.push((0xc0 + len) as u8);
        } else {
            // If the total payload of a list is more than 55 bytes long, the RLP encoding consists
            // of a single byte with value 0xf7 plus the length in bytes of the length of the
            // payload in binary form, followed by the length of the payload, followed by the
            // concatenation of the RLP encodings of the items. The range of the first byte is
            // thus [0xf8, 0xff].
            let len_bytes = bytes_count(len);
            buf.push(0xf7 + len_bytes);
            buf.extend_from_slice(&to_bytes(len as u64, len_bytes));
        }
        buf.extend_from_slice(&self.tail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn encode_zero() {
        let mut buf = Vec::new();
        0u8.write_rlp(&mut buf);
        assert_eq!([0x80], buf.as_slice());
    }

    #[test]
    fn encode_smallint() {
        let mut buf = Vec::new();
        1u8.write_rlp(&mut buf);
        assert_eq!([0x01], buf.as_slice());
    }

    #[test]
    fn encode_smallint2() {
        let mut buf = Vec::new();
        16u8.write_rlp(&mut buf);
        assert_eq!([0x10], buf.as_slice());
    }

    #[test]
    fn encode_smallint3() {
        let mut buf = Vec::new();
        79u8.write_rlp(&mut buf);
        assert_eq!([0x4f], buf.as_slice());
    }

    #[test]
    fn encode_smallint4() {
        let mut buf = Vec::new();
        127u8.write_rlp(&mut buf);
        assert_eq!([0x7f], buf.as_slice());
    }

    #[test]
    fn encode_mediumint1() {
        let mut buf = Vec::new();
        128u16.write_rlp(&mut buf);
        assert_eq!([0x81, 0x80], buf.as_slice());
    }

    #[test]
    fn encode_mediumint2() {
        let mut buf = Vec::new();
        1000u16.write_rlp(&mut buf);
        assert_eq!([0x82, 0x03, 0xe8], buf.as_slice());
    }

    #[test]
    fn encode_mediumint3() {
        let mut buf = Vec::new();
        100000u32.write_rlp(&mut buf);
        assert_eq!([0x83, 0x01, 0x86, 0xa0], buf.as_slice());
    }

    #[test]
    fn encode_mediumint4() {
        let mut buf = Vec::new();
        Vec::from_hex("102030405060708090a0b0c0d0e0f2")
            .unwrap()
            .as_slice()
            .write_rlp(&mut buf);
        assert_eq!("8f102030405060708090a0b0c0d0e0f2", buf.to_hex());
    }

    #[test]
    fn encode_mediumint5() {
        let mut buf = Vec::new();
        Vec::from_hex("0100020003000400050006000700080009000a000b000c000d000e01")
            .unwrap()
            .as_slice()
            .write_rlp(&mut buf);
        assert_eq!(
            "9c0100020003000400050006000700080009000a000b000c000d000e01",
            buf.to_hex()
        );
    }

    #[test]
    fn encode_empty_str() {
        let mut buf = Vec::new();
        "".write_rlp(&mut buf);
        assert_eq!([0x80], buf.as_slice());
    }

    #[test]
    fn encode_short_str() {
        let mut buf = Vec::new();
        "dog".write_rlp(&mut buf);
        assert_eq!([0x83, b'd', b'o', b'g'], buf.as_slice());
    }

    #[test]
    fn encode_normal_str() {
        let mut buf = Vec::new();
        "Lorem ipsum dolor sit amet, consectetur adipisicing eli".write_rlp(&mut buf);
        assert_eq!("b74c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e\
                    7365637465747572206164697069736963696e6720656c69",
                   buf.to_hex());
    }

    #[test]
    fn encode_long_str() {
        let mut buf = Vec::new();
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit".write_rlp(&mut buf);
        assert_eq!("b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f\
                    6e7365637465747572206164697069736963696e6720656c6974",
                   buf.to_hex());
    }

    #[test]
    fn encode_extra_long_str() {
        let mut buf = Vec::new();
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur mauris magna, \
         suscipit sed vehicula non, iaculis faucibus tortor. Proin suscipit ultricies malesuada. \
         Duis tortor elit, dictum quis tristique eu, ultrices at risus. Morbi a est imperdiet mi \
         ullamcorper aliquet suscipit nec lorem. Aenean quis leo mollis, vulputate elit varius, \
         consequat enim. Nulla ultrices turpis justo, et posuere urna consectetur nec. Proin non \
         convallis metus. Donec tempor ipsum in mauris congue sollicitudin. Vestibulum ante ipsum \
         primis in faucibus orci luctus et ultrices posuere cubilia Curae; Suspendisse convallis \
         sem vel massa faucibus, eget lacinia lacus tempor. Nulla quis ultricies purus. Proin \
         auctor rhoncus nibh condimentum mollis. Aliquam consequat enim at metus luctus, a \
         eleifend purus egestas. Curabitur at nibh metus. Nam bibendum, neque at auctor \
         tristique, lorem libero aliquet arcu, non interdum tellus lectus sit amet eros. Cras \
         rhoncus, metus ac ornare cursus, dolor justo ultrices metus, at ullamcorper volutpat"
            .write_rlp(&mut buf);
        assert_eq!("b904004c6f72656d20697073756d20646f6c6f722073697420616d65742c2063\
                    6f6e73656374657475722061646970697363696e6720656c69742e2043757261\
                    6269747572206d6175726973206d61676e612c20737573636970697420736564\
                    207665686963756c61206e6f6e2c20696163756c697320666175636962757320\
                    746f72746f722e2050726f696e20737573636970697420756c74726963696573\
                    206d616c6573756164612e204475697320746f72746f7220656c69742c206469\
                    6374756d2071756973207472697374697175652065752c20756c747269636573\
                    2061742072697375732e204d6f72626920612065737420696d70657264696574\
                    206d6920756c6c616d636f7270657220616c6971756574207375736369706974\
                    206e6563206c6f72656d2e2041656e65616e2071756973206c656f206d6f6c6c\
                    69732c2076756c70757461746520656c6974207661726975732c20636f6e7365\
                    7175617420656e696d2e204e756c6c6120756c74726963657320747572706973\
                    206a7573746f2c20657420706f73756572652075726e6120636f6e7365637465\
                    747572206e65632e2050726f696e206e6f6e20636f6e76616c6c6973206d6574\
                    75732e20446f6e65632074656d706f7220697073756d20696e206d6175726973\
                    20636f6e67756520736f6c6c696369747564696e2e20566573746962756c756d\
                    20616e746520697073756d207072696d697320696e206661756369627573206f\
                    726369206c756374757320657420756c74726963657320706f73756572652063\
                    7562696c69612043757261653b2053757370656e646973736520636f6e76616c\
                    6c69732073656d2076656c206d617373612066617563696275732c2065676574\
                    206c6163696e6961206c616375732074656d706f722e204e756c6c6120717569\
                    7320756c747269636965732070757275732e2050726f696e20617563746f7220\
                    72686f6e637573206e69626820636f6e64696d656e74756d206d6f6c6c69732e\
                    20416c697175616d20636f6e73657175617420656e696d206174206d65747573\
                    206c75637475732c206120656c656966656e6420707572757320656765737461\
                    732e20437572616269747572206174206e696268206d657475732e204e616d20\
                    626962656e64756d2c206e6571756520617420617563746f7220747269737469\
                    7175652c206c6f72656d206c696265726f20616c697175657420617263752c20\
                    6e6f6e20696e74657264756d2074656c6c7573206c6563747573207369742061\
                    6d65742065726f732e20437261732072686f6e6375732c206d65747573206163\
                    206f726e617265206375727375732c20646f6c6f72206a7573746f20756c7472\
                    69636573206d657475732c20617420756c6c616d636f7270657220766f6c7574\
                    706174",
                   buf.to_hex());
    }

    #[test]
    fn encode_bytearray() {
        let mut buf = Vec::new();
        [].write_rlp(&mut buf);
        assert_eq!([0x80], buf.as_slice());
    }

    #[test]
    fn encode_single_bytearray() {
        let mut buf = Vec::new();
        [0].write_rlp(&mut buf);
        assert_eq!([0x81, 0x00], buf.as_slice());
    }

    #[test]
    fn encode_bytestring00() {
        let mut buf = Vec::new();
        "\u{0000}".write_rlp(&mut buf);
        assert_eq!([0x00], buf.as_slice());
    }

    #[test]
    fn encode_bytestring01() {
        let mut buf = Vec::new();
        "\u{0001}".write_rlp(&mut buf);
        assert_eq!([0x01], buf.as_slice());
    }

    #[test]
    fn encode_bytestring7f() {
        let mut buf = Vec::new();
        "\u{007f}".write_rlp(&mut buf);
        assert_eq!([0x7f], buf.as_slice());
    }

    #[test]
    fn encode_empty_option() {
        let mut buf = Vec::new();
        let val: Option<&str> = None;
        val.write_rlp(&mut buf);
        assert_eq!([0x80], buf.as_slice())
    }

    #[test]
    fn encode_empty_list() {
        let mut buf = Vec::new();
        let list: Vec<u8> = vec![];
        list.write_rlp(&mut buf);
        assert_eq!([0xc0], buf.as_slice());
    }

    #[test]
    fn encode_simple_list() {
        let mut buf = Vec::new();
        let list = vec!["cat".to_string(), "dog".to_string()];
        list.write_rlp(&mut buf);
        assert_eq!(
            [0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'],
            buf.as_slice()
        );
    }

    #[test]
    fn encode_nested_lists() {
        // [ [], [[]], [ [], [[]] ] ]
        let mut buf = Vec::new();
        let mut list = RLPList::default();
        list.push(&RLPList::default());
        let mut item1 = RLPList::default();
        item1.push(&RLPList::default());
        list.push(&item1);
        let mut item2 = RLPList::default();
        item2.push(&RLPList::default());
        let mut item21 = RLPList::default();
        item21.push(&RLPList::default());
        item2.push(&item21);
        list.push(&item2);
        list.write_rlp(&mut buf);
        assert_eq!(
            [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0],
            buf.as_slice()
        );
    }
}
