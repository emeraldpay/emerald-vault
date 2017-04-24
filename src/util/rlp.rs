//! The purpose of RLP (Recursive Length Prefix) is to encode arbitrarily nested arrays of binary
//! data, and RLP is the main encoding method used to serialize objects in Ethereum. The only
//! purpose of RLP is to encode structure; encoding specific atomic data types (eg. strings, ints,
//! floats) is left up to higher-order protocols; in Ethereum integers must be represented in big
//! endian binary form with no leading zeroes (thus making the integer value zero be equivalent to
//! the empty byte array).
//!
//! See [RLP spec](https://github.com/ethereumproject/wiki/wiki/RLP)

/// A list serializable to RLP
pub struct RLPList {
    tail: Vec<u8>,
}

impl RLPList {
    /// start with provided vector
    pub fn from_slice<T: WriteRLP>(items: &[T]) -> RLPList {
        let mut start = RLPList { tail: Vec::new() };
        for i in items {
            start.push(i)
        }
        start
    }

    /// add an item to the list
    pub fn push<T: WriteRLP>(&mut self, item: &T) {
        item.write_rlp(&mut self.tail);
    }
}

impl Default for RLPList {
    fn default() -> RLPList {
        RLPList { tail: Vec::new() }
    }
}

/// The `WriteRLP` trait is used to specify functionality of serializing data to RLP bytes
pub trait WriteRLP {
    /// Writes itself as RLP bytes into specified buffer
    fn write_rlp(&self, buf: &mut Vec<u8>);
}

impl WriteRLP for str {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        self.as_bytes().write_rlp(buf)
    }
}

impl WriteRLP for String {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        self.as_bytes().write_rlp(buf)
    }
}

impl WriteRLP for u8 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        to_bytes(*self as usize, 1).as_slice().write_rlp(buf)
    }
}

impl WriteRLP for u16 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        to_bytes(*self as usize, 2).as_slice().write_rlp(buf)
    }
}

impl WriteRLP for u32 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        to_bytes(*self as usize, 4).as_slice().write_rlp(buf)
    }
}

impl WriteRLP for u64 {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        to_bytes(*self as usize, 8).as_slice().write_rlp(buf)
    }
}

impl<T: WriteRLP> WriteRLP for Vec<T> {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        RLPList::from_slice(self).write_rlp(buf);
    }
}

impl WriteRLP for [u8; 32] {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        RLPList::from_slice(self).write_rlp(buf);
    }
}

impl WriteRLP for [u8] {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        let len = self.len();

        // For a single byte whose value is in the [0x00, 0x7f] range,
        // that byte is its own RLP encoding.
        if len == 1 && self[0] < 0x7f {
            buf.push(self[0])
        } else if len <= 55 {
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
            for x in 0..len_bytes {
                buf.push((0xff & (len >> (8 * x))) as u8);
            }
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
            let len_data = to_bytes(len, len_bytes);
            buf.extend_from_slice(len_data.as_slice());
        }
        buf.extend_from_slice(self.tail.as_slice());
    }
}

impl<T: WriteRLP> WriteRLP for Option<T> {
    fn write_rlp(&self, buf: &mut Vec<u8>) {
        match *self {
            Some(ref x) => x.write_rlp(buf),
            None => [].write_rlp(buf),
        }
    }
}

fn bytes_count(x: usize) -> u8 {
    match x {
        _ if x > 0xff => 1 + bytes_count(x >> 8),
        _ if x > 0 => 1,
        _ => 0,
    }
}

fn to_bytes(x: usize, b_len: u8) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(b_len as usize);
    for i in 0..b_len {
        let u = (x >> ((b_len - i - 1) * 8)) & 0xff;
        buf.push(u as u8);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::tests::*;

    #[test]
    fn u8_to_bytes() {
        assert_eq!([1], to_bytes(1, 1).as_slice());
        assert_eq!([2], to_bytes(2, 1).as_slice());
        assert_eq!([127], to_bytes(127, 1).as_slice());
        assert_eq!([128], to_bytes(128, 1).as_slice());
        assert_eq!([255], to_bytes(255, 1).as_slice());
    }

    #[test]
    fn u16_to_bytes() {
        assert_eq!([0, 1], to_bytes(1, 2).as_slice());
        assert_eq!([0, 2], to_bytes(2, 2).as_slice());
        assert_eq!([0, 255], to_bytes(255, 2).as_slice());
        assert_eq!([1, 0], to_bytes(256, 2).as_slice());
        assert_eq!([0x12, 0x34], to_bytes(0x1234, 2).as_slice());
        assert_eq!([0xff, 0xff], to_bytes(0xffff, 2).as_slice());
    }

    #[test]
    fn u32_to_bytes() {
        assert_eq!([0, 0, 0, 1], to_bytes(1, 4).as_slice());
        assert_eq!([0x12, 0x34, 0x56, 0x78], to_bytes(0x12345678, 4).as_slice());
        assert_eq!([0xff, 0x0, 0x0, 0x0], to_bytes(0xff000000, 4).as_slice());
        assert_eq!([0x00, 0xff, 0x0, 0x0], to_bytes(0x00ff0000, 4).as_slice());
    }

    #[test]
    fn encode_str() {
        let mut buf = Vec::new();
        "dog".write_rlp(&mut buf);
        assert_eq!([0x83, b'd', b'o', b'g'], buf.as_slice());
    }

    #[test]
    fn encode_list() {
        {
            let mut buf = Vec::new();
            let list = vec!["cat".to_string(), "dog".to_string()];
            list.write_rlp(&mut buf);
            assert_eq!([0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'],
                       buf.as_slice());
        }

        {
            let mut buf = Vec::new();
            let list: Vec<u8> = vec![];
            list.write_rlp(&mut buf);
            assert_eq!([0xc0], buf.as_slice());
        }

        {
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
            assert_eq!([0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0],
                       buf.as_slice());
        }
    }

    #[test]
    fn encode_empty() {
        let mut buf = Vec::new();
        let val: Option<String> = None;
        val.write_rlp(&mut buf);
        assert_eq!([0x80], buf.as_slice())
    }

    #[test]
    fn encode_number() {
        {
            let mut buf = Vec::new();
            let val = 0x0f as u8;
            val.write_rlp(&mut buf);
            assert_eq!([0x0f], buf.as_slice())
        }

        {
            let mut buf = Vec::new();
            let val = 0x0400 as u16;
            val.write_rlp(&mut buf);
            assert_eq!([0x82, 0x04, 0x00], buf.as_slice())
        }
    }
}
