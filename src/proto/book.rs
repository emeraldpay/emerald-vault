// This file is generated by rust-protobuf 2.8.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `book.proto`

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_8_1;

#[derive(PartialEq,Clone,Default)]
pub struct BookItem {
    // message fields
    pub file_type: super::common::FileType,
    pub label: ::std::string::String,
    pub description: ::std::string::String,
    pub blockchain: u32,
    pub address: ::protobuf::SingularPtrField<super::address::Address>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a BookItem {
    fn default() -> &'a BookItem {
        <BookItem as ::protobuf::Message>::default_instance()
    }
}

impl BookItem {
    pub fn new() -> BookItem {
        ::std::default::Default::default()
    }

    // .emerald.vault.FileType file_type = 1;


    pub fn get_file_type(&self) -> super::common::FileType {
        self.file_type
    }
    pub fn clear_file_type(&mut self) {
        self.file_type = super::common::FileType::FILE_UNKNOWN;
    }

    // Param is passed by value, moved
    pub fn set_file_type(&mut self, v: super::common::FileType) {
        self.file_type = v;
    }

    // string label = 2;


    pub fn get_label(&self) -> &str {
        &self.label
    }
    pub fn clear_label(&mut self) {
        self.label.clear();
    }

    // Param is passed by value, moved
    pub fn set_label(&mut self, v: ::std::string::String) {
        self.label = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_label(&mut self) -> &mut ::std::string::String {
        &mut self.label
    }

    // Take field
    pub fn take_label(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.label, ::std::string::String::new())
    }

    // string description = 3;


    pub fn get_description(&self) -> &str {
        &self.description
    }
    pub fn clear_description(&mut self) {
        self.description.clear();
    }

    // Param is passed by value, moved
    pub fn set_description(&mut self, v: ::std::string::String) {
        self.description = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_description(&mut self) -> &mut ::std::string::String {
        &mut self.description
    }

    // Take field
    pub fn take_description(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.description, ::std::string::String::new())
    }

    // uint32 blockchain = 4;


    pub fn get_blockchain(&self) -> u32 {
        self.blockchain
    }
    pub fn clear_blockchain(&mut self) {
        self.blockchain = 0;
    }

    // Param is passed by value, moved
    pub fn set_blockchain(&mut self, v: u32) {
        self.blockchain = v;
    }

    // .emerald.vault.Address address = 5;


    pub fn get_address(&self) -> &super::address::Address {
        self.address.as_ref().unwrap_or_else(|| super::address::Address::default_instance())
    }
    pub fn clear_address(&mut self) {
        self.address.clear();
    }

    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    // Param is passed by value, moved
    pub fn set_address(&mut self, v: super::address::Address) {
        self.address = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_address(&mut self) -> &mut super::address::Address {
        if self.address.is_none() {
            self.address.set_default();
        }
        self.address.as_mut().unwrap()
    }

    // Take field
    pub fn take_address(&mut self) -> super::address::Address {
        self.address.take().unwrap_or_else(|| super::address::Address::new())
    }
}

impl ::protobuf::Message for BookItem {
    fn is_initialized(&self) -> bool {
        for v in &self.address {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_proto3_enum_with_unknown_fields_into(wire_type, is, &mut self.file_type, 1, &mut self.unknown_fields)?
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.label)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.description)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.blockchain = tmp;
                },
                5 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.address)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if self.file_type != super::common::FileType::FILE_UNKNOWN {
            my_size += ::protobuf::rt::enum_size(1, self.file_type);
        }
        if !self.label.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.label);
        }
        if !self.description.is_empty() {
            my_size += ::protobuf::rt::string_size(3, &self.description);
        }
        if self.blockchain != 0 {
            my_size += ::protobuf::rt::value_size(4, self.blockchain, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.address.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if self.file_type != super::common::FileType::FILE_UNKNOWN {
            os.write_enum(1, self.file_type.value())?;
        }
        if !self.label.is_empty() {
            os.write_string(2, &self.label)?;
        }
        if !self.description.is_empty() {
            os.write_string(3, &self.description)?;
        }
        if self.blockchain != 0 {
            os.write_uint32(4, self.blockchain)?;
        }
        if let Some(ref v) = self.address.as_ref() {
            os.write_tag(5, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> BookItem {
        BookItem::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeEnum<super::common::FileType>>(
                    "file_type",
                    |m: &BookItem| { &m.file_type },
                    |m: &mut BookItem| { &mut m.file_type },
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "label",
                    |m: &BookItem| { &m.label },
                    |m: &mut BookItem| { &mut m.label },
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "description",
                    |m: &BookItem| { &m.description },
                    |m: &mut BookItem| { &mut m.description },
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "blockchain",
                    |m: &BookItem| { &m.blockchain },
                    |m: &mut BookItem| { &mut m.blockchain },
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<super::address::Address>>(
                    "address",
                    |m: &BookItem| { &m.address },
                    |m: &mut BookItem| { &mut m.address },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<BookItem>(
                    "BookItem",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static BookItem {
        static mut instance: ::protobuf::lazy::Lazy<BookItem> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const BookItem,
        };
        unsafe {
            instance.get(BookItem::new)
        }
    }
}

impl ::protobuf::Clear for BookItem {
    fn clear(&mut self) {
        self.file_type = super::common::FileType::FILE_UNKNOWN;
        self.label.clear();
        self.description.clear();
        self.blockchain = 0;
        self.address.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for BookItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BookItem {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\nbook.proto\x12\remerald.vault\x1a\raddress.proto\x1a\x0ccommon.proto\
    \"\xca\x01\n\x08BookItem\x124\n\tfile_type\x18\x01\x20\x01(\x0e2\x17.eme\
    rald.vault.FileTypeR\x08fileType\x12\x14\n\x05label\x18\x02\x20\x01(\tR\
    \x05label\x12\x20\n\x0bdescription\x18\x03\x20\x01(\tR\x0bdescription\
    \x12\x1e\n\nblockchain\x18\x04\x20\x01(\rR\nblockchain\x120\n\x07address\
    \x18\x05\x20\x01(\x0b2\x16.emerald.vault.AddressR\x07addressJ\xdd\x02\n\
    \x06\x12\x04\0\0\x0b\x01\n\x08\n\x01\x0c\x12\x03\0\0\x12\n\x08\n\x01\x02\
    \x12\x03\x01\0\x16\n\t\n\x02\x03\0\x12\x03\x02\0\x17\n\t\n\x02\x03\x01\
    \x12\x03\x03\0\x16\n\n\n\x02\x04\0\x12\x04\x05\0\x0b\x01\n\n\n\x03\x04\0\
    \x01\x12\x03\x05\x08\x10\n\x0b\n\x04\x04\0\x02\0\x12\x03\x06\x04\x1b\n\
    \x0c\n\x05\x04\0\x02\0\x06\x12\x03\x06\x04\x0c\n\x0c\n\x05\x04\0\x02\0\
    \x01\x12\x03\x06\r\x16\n\x0c\n\x05\x04\0\x02\0\x03\x12\x03\x06\x19\x1a\n\
    \x0b\n\x04\x04\0\x02\x01\x12\x03\x07\x04\x15\n\x0c\n\x05\x04\0\x02\x01\
    \x05\x12\x03\x07\x04\n\n\x0c\n\x05\x04\0\x02\x01\x01\x12\x03\x07\x0b\x10\
    \n\x0c\n\x05\x04\0\x02\x01\x03\x12\x03\x07\x13\x14\n\x0b\n\x04\x04\0\x02\
    \x02\x12\x03\x08\x04\x1b\n\x0c\n\x05\x04\0\x02\x02\x05\x12\x03\x08\x04\n\
    \n\x0c\n\x05\x04\0\x02\x02\x01\x12\x03\x08\x0b\x16\n\x0c\n\x05\x04\0\x02\
    \x02\x03\x12\x03\x08\x19\x1a\n\x0b\n\x04\x04\0\x02\x03\x12\x03\t\x04\x1a\
    \n\x0c\n\x05\x04\0\x02\x03\x05\x12\x03\t\x04\n\n\x0c\n\x05\x04\0\x02\x03\
    \x01\x12\x03\t\x0b\x15\n\x0c\n\x05\x04\0\x02\x03\x03\x12\x03\t\x18\x19\n\
    \x0b\n\x04\x04\0\x02\x04\x12\x03\n\x04\x18\n\x0c\n\x05\x04\0\x02\x04\x06\
    \x12\x03\n\x04\x0b\n\x0c\n\x05\x04\0\x02\x04\x01\x12\x03\n\x0c\x13\n\x0c\
    \n\x05\x04\0\x02\x04\x03\x12\x03\n\x16\x17b\x06proto3\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}