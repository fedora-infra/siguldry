//! A serde serializer for the sigul format.
//!
//! The sigul format as it is defined in the Python implementation supports a
//! minimal number of data types. These are:
//!
//! - boolean: serialized to a u8
//! - integers: serialized as a u32
//! - str: serialized to a UTF-8 array of bytes
//! - bytes: Sent as-is
//!
//! Type information is not included explicitly in the format; instead there is an
//! "op" field that names the remote function being called and it knows what its
//! expected argument types are. Because of this, it's not possible to cleanly
//! round-trip this format between this format's serializer and deserializer.
//!
//! This implementation has opted to serialize integer types larger than 32 bits
//! as well as floats to a byte array. The unit type, options, and compound
//! types other than `Map` are also not supported.
//!
//! # Map
//!
//! The map type has a few additional restrictions.
//!
//! - Keys must be strings that are less than 256 bytes long when encoded to UTF-8.
//! - Values must be less than 256 bytes long.
//!
//! Additionally, the map must have a known length when serializing.
use serde::{ser, Serialize};

use super::{Error, Result};

pub struct Serializer {
    output: Vec<u8>,
}

/// Return a [`Vec<u8>`] with the serialized value.
///
///
/// # Example
///
/// ```ignore
/// use std::collections::HashMap;
/// use siguldry::serdes::{to_bytes, Result};
///
/// # fn main() -> Result<()> {
/// let mut map = HashMap::new();
/// map.insert("op", "pe-sign");
/// map.insert("user", "my_user");
/// map.insert("key", "my-signing-key-name");
/// map.insert("cert-name", "signing-cert-name");
///
/// let bytes = to_bytes(&map)?;
/// # Ok(())
/// # }
/// ```
pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut serializer = Serializer { output: Vec::new() };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

fn size_of<F>() -> Result<u8> {
    let field_size = std::mem::size_of::<F>();
    if field_size > 255 {
        Err(Error::FieldSize)
    } else {
        Ok(field_size as u8)
    }
}

impl ser::Serializer for &mut Serializer {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u8>()?);
        self.output.push(if v { 1_u8 } else { 0_u8 });
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u32>()?);
        for byte in (v as u32).to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_i16(self, v: i16) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u32>()?);
        for byte in (v as u32).to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_i32(self, v: i32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u32>()?);
        for byte in (v as u32).to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_i64(self, v: i64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<i64>()?);
        for byte in v.to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_u8(self, v: u8) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(v);
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u32>()?);
        for byte in (v as u32).to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_u32(self, v: u32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u32>()?);
        for byte in v.to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_u64(self, v: u64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<u64>()?);
        for byte in v.to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_f32(self, v: f32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<f32>()?);
        for byte in v.to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_f64(self, v: f64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.push(size_of::<f64>()?);
        for byte in v.to_be_bytes() {
            self.output.push(byte);
        }

        Ok(())
    }

    fn serialize_char(self, v: char) -> std::result::Result<Self::Ok, Self::Error> {
        let mut buf = [0; 4];
        let v = v.encode_utf8(&mut buf);
        self.serialize_str(v)
    }

    fn serialize_str(self, v: &str) -> std::result::Result<Self::Ok, Self::Error> {
        self.serialize_bytes(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> std::result::Result<Self::Ok, Self::Error> {
        if v.len() > 255 {
            return Err(Error::FieldSize);
        }

        self.output.push(v.len() as u8);
        for byte in v.iter() {
            self.output.push(*byte);
        }

        Ok(())
    }

    fn serialize_map(
        self,
        len: Option<usize>,
    ) -> std::result::Result<Self::SerializeMap, Self::Error> {
        let len = len.ok_or(Error::FieldCount)?;
        if len > 255 {
            Err(Error::FieldCount)
        } else {
            self.output.push(len as u8);
            Ok(self)
        }
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeStruct, Self::Error> {
        // The name is serialized as the op. Yes it's gross.
        let len = len + 1;
        if len > 255 {
            Err(Error::FieldCount)
        } else {
            self.output.push(len as u8);
            let mut parts = vec![];
            for char in name.chars() {
                if char.is_ascii_uppercase() {
                    let part = String::from(char.to_ascii_lowercase());
                    parts.push(part);
                } else {
                    parts
                        .last_mut()
                        .map(|s| s.push(char))
                        .unwrap_or_else(|| parts.push(String::from(char)));
                }
            }
            let op_name = parts.join("-");
            self.serialize_str("op")?;
            self.serialize_str(&op_name)?;
            Ok(self)
        }
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeStructVariant, Self::Error> {
        self.serialize_struct(variant, len)
    }

    //  The remaining fns are for types we don't support and all return errors.  //
    ///////////////////////////////////////////////////////////////////////////////

    /// Optional types aren't really supported, for structures with Options they _must_
    /// be marked with `#[serde(skip_serializing_if = "Option::is_none")]`
    fn serialize_none(self) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_some<T>(self, value: &T) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_unit_struct(
        self,
        _name: &'static str,
    ) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn serialize_seq(
        self,
        len: Option<usize>,
    ) -> std::result::Result<Self::SerializeSeq, Self::Error> {
        if let Some(len) = len {
            if len > 255 {
                return Err(Error::FieldSize);
            }
            self.output.push(len as u8);
            Ok(self)
        } else {
            Err(Error::UnsupportedType)
        }
    }

    fn serialize_tuple(
        self,
        _len: usize,
    ) -> std::result::Result<Self::SerializeTuple, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> std::result::Result<Self::SerializeTupleStruct, Self::Error> {
        Err(Error::UnsupportedType)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> std::result::Result<Self::SerializeTupleVariant, Self::Error> {
        Err(Error::UnsupportedType)
    }
}

impl ser::SerializeStruct for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let fixed_key = key.replace('_', "-");
        fixed_key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let fixed_key = key.replace('_', "-");
        fixed_key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeMap for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        // TODO: keys must be strings, implement a separate serialized to enforce this.
        key.serialize(&mut **self)
    }

    fn serialize_value<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// The remaining impls are for types we don't support and all return errors. //
///////////////////////////////////////////////////////////////////////////////

impl ser::SerializeSeq for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTuple for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }
}

impl ser::SerializeTupleStruct for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }
}

impl ser::SerializeTupleVariant for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pyo3::{
        prelude::*,
        types::{IntoPyDict, PyDict},
    };
    use serde::Serialize;

    // The reference Python implementation.
    const SIGUL: &str = include_str!("serde.py");

    #[test]
    fn serialize_map_matches_python() -> anyhow::Result<()> {
        let mut fields = HashMap::new();
        fields.insert("op", "pe-sign");
        fields.insert("user", "example_user");
        fields.insert("key", "my-key-name");
        fields.insert("cert-name", "my-cert-name");

        let rust_result = super::to_bytes(&fields)?;

        Python::attach(|py| {
            let code = std::ffi::CString::new(SIGUL)?;
            let sigul = PyModule::from_code(py, &code, c"serde.py", c"serde")?;
            let format_fields = sigul.getattr("format_fields")?;
            let fields = fields.into_py_dict(py)?;

            let python_result = format_fields
                .call1((fields,))
                .map(|bytes| bytes.extract::<Vec<u8>>())??;

            assert_eq!(rust_result, python_result);

            Ok(())
        })
    }

    #[test]
    fn serialize_struct_variant() -> anyhow::Result<()> {
        #[derive(Serialize)]
        enum Ops {
            SignPe {
                user: String,
                key: String,
                cert_name: String,
            },
        }

        let op = Ops::SignPe {
            user: "my-user".to_string(),
            key: "my-key-name".to_string(),
            cert_name: "my-cert-name".to_string(),
        };

        let rust_result = super::to_bytes(&op)?;

        Python::attach(|py| {
            let code = std::ffi::CString::new(SIGUL)?;
            let sigul = PyModule::from_code(py, &code, c"serde.py", c"serde")?;
            let format_fields = sigul.getattr("format_fields")?;
            let fields = PyDict::new(py);
            fields.set_item("op", "sign-pe")?;
            fields.set_item("user", "my-user")?;
            fields.set_item("key", "my-key-name")?;
            fields.set_item("cert-name", "my-cert-name")?;
            let fields = fields.into_py_dict(py)?;

            let python_result = format_fields
                .call1((fields,))
                .map(|bytes| bytes.extract::<Vec<u8>>())??;

            assert_eq!(rust_result, python_result);

            Ok(())
        })
    }

    #[test]
    fn serialize_mixed_types() -> anyhow::Result<()> {
        #[derive(Serialize)]
        enum Ops {
            SignSomethingElse { a_bool: bool, int: u32 },
        }

        let op = Ops::SignSomethingElse {
            a_bool: true,
            int: 2_000_000,
        };

        let rust_result = super::to_bytes(&op)?;

        Python::attach(|py| {
            let code = std::ffi::CString::new(SIGUL)?;
            let sigul = PyModule::from_code(py, &code, c"serde.py", c"serde")?;
            let format_fields = sigul.getattr("format_fields")?;
            let fields = PyDict::new(py);
            fields.set_item("op", "sign-something-else")?;
            fields.set_item("a-bool", true)?;
            fields.set_item("int", 2_000_000)?;
            let fields = fields.into_py_dict(py)?;

            let python_result = format_fields
                .call1((fields,))
                .map(|bytes| bytes.extract::<Vec<u8>>())??;

            assert_eq!(rust_result, python_result);

            Ok(())
        })
    }

    #[test]
    fn serialize_optional_types() -> anyhow::Result<()> {
        #[derive(Serialize)]
        enum Ops {
            SignSomethingElse {
                #[serde(skip_serializing_if = "Option::is_none")]
                a_bool: Option<bool>,
                #[serde(skip_serializing_if = "Option::is_none")]
                a_string: Option<String>,
            },
        }

        let op = Ops::SignSomethingElse {
            a_bool: None,
            a_string: Some("string".to_string()),
        };

        let rust_result = super::to_bytes(&op)?;

        // There should only be one serialized field.
        Python::attach(|py| {
            let code = std::ffi::CString::new(SIGUL)?;
            let sigul = PyModule::from_code(py, &code, c"serde.py", c"serde")?;
            let format_fields = sigul.getattr("format_fields")?;
            let fields = PyDict::new(py);
            fields.set_item("op", "sign-something-else")?;
            fields.set_item("a-string", "string")?;
            let fields = fields.into_py_dict(py)?;

            let python_result = format_fields
                .call1((fields,))
                .map(|bytes| bytes.extract::<Vec<u8>>())??;

            assert_eq!(rust_result, python_result);

            Ok(())
        })
    }
}
