use std::borrow::Cow;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .serde_serialized_types(&[
            "WalletBalanceResponse",
            "NewAddressResponse",
            "ListUnspentResponse",
        ])
        .serde_serialized_type("TransactionOutput", &[rev_hex("txId"), hex("scriptPubKey")])
        .serde_serialized_type(
            "ConfEvent",
            &[
                opt_hex("rawTx"),
                enum_field("confidenceType", "ConfidenceType"),
            ],
        )
        .serde_serialized_type("ConfirmationBlockTime", &[rev_hex("blockHash")])
        .serde_serialized_enum("ConfidenceType")
        .compile_protos(
            &[
                "src/main/proto/rpc.proto",
                "src/main/proto/wallet.proto",
                "src/main/proto/bmp_protocol.proto",
            ],
            &["src/main/proto"],
        )?;
    Ok(())
}

type CustomField<'a> = (&'a str, Cow<'static, str>);

const fn hex(field: &str) -> CustomField {
    (
        field,
        Cow::Borrowed("#[serde_as(as = \"::serde_with::hex::Hex\")]"),
    )
}

const fn rev_hex(field: &str) -> CustomField {
    (
        field,
        Cow::Borrowed("#[serde_as(as = \"crate::pb::convert::hex::ByteReversedHex\")]"),
    )
}

const fn opt_hex(field: &str) -> CustomField {
    (
        field,
        Cow::Borrowed("#[serde_as(as = \"::core::option::Option<::serde_with::hex::Hex>\")]"),
    )
}

fn enum_field<'a>(field: &'a str, type_name: &'_ str) -> CustomField<'a> {
    (
        field,
        Cow::Owned(format!(
            "#[serde_as(as = \"::serde_with::TryFromInto<{type_name}>\")]"
        )),
    )
}

trait BuilderEx {
    fn serde_serialized_enum(self, path: &str) -> Self;

    fn serde_serialized_type(self, path: &str, custom_fields: &[CustomField]) -> Self;

    fn serde_serialized_types(mut self, paths: &[&str]) -> Self
    where
        Self: Sized,
    {
        for &path in paths {
            self = self.serde_serialized_type(path, &[]);
        }
        self
    }
}

impl BuilderEx for tonic_build::Builder {
    fn serde_serialized_enum(self, path: &str) -> Self {
        self.enum_attribute(path, "#[derive(::serde::Serialize)]")
            .enum_attribute(path, "#[serde(rename_all = \"SCREAMING_SNAKE_CASE\")]")
    }

    fn serde_serialized_type(mut self, path: &str, custom_fields: &[CustomField]) -> Self {
        self = self
            .type_attribute(path, "#[::serde_with::serde_as]")
            .type_attribute(path, "#[derive(::serde::Serialize)]")
            .type_attribute(path, "#[serde(rename_all = \"camelCase\")]");
        for (field, attribute) in custom_fields {
            self = self.field_attribute(format!("{path}.{field}"), attribute);
        }
        self
    }
}
