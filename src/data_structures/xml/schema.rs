//! Module to read the static schema and to prodive some functionalities in the
//! structure
//!
//! Use the object [OnceLock] to create the structure only once from the static string. Action is thread safe

use crate::resources;
use anyhow::{anyhow, Context, Result};
use roxmltree::{Document, Node as RoNode};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::OnceLock;

static SCHEMA_CELL_ECH_0006: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0007: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0008: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0010: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0044: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0058: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0110: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0155: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_0222: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_DECRYPT: OnceLock<Schema> = OnceLock::new();
static SCHEMA_CELL_ECH_CONFIG: OnceLock<Schema> = OnceLock::new();

const XML_SCHEMA_URI: &str = "http://www.w3.org/2001/XMLSchema";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Enumarate for the kind of schemas.
pub enum SchemaKind {
    ech_0006,
    ech_0007,
    ech_0008,
    ech_0010,
    ech_0044,
    ech_0058,
    ech_0110,
    ech_0155,
    ech_0222,
    decrypt,
    config,
}

/// Schema containing the structure of the schema
pub struct Schema<'a> {
    document: Document<'a>,
    schema_kind: SchemaKind,
    target_namespace_name: String,
    target_namespace_uri: String,
    xml_schema_name: String,
    namespaces: HashMap<String, String>,
}

impl SchemaKind {
    /// Get the schema structure
    pub fn get_schema(&self) -> &Schema {
        match self {
            SchemaKind::ech_0006 => {
                SCHEMA_CELL_ECH_0006.get_or_init(|| Schema::new(self, resources::XSD_ECH_0006))
            }
            SchemaKind::ech_0007 => {
                SCHEMA_CELL_ECH_0007.get_or_init(|| Schema::new(self, resources::XSD_ECH_0007))
            }
            SchemaKind::ech_0008 => {
                SCHEMA_CELL_ECH_0008.get_or_init(|| Schema::new(self, resources::XSD_ECH_0008))
            }
            SchemaKind::ech_0010 => {
                SCHEMA_CELL_ECH_0010.get_or_init(|| Schema::new(self, resources::XSD_ECH_0010))
            }
            SchemaKind::ech_0044 => {
                SCHEMA_CELL_ECH_0044.get_or_init(|| Schema::new(self, resources::XSD_ECH_0044))
            }
            SchemaKind::ech_0058 => {
                SCHEMA_CELL_ECH_0058.get_or_init(|| Schema::new(self, resources::XSD_ECH_0058))
            }
            SchemaKind::ech_0110 => {
                SCHEMA_CELL_ECH_0110.get_or_init(|| Schema::new(self, resources::XSD_ECH_0110))
            }
            SchemaKind::ech_0155 => {
                SCHEMA_CELL_ECH_0155.get_or_init(|| Schema::new(self, resources::XSD_ECH_0155))
            }
            SchemaKind::ech_0222 => {
                SCHEMA_CELL_ECH_0222.get_or_init(|| Schema::new(self, resources::XSD_ECH_0222))
            }
            SchemaKind::decrypt => {
                SCHEMA_CELL_ECH_DECRYPT.get_or_init(|| Schema::new(self, resources::XSD_DECRYPT))
            }
            SchemaKind::config => {
                SCHEMA_CELL_ECH_CONFIG.get_or_init(|| Schema::new(self, resources::XSD_CONFIG))
            }
        }
    }
}

impl<'a> Schema<'a> {
    /// Try to create a new schema of kind [schema_kind] with the static str [xsd_str]
    ///
    /// Return an error in the following cases:
    /// - It is not possible to create it
    /// - Targetnamespace is missing
    pub fn try_new(schema_kind: &SchemaKind, xsd_str: &'static str) -> Result<Self> {
        let doc = Document::parse(xsd_str).with_context(|| "Failed to read the schema")?;
        let root = doc.root_element();
        let target_ns_uri = root
            .attributes()
            .find(|attr| attr.name() == "targetNamespace")
            .map(|a| a.value().to_string())
            .ok_or(anyhow!("targetNamespace is missing"))?;
        let mut hm = HashMap::new();
        for ns in root.namespaces() {
            hm.insert(ns.name().unwrap().to_string(), ns.uri().to_string());
        }
        let target_ns_name = hm
            .iter()
            .find(|(_, uri)| uri == &&target_ns_uri)
            .ok_or(anyhow!(
                "The name of the target namespace is not defined in the list of namespaces"
            ))?
            .0;
        let schema_ns_name = hm
            .iter()
            .find(|(_, uri)| uri.as_str() == XML_SCHEMA_URI)
            .ok_or(anyhow!(
                "The name of the xml schema is not defined in the list of namespaces"
            ))?
            .0;
        Ok(Self {
            document: doc,
            target_namespace_uri: target_ns_uri,
            target_namespace_name: target_ns_name.clone(),
            xml_schema_name: schema_ns_name.clone(),
            namespaces: hm,
            schema_kind: *schema_kind,
        })
    }

    /// Try to create a new schema of kind [schema_kind] with the static str [xsd_str]
    ///
    /// Panic if it is not possible to create it
    pub fn new(schema_kind: &SchemaKind, xsd_str: &'static str) -> Self {
        Self::try_new(schema_kind, xsd_str).unwrap()
    }

    /// Root element of the schema
    pub fn root_element(&self) -> RoNode {
        self.document.root_element()
    }

    /// The source document of type [Document]
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The name of the target namespace's name, based on the uri in `targetNamespace` and the list of namespaces
    pub fn target_namespace_name(&'a self) -> &'a str {
        self.target_namespace_name.as_str()
    }

    /// The name of the xml schema namespace's name, based on the standard uri "http://www.w3.org/2001/XMLSchema" and the list of namespaces
    pub fn xmlschema_namespace_name(&'a self) -> &'a str {
        self.xml_schema_name.as_str()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_schema_decrypt() {
        let xsd = SchemaKind::decrypt.get_schema();
        assert_eq!(
            xsd.target_namespace_uri,
            "http://www.evoting.ch/xmlns/decrypt/1"
        );
        assert_eq!(xsd.namespaces.keys().len(), 2);
        assert_eq!(
            xsd.namespaces.get("decrypt").unwrap(),
            "http://www.evoting.ch/xmlns/decrypt/1"
        );
        assert_eq!(
            xsd.namespaces.get("xs").unwrap(),
            "http://www.w3.org/2001/XMLSchema"
        );
    }

    #[test]
    fn test_schema_config() {
        let xsd = SchemaKind::config.get_schema();
        assert_eq!(
            xsd.target_namespace_uri,
            "http://www.evoting.ch/xmlns/config/5"
        );
        assert_eq!(xsd.namespaces.keys().len(), 2);
        assert_eq!(
            xsd.namespaces.get("config").unwrap(),
            "http://www.evoting.ch/xmlns/config/5"
        );
        assert_eq!(
            xsd.namespaces.get("xs").unwrap(),
            "http://www.w3.org/2001/XMLSchema"
        );
    }

    #[test]
    fn test_target_namespace_name() {
        let xsd = SchemaKind::config.get_schema();
        assert_eq!(xsd.target_namespace_name(), "config");
    }

    #[test]
    fn test_xmlschema_namespace_name() {
        let xsd = SchemaKind::config.get_schema();
        assert_eq!(xsd.xmlschema_namespace_name(), "xs");
    }
}
