use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use std::convert::From;

const SEP: char = '~'; // separator between pk and sk, eg: Usr#qywen~Acc#ICI-Prj#MailBox
const PK: &str = "pk";
const SK: &str = "sk";

#[derive(Debug, PartialEq)]
pub struct CompositeKey {
    pk: String,
    sk: String,
}

impl CompositeKey {
    pub fn new(pk: &str, sk: &str) -> Self {
        CompositeKey {
            pk: String::from(pk),
            sk: String::from(sk),
        }
    }

    pub fn key_as_string(pk: &str, sk: &str) -> String {
        format!("{}{SEP}{}", pk, sk)
    }

    pub fn key_as_hashmap(pk: &str, sk: &str) -> HashMap<String, AttributeValue> {
        HashMap::from([
            ("pk".to_string(), AttributeValue::S(pk.to_string())),
            ("sk".to_string(), AttributeValue::S(sk.to_string())),
        ])
    }

    pub fn key_condition_expression(&self) -> String {
        if self.sk.ends_with("#") || self.sk.ends_with("*") {
            format!("pk = :hashKey AND begins_with( sk, :rangeKey )")
        } else {
            format!("pk = :hashKey AND sk = :rangeKey")
        }
    }

    pub fn pk(&self) -> String {
        self.pk.clone()
    }

    pub fn sk(&self) -> String {
        self.sk.strip_suffix('*').unwrap_or(&self.sk).to_string()
    }
}

// impl TryFrom<&str> for CompositeKey {
//     type Error = DynamoError;
//     fn try_from(value: &str) -> Result<Self, DynamoError> {
//         let pksk: Vec<&str> = value.split(SEP).collect();
//         if pksk.len() == 2 {
//             Ok(Self {
//                 pk: String::from(pksk[0]),
//                 sk: String::from(pksk[1]),
//             })
//         } else {
//             // Err(KeyError::MissingSortKey("Missing sk".to_string()))
//             Ok(Self {
//                 pk: String::from(pksk[0]),
//                 sk: String::from("#"),
//             })
//         }
//     }
// }

impl From<CompositeKey> for String {
    fn from(value: CompositeKey) -> Self {
        format!("{}{SEP}{}", value.pk, value.sk)
    }
}

impl From<String> for CompositeKey {
    fn from(value: String) -> Self {
        let mut parts = value.splitn(2, SEP);
        Self {
            pk: parts.next().unwrap_or("").to_string(),
            sk: parts.next().unwrap_or("#").to_string(),
        }
    }
}

impl From<&str> for CompositeKey {
    fn from(value: &str) -> Self {
        let mut parts = value.splitn(2, SEP);
        Self {
            pk: parts.next().unwrap_or("").to_string(),
            sk: parts.next().unwrap_or("#").to_string(),
        }
    }
}

impl From<CompositeKey> for HashMap<String, AttributeValue> {
    fn from(value: CompositeKey) -> Self {
        HashMap::from([
            (PK.to_string(), AttributeValue::S(value.pk.to_string())),
            (SK.to_string(), AttributeValue::S(value.sk.to_string())),
        ])
    }
}

impl From<HashMap<String, AttributeValue>> for CompositeKey {
    fn from(value: HashMap<String, AttributeValue>) -> Self {
        let pk = value.get("pk").unwrap().as_s().unwrap();
        let sk = value.get("sk").unwrap().as_s().unwrap();
        CompositeKey {
            pk: pk.to_owned(),
            sk: sk.to_owned(),
        }
    }
}
