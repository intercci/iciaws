use aws_sdk_dynamodb::types::{AttributeValue, Condition};
use std::collections::HashMap;

pub type ItemType = HashMap<String, AttributeValue>;
pub type StringMap = HashMap<String, String>;
pub type FilterType = HashMap<String, Condition>;
