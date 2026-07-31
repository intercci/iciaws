use aws_sdk_dynamodb::{
    Client,
    operation::query::{QueryOutput, builders::QueryFluentBuilder},
    types::AttributeValue,
    error::DisplayErrorContext,
};
use std::collections::HashMap;

use crate::{errors::DynamoError, pagekey::make_start_key};

const HASH_KEY_NAME: &str = "pk";
const SORT_KEY_NAME: &str = "sk";

/// A Query helper builder with default values of hash and sort key names (pk, sk), limit and descending sort.
#[derive(Debug)]
pub struct QueriesBuilder<'a> {
    pk_name: &'a str,
    sk_name: &'a str,
    ascending: bool,
    last_key: Option<String>,
    page_size: Option<i32>,
    pub builder: QueryFluentBuilder,
}

impl<'a> QueriesBuilder<'a> {
    pub fn with_table(client: &Client, tablename: &str) -> Self {
        Self {
            pk_name: HASH_KEY_NAME,
            sk_name: SORT_KEY_NAME,
            ascending: false,
            last_key: None,
            page_size: None,
            builder: client.query().table_name(tablename),
        }
    }

    pub fn use_index(mut self, indexname: &str) -> Self {
        self.builder = self.builder.index_name(indexname);
        self
    }

    pub fn key_names(mut self, hash_keyname: &'a str, sort_keyname: &'a str) -> Self {
        self.pk_name = hash_keyname;
        self.sk_name = sort_keyname;
        self
    }

    pub fn hash_key(mut self, key_value: &str) -> Self {
        self.builder = self
            .builder
            .key_condition_expression("#pk = :pk")
            .expression_attribute_names("#pk", self.pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(key_value.into()));
        self
    }

    /// Key condition with sort key as begins_with(sk, "...")
    pub fn hash_key_with_sort_key_prefix(
        mut self,
        hash_key_value: &str,
        sort_key_prefix: &str,
    ) -> Self {
        self.builder = self
            .builder
            .key_condition_expression("#pk = :pk and begins_with(#sk, :pfx)")
            .expression_attribute_names("#pk", self.pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(hash_key_value.into()))
            .expression_attribute_names("#sk", self.sk_name)
            .expression_attribute_values(":pfx", AttributeValue::S(sort_key_prefix.into()));
        self
    }

    /// Key condition such as: pk = 'A' and sk > '100'
    /// sort_key_op can be: =, >, <, >=, <=
    pub fn hash_key_with_sort_key_expr(
        mut self,
        hash_key_value: &str,
        sort_key_op: &str,
        sort_key_val: &str,
    ) -> Self {
        self.builder = self
            .builder
            .key_condition_expression(format!("#pk = :pk and #sk {sort_key_op} :sk"))
            .expression_attribute_names("#pk", self.pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(hash_key_value.into()))
            .expression_attribute_names("#sk", self.sk_name)
            .expression_attribute_values(":sk", AttributeValue::S(sort_key_val.into()));
        self
    }

    /// Key condition such as: pk = 'A' and sk between '1' and '2'
    pub fn hash_key_with_sort_key_between(
        mut self,
        hash_key_value: &str,
        sort_key_val1: &str,
        sort_key_val2: &str,
    ) -> Self {
        self.builder = self
            .builder
            .key_condition_expression("#pk = :pk and #sk between :sk1 and :sk2")
            .expression_attribute_names("#pk", self.pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(hash_key_value.into()))
            .expression_attribute_names("#sk", self.sk_name)
            .expression_attribute_values(":sk1", AttributeValue::S(sort_key_val1.into()))
            .expression_attribute_values(":sk2", AttributeValue::S(sort_key_val2.into()));
        self
    }

    pub fn set_filter(
        mut self,
        filter_exp: &str,
        filter_names: Option<HashMap<String, String>>,
        filter_vals: Option<HashMap<String, AttributeValue>>,
    ) -> Self {
        // Merge the filter's attribute-name/value maps into the ones already set by
        // `hash_key` / `hash_key_with_sort_key_prefix`. The SDK setters would otherwise
        // REPLACE the key-condition placeholders (#pk / :pk), and passing None would
        // clear them entirely, breaking the query.
        let mut names = self
            .builder
            .get_expression_attribute_names()
            .clone()
            .unwrap_or_default();
        if let Some(filter_names) = filter_names {
            names.extend(filter_names);
        }
        let mut vals = self
            .builder
            .get_expression_attribute_values()
            .clone()
            .unwrap_or_default();
        if let Some(filter_vals) = filter_vals {
            vals.extend(filter_vals);
        }
        self.builder = self
            .builder
            .set_filter_expression(Some(filter_exp.to_string()))
            .set_expression_attribute_names(if names.is_empty() { None } else { Some(names) })
            .set_expression_attribute_values(if vals.is_empty() { None } else { Some(vals) });
        self
    }

    pub fn set_ascending(mut self, ascending: bool) -> Self {
        self.ascending = ascending;
        self
    }

    pub fn set_page_key(mut self, last_key_str: Option<String>) -> Self {
        self.last_key = last_key_str;
        self
    }

    pub fn set_page_size(mut self, page_size: Option<i32>) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn build(mut self) -> Self {
        self.builder = self
            .builder
            .scan_index_forward(self.ascending)
            .set_exclusive_start_key(make_start_key(self.last_key.clone()))
            .set_limit(self.page_size);
        self
    }

    pub async fn go(self) -> Result<QueryOutput, DynamoError> {
        self.builder
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pagekey::last_evaluated_key_to_base64;
    use aws_config::Region;
    use aws_sdk_dynamodb::config::Credentials;
    use aws_sdk_dynamodb::Config;

    /// Build a DynamoDB client with dummy credentials and a dead endpoint so that
    /// constructing the client performs no network I/O (offline-safe for unit tests).
    fn test_client() -> Client {
        let creds = Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "unit-test",
        );
        let conf = Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .endpoint_url("http://localhost:0")
            .credentials_provider(creds)
            .build();
        Client::from_conf(conf)
    }

    #[test]
    fn test_with_table_defaults() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table");
        assert_eq!(qb.pk_name, "pk");
        assert_eq!(qb.sk_name, "sk");
        assert!(!qb.ascending, "default scan order must be descending");
        assert_eq!(qb.last_key, None);
        assert_eq!(qb.page_size, None);
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("table_name: Some(\"test-table\")"), "{dbg}");
    }

    #[test]
    fn test_hash_key() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table").hash_key("P#1");
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("key_condition_expression: Some(\"#pk = :pk\")"),
            "{dbg}"
        );
        assert!(dbg.contains("\"#pk\": \"pk\""), "{dbg}");
        assert!(dbg.contains("\":pk\": S(\"P#1\")"), "{dbg}");
    }

    #[test]
    fn test_hash_key_with_sort_key_prefix() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .hash_key_with_sort_key_prefix("P#1", "F#");
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("begins_with(#sk, :pfx)"), "{dbg}");
        assert!(dbg.contains("\"#sk\": \"sk\""), "{dbg}");
        assert!(dbg.contains("\":pfx\": S(\"F#\")"), "{dbg}");
    }

    #[test]
    fn test_hash_key_with_sort_key_expr() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .hash_key_with_sort_key_expr("P#1", ">=", "1234");
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("key_condition_expression: Some(\"#pk = :pk and #sk >= :sk\")"), "{dbg}");
        assert!(dbg.contains("\"#pk\": \"pk\""), "{dbg}");
        assert!(dbg.contains("\"#sk\": \"sk\""), "{dbg}");
        assert!(dbg.contains("\":sk\": S(\"1234\")"), "{dbg}");
    }

    #[test]
    fn test_hash_key_with_sort_key_between() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .hash_key_with_sort_key_between("P#1", "A1", "A4");
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("key_condition_expression: Some(\"#pk = :pk and #sk between :sk1 and :sk2\")"), "{dbg}");
        assert!(dbg.contains("\"#pk\": \"pk\""), "{dbg}");
        assert!(dbg.contains("\"#sk\": \"sk\""), "{dbg}");
        assert!(dbg.contains("\":sk1\": S(\"A1\")"), "{dbg}");
        assert!(dbg.contains("\":sk2\": S(\"A4\")"), "{dbg}");
    }

    #[test]
    fn test_key_names_flow_into_expression() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .key_names("gpk", "gsk")
            .hash_key("P#1");
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("key_condition_expression: Some(\"#pk = :pk\")"),
            "{dbg}"
        );
        assert!(dbg.contains("\"#pk\": \"gpk\""), "{dbg}");
    }

    #[test]
    fn test_use_index() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table").use_index("GSI1");
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("index_name: Some(\"GSI1\")"), "{dbg}");
    }

    #[test]
    fn test_set_filter() {
        let names = HashMap::from([("#f".to_string(), "field".to_string())]);
        let vals = HashMap::from([(":f".to_string(), AttributeValue::S("future".to_string()))]);
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_filter("field = :f", Some(names), Some(vals));
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("filter_expression: Some(\"field = :f\")"),
            "{dbg}"
        );
        assert!(dbg.contains("\"#f\": \"field\""), "{dbg}");
        assert!(dbg.contains("\":f\": S(\"future\")"), "{dbg}");
    }

    /// Regression: `set_filter` with None maps must NOT clear the placeholders
    /// set by `hash_key` (the SDK setters would otherwise wipe #pk / :pk).
    #[test]
    fn test_set_filter_none_maps_keep_key_placeholders() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .hash_key("P#1")
            .set_filter("attribute_exists(f)", None, None);
        let dbg = format!("{:?}", qb.builder);
        assert!(
            dbg.contains("filter_expression: Some(\"attribute_exists(f)\")"),
            "{dbg}"
        );
        assert!(dbg.contains("\"#pk\": \"pk\""), "{dbg}");
        assert!(dbg.contains("\":pk\": S(\"P#1\")"), "{dbg}");
    }

    /// Regression: `set_filter` with Some maps must MERGE into (not replace)
    /// the key-condition placeholders set by `hash_key`.
    #[test]
    fn test_set_filter_some_maps_merge_with_key_placeholders() {
        let names = HashMap::from([("#f".to_string(), "field".to_string())]);
        let vals = HashMap::from([(":f".to_string(), AttributeValue::S("future".to_string()))]);
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .hash_key("P#1")
            .set_filter("field = :f", Some(names), Some(vals));
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("\"#pk\": \"pk\""), "{dbg}");
        assert!(dbg.contains("\":pk\": S(\"P#1\")"), "{dbg}");
        assert!(dbg.contains("\"#f\": \"field\""), "{dbg}");
        assert!(dbg.contains("\":f\": S(\"future\")"), "{dbg}");
    }

    #[test]
    fn test_build_default_descending_limit() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_page_size(Some(2))
            .build();
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("scan_index_forward: Some(false)"), "{dbg}");
        assert!(dbg.contains("limit: Some(2)"), "{dbg}");
    }

    #[test]
    fn test_build_ascending() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_ascending(true)
            .set_page_size(Some(2))
            .build();
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("scan_index_forward: Some(true)"), "{dbg}");
        assert!(dbg.contains("limit: Some(2)"), "{dbg}");
    }

    #[test]
    fn test_build_with_page_key_roundtrip() {
        let key: HashMap<String, AttributeValue> = HashMap::from([
            ("pk".to_string(), AttributeValue::S("P#1".to_string())),
            ("sk".to_string(), AttributeValue::S("S#1".to_string())),
        ]);
        let b64 = last_evaluated_key_to_base64(key).unwrap();
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_page_key(Some(b64))
            .build();
        let dbg = format!("{:?}", qb.builder);
        assert!(dbg.contains("exclusive_start_key: Some({"), "{dbg}");
        assert!(dbg.contains("\"pk\": S(\"P#1\")"), "{dbg}");
        assert!(dbg.contains("\"sk\": S(\"S#1\")"), "{dbg}");
    }

    #[test]
    fn test_build_no_page_key() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_page_key(None)
            .build();
        let dbg = format!("{:?}", qb.builder);
        assert!(!dbg.contains("exclusive_start_key: Some("), "{dbg}");
    }

    /// `make_start_key` swallows decode errors with `.ok()`, so a garbage page key
    /// is silently dropped and the query starts from the beginning. Lock that in.
    #[test]
    fn test_build_invalid_page_key_silently_dropped() {
        let qb = QueriesBuilder::with_table(&test_client(), "test-table")
            .set_page_key(Some("!!!not-base64!!!".to_string()))
            .build();
        let dbg = format!("{:?}", qb.builder);
        assert!(!dbg.contains("exclusive_start_key: Some("), "{dbg}");
    }
}
