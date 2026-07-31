#![allow(dead_code)]
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{
    Client,
    error::DisplayErrorContext,
    operation::{
        batch_write_item::BatchWriteItemOutput, get_item::GetItemOutput, put_item::PutItemOutput,
        query::QueryOutput, scan::ScanOutput, update_item::UpdateItemOutput,
    },
    types::{AttributeValue, DeleteRequest, PutRequest, ReturnValue, WriteRequest},
};
use dotenv::dotenv;
use std::collections::HashMap;
use std::env;
pub mod ckey;
use chrono::Utc;
use ckey::CompositeKey;
pub mod types;
use types::{FilterType, ItemType, StringMap};
pub mod queries;
pub mod builder;
pub mod pagekey;
use pagekey::make_start_key;
pub mod errors;
use errors::DynamoError;
use tokio::sync::OnceCell;

use crate::queries::QueriesBuilder;

pub async fn dynamo_client() -> Client {
    if env::var("LAMBDA_TASK_ROOT").is_err() {
        println!("Loading from .env...");
        dotenv().ok();
    }
    let config = aws_config::defaults(BehaviorVersion::latest());
    let config = match env::var("DYNAMO_ENDPOINT_URL") {
        Ok(ep) => {
            println!("Using DynamoDB at {ep}");
            config.endpoint_url(&ep).load().await
        }
        Err(_) => config.load().await,
    };
    Client::new(&config)
}

#[derive(Debug, Clone)]
pub struct DynamoClient {
    table_name: String,
    client: Client,
}

impl DynamoClient {
    pub async fn new(table_name: String) -> DynamoClient {
        DynamoClient {
            table_name,
            client: dynamo_client().await,
        }
    }

    /// Dynamodb put_item without overwriting an existing item with the key.
    pub async fn put(
        &self,
        item: HashMap<String, AttributeValue>,
        tablename: Option<&str>,
    ) -> Result<PutItemOutput, DynamoError> {
        // println!("Enter put({:?})", &item);

        let po = self
            .client
            .put_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(po)
    }

    /// Dynamodb put_item overwriting an existing item with the key.
    pub async fn put_over(
        &self,
        item: ItemType,
        tablename: Option<&str>,
    ) -> Result<PutItemOutput, DynamoError> {
        // println!("Enter put({:?})", &item);

        let po = self
            .client
            .put_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(po)
    }

    /// Batch put item will overwrite existing items with the same key.
    pub async fn batch_put(
        &self,
        items: Vec<ItemType>,
        tablename: Option<&str>,
    ) -> Result<BatchWriteItemOutput, DynamoError> {
        let rs = items
            .into_iter()
            .map(|item| {
                WriteRequest::builder()
                    .set_put_request(Some(
                        PutRequest::builder().set_item(Some(item)).build().unwrap(),
                    ))
                    .build()
            })
            .collect::<Vec<WriteRequest>>();

        let reqs = HashMap::from([(tablename.unwrap_or(&self.table_name).to_string(), rs)]);

        let bo = self
            .client
            .batch_write_item()
            .set_request_items(Some(reqs))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(bo)
    }

    pub async fn get_by_pksk(
        &self,
        pk: &str,
        sk: &str,
        tablename: Option<&str>,
    ) -> Result<GetItemOutput, DynamoError> {
        let gout = self
            .client
            .get_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(CompositeKey::key_as_hashmap(pk, sk)))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(gout)
    }

    pub async fn get(
        &self,
        res_id: &str,
        tablename: Option<&str>,
    ) -> Result<GetItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();

        let gout = self
            .client
            .get_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(gout)
    }

    pub async fn query_by_pk(
        &self,
        pk: &str,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression("pk = :hashKey")
            .expression_attribute_values(":hashKey", AttributeValue::S(pk.to_string()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    /// Query top N items by hash key sorted by sk in descending order.
    /// This assumes sk is a timestamp like string.
    pub async fn query_latest_by_pk(
        &self,
        pk: &str,
        limit: Option<i32>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression("pk = :hashKey")
            .expression_attribute_values(":hashKey", AttributeValue::S(pk.to_string()))
            .scan_index_forward(false)
            .limit(limit.unwrap_or(1))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    pub async fn query_by_pk_with_sk_prefix(
        &self,
        pk: &str,
        sk_prefix: &str,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression("pk = :hashKey and begins_with(sk, :prefix)")
            .expression_attribute_values(":hashKey", AttributeValue::S(pk.to_string()))
            .expression_attribute_values(":prefix", AttributeValue::S(sk_prefix.to_string()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;
        Ok(qo)
    }

    /// Query a page by hashkey (pk) with a descending order.
    pub async fn query_page_by_pk(
        &self,
        pk: &str,
        last_key_str: Option<String>,
        limit: Option<i32>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression("pk = :hashKey")
            .expression_attribute_values(":hashKey", AttributeValue::S(pk.to_string()))
            .set_limit(limit)
            .set_exclusive_start_key(make_start_key(last_key_str))
            .scan_index_forward(false)
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    pub async fn query(
        &self,
        res_id: &str,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();

        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression(ck.key_condition_expression())
            .expression_attribute_values(":hashKey", AttributeValue::S(ck.pk()))
            .expression_attribute_values(":rangeKey", AttributeValue::S(ck.sk()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    pub async fn query_with_key(
        &self,
        gsi: Option<String>,
        kce: &str,
        ean: Option<HashMap<String, String>>,
        eav: Option<HashMap<String, AttributeValue>>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_index_name(gsi)
            .key_condition_expression(kce)
            .set_expression_attribute_names(ean)
            .set_expression_attribute_values(eav)
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;
        Ok(qo)
    }

    pub async fn query_gsi_by_pk(
        &self,
        gsi: &str,
        pk_name: &str,
        pk_val: &str,
        forward: bool,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .index_name(gsi)
            .key_condition_expression("#pk = :pk")
            .expression_attribute_names("#pk", pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(pk_val.to_string()))
            .scan_index_forward(forward)
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    pub async fn query_gsi_by_pk_with_sk_prefix(
        &self,
        gsi: &str,
        pk_name: &str,
        pk_val: &str,
        sk_name: &str,
        sk_pfx: &str,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .index_name(gsi)
            .key_condition_expression("#pk = :pk and begins_with(#sk, :pfx)")
            .expression_attribute_names("#pk", pk_name)
            .expression_attribute_names("#sk", sk_name)
            .expression_attribute_values(":pk", AttributeValue::S(pk_val.to_owned()))
            .expression_attribute_values(":pfx", AttributeValue::S(sk_pfx.to_owned()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    pub async fn query_gsi_page_by_pk(
        &self,
        gsi: &str,
        pk_name: &str,
        pk_val: &str,
        forward: bool,
        last_key_str: Option<String>,
        limit: Option<i32>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .index_name(gsi)
            .key_condition_expression("#pk = :pk")
            .expression_attribute_names("#pk", pk_name)
            .expression_attribute_values(":pk", AttributeValue::S(pk_val.to_string()))
            .scan_index_forward(forward)
            .set_limit(limit)
            .set_exclusive_start_key(make_start_key(last_key_str))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(qo)
    }

    /// Query by pk with a filter expression for short dataset (no pagination necessary)
    ///
    /// # Arguments
    ///
    /// * pk - hash key
    /// * filter - filter expression e.g. "field = :field"
    /// * filter_name - {"#fields": "fields"}
    /// * filter_val - e.g. {":field": "future"}
    pub async fn query_by_pk_with_filter(
        &self,
        pk: &str,
        filter: &str,
        filter_name: Option<HashMap<String, String>>,
        filter_val: Option<HashMap<String, AttributeValue>>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = self
            .client
            .query()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key_condition_expression("pk = :pk")
            .set_filter_expression(Some(filter.to_string()))
            .set_expression_attribute_names(filter_name)
            .set_expression_attribute_values(filter_val)
            .expression_attribute_values(":pk", AttributeValue::S(pk.to_string()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;
        Ok(qo)
    }

    pub async fn query_page_by_pk_with_filter(
        &self,
        pk: &str,
        last_key_str: Option<String>,
        limit: Option<i32>,
        ascending: bool,
        filter: &str,
        filter_names: Option<HashMap<String, String>>,
        filter_vals: Option<HashMap<String, AttributeValue>>,
        tablename: Option<&str>,
    ) -> Result<QueryOutput, DynamoError> {
        let qo = QueriesBuilder::with_table(&self.client, tablename.unwrap_or(&self.table_name))
            .hash_key(pk)
            .set_ascending(ascending)
            .set_page_size(limit)
            .set_page_key(last_key_str)
            .set_filter(filter, filter_names, filter_vals)
            .build().go().await?;
        Ok(qo)
    }

    pub async fn scan_with_filter(
        &self,
        filter: FilterType,
        tablename: Option<&str>,
    ) -> Result<ScanOutput, DynamoError> {
        let so = self
            .client
            .scan()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_scan_filter(Some(filter))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(so)
    }

    pub async fn scan_with_filter2(
        &self,
        filter_expression: &str,
        ean: StringMap,
        eav: ItemType,
        last_key_str: Option<String>,
        tablename: Option<&str>,
    ) -> Result<ScanOutput, DynamoError> {
        let so = self
            .client
            .scan()
            .table_name(tablename.unwrap_or(&self.table_name))
            .filter_expression(filter_expression.to_string())
            .set_expression_attribute_names(Some(ean))
            .set_expression_attribute_values(Some(eav))
            .set_exclusive_start_key(make_start_key(last_key_str))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(so)
    }

    pub async fn update_s(
        &self,
        res_id: &str,
        fld: &str,
        sval: &str,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();

        let request = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .update_expression("SET #fld = :sval")
            .expression_attribute_names("#fld", fld)
            .expression_attribute_values(":sval", AttributeValue::S(sval.to_string()))
            .return_values(ReturnValue::UpdatedNew);

        let uo = request
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_n(
        &self,
        res_id: &str,
        fld: &str,
        byval: i32,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();

        let request = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .update_expression("SET #fld = :sval")
            .expression_attribute_names("#fld", fld)
            .expression_attribute_values(":sval", AttributeValue::N(byval.to_string()))
            .return_values(ReturnValue::UpdatedNew);

        let uo = request
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update(
        &self,
        key: ItemType,
        uex: String,
        ean: StringMap,
        eav: ItemType,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let request = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(key))
            .set_update_expression(Some(uex))
            .set_expression_attribute_names(Some(ean))
            .set_expression_attribute_values(if eav.is_empty() { None } else { Some(eav) })
            .return_values(ReturnValue::UpdatedNew);

        let uo: UpdateItemOutput = request
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_add_list_str(
        &self,
        key: ItemType,
        list_name: &str,
        value: &str,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let uex = "SET #attr = list_append(if_not_exists(#attr, :elst), :val)";
        let eav: ItemType = HashMap::from([
            (
                ":val".to_string(),
                AttributeValue::L(vec![AttributeValue::S(value.to_string())]),
            ),
            (":elst".to_string(), AttributeValue::L(Vec::new())),
        ]);

        let req = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(key))
            .update_expression(uex)
            .expression_attribute_names("#attr", list_name)
            .set_expression_attribute_values(Some(eav))
            .return_values(ReturnValue::UpdatedNew);

        let uo = req
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_add_list(
        &self,
        key: ItemType,
        list_name: &str,
        value: serde_json::Value,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let uex = "SET #attr = list_append(if_not_exists(#attr, :elst), :val)";
        let eav: ItemType = HashMap::from([
            (
                ":val".to_string(),
                AttributeValue::L(vec![serde_dynamo::to_attribute_value(value)?]),
            ),
            (":elst".to_string(), AttributeValue::L(Vec::new())),
        ]);

        let req = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(key))
            .update_expression(uex)
            .expression_attribute_names("#attr", list_name)
            .set_expression_attribute_values(Some(eav))
            .return_values(ReturnValue::UpdatedNew);

        let uo = req
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_add(
        &self,
        res_id: &str,
        fld: &str,
        byval: i32,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();
        // let uex = format!("SET {} = if_not_exists({}, :zero) + :one", fld, fld);

        let request = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .update_expression("SET #fld = if_not_exists(#fld, :zero) + :one")
            .expression_attribute_names("#fld", fld)
            .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
            .expression_attribute_values(":one", AttributeValue::N(byval.to_string()))
            .return_values(ReturnValue::UpdatedNew);

        let uo = request
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_add_ts(
        &self,
        res_id: &str,
        fld: &str,
        byval: i32,
        tsname: &str,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();
        let ts = Utc::now().format("%y%m%d%H%M%S").to_string();

        let request = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .update_expression("SET #fld = if_not_exists(#fld, :zero) + :one, #ts = :tsv")
            .expression_attribute_names("#fld", fld)
            .expression_attribute_names("#ts", tsname)
            .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
            .expression_attribute_values(":one", AttributeValue::N(byval.to_string()))
            .expression_attribute_values(":tsv", AttributeValue::S(ts))
            .return_values(ReturnValue::UpdatedNew);

        let uo = request
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn update_remove_attr(
        &self,
        res_id: &str,
        fld: &str,
        tablename: Option<&str>,
    ) -> Result<UpdateItemOutput, DynamoError> {
        let ck = CompositeKey::try_from(res_id).unwrap();

        let uo = self
            .client
            .update_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .update_expression("REMOVE #fld")
            .expression_attribute_names("#fld", fld)
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(uo)
    }

    pub async fn delete_by_pksk(
        &self,
        pk: &str,
        sk: &str,
        tablename: Option<&str>,
    ) -> Result<(), DynamoError> {
        let _ = self
            .client
            .delete_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .key("pk", AttributeValue::S(pk.to_string()))
            .key("sk", AttributeValue::S(sk.to_string()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(())
    }

    /// Delete an item by key as a string
    ///
    /// # Arguments
    ///
    /// * res_id - <hash-key>~<range-key>, for items, <pk>~<sk>
    /// * condition - condition expression
    /// * tablename - optionally specify a different tablename, default is self.table_name
    ///
    /// # Returns nothing if successfully deleted, else error
    pub async fn delete(
        &self,
        res_id: &str,
        condition: &str,
        tablename: Option<&str>,
    ) -> Result<(), DynamoError> {
        let ck = CompositeKey::from(res_id);

        let _ = self
            .client
            .delete_item()
            .table_name(tablename.unwrap_or(&self.table_name))
            .set_key(Some(ck.into()))
            .condition_expression(condition)
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        Ok(())
    }

    /// Batch delete a list of items
    ///
    /// # Arguments
    ///
    /// * items - Array of items of HashMap<String, AttributeValue>
    /// * tabname - tablename
    ///
    /// # Returns nothing if successful, else returns DynamoError
    pub async fn batch_delete(
        &self,
        items: Vec<HashMap<String, AttributeValue>>,
        tabname: &str,
    ) -> Result<(), DynamoError> {
        for chunk in items.chunks(25) {
            let wreqs: Result<Vec<WriteRequest>, DynamoError> = chunk
                .iter()
                .map(|item| {
                    let pk = item.get("pk").cloned().unwrap();
                    let sk = item.get("sk").cloned().unwrap();
                    let k: HashMap<String, AttributeValue> =
                        HashMap::from([("pk".to_string(), pk), ("sk".to_string(), sk)]);
                    let delete_req =
                        DeleteRequest::builder()
                            .set_key(Some(k))
                            .build()
                            .map_err(|e| {
                                DynamoError::DynDbError(format!("{}", DisplayErrorContext(&e)))
                            })?;
                    Ok(WriteRequest::builder()
                        .set_delete_request(Some(delete_req))
                        .build())
                })
                .collect();

            let wreqs = wreqs?;
            let reqs = HashMap::from([(tabname.to_string(), wreqs)]);

            self.client
                .batch_write_item()
                .set_request_items(Some(reqs))
                .send()
                .await
                .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;
        }

        Ok(())
    }

    /// Delete all items sharing the same pk like 'M#a2344#Tag' for all tags of a module
    ///
    /// # Arguments
    ///
    /// * pk: hash key to query
    /// * tablename: If none, use self.table_name
    pub async fn delete_by_pk(&self, pk: &str, tablename: Option<&str>) -> Result<(), DynamoError> {
        let tabname = tablename.unwrap_or(&self.table_name);
        let qo = self
            .client
            .query()
            .table_name(tabname)
            .key_condition_expression("pk = :hashKey")
            .expression_attribute_values(":hashKey", AttributeValue::S(pk.to_string()))
            .send()
            .await
            .map_err(|e| DynamoError::DynDbError(format!("{}", DisplayErrorContext(e))))?;

        if let Some(items) = qo.items
            && !items.is_empty()
        {
            let _bdo = self.batch_delete(items, tabname).await?;
        }

        Ok(())
    }

    pub fn keys_to_resid(&self, keys: HashMap<String, AttributeValue>) -> String {
        let ck: CompositeKey = CompositeKey::from(keys);
        ck.into()
    }

    pub fn resid_to_keys(&self, resid: &str) -> HashMap<String, AttributeValue> {
        let ck = CompositeKey::try_from(resid).unwrap();
        ck.into()
    }
}

pub static DYNAMO: OnceCell<DynamoClient> = OnceCell::const_new();

pub async fn get_dynamo_client<S: AsRef<str>>(
    default_table_name: Option<S>,
) -> &'static DynamoClient {
    let tname = match default_table_name {
        Some(s) => s.as_ref().to_string(),
        None => env::var("TABLE_NAME").unwrap_or_else(|_| "ici-users".to_string()),
    };
    println!("Using DynamoDB table name '{tname}'");
    DYNAMO
        .get_or_init(|| async { DynamoClient::new(tname).await })
        .await
}
