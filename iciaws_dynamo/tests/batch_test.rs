use aws_sdk_dynamodb::types::AttributeValue;
use iciaws_dynamo::{DynamoClient, errors::DynamoError};
use std::collections::HashMap;

#[tokio::test]
async fn test_batch_get() {
    let dynamo = DynamoClient::new(String::from("ici-shop")).await;
    let pk = "Theme#Cultural";
    // get
    // let go = dynamo.get("Theme#Cultural~FL001", None).await.unwrap();
    // println!("--- Get outpur: {:?}", go);
    let keys = Vec::from([
        HashMap::from([
            ("pk".to_owned(), AttributeValue::S(pk.to_owned())),
            ("sk".to_owned(), AttributeValue::S("FL001".to_string())),
        ]),
        HashMap::from([
            ("pk".to_owned(), AttributeValue::S(pk.to_owned())),
            ("sk".to_owned(), AttributeValue::S("FL003".to_string())),
        ]),
        HashMap::from([
            ("pk".to_owned(), AttributeValue::S(pk.to_owned())),
            ("sk".to_owned(), AttributeValue::S("FL005".to_string())),
        ]),
        HashMap::from([
            ("pk".to_owned(), AttributeValue::S(pk.to_owned())),
            ("sk".to_owned(), AttributeValue::S("FL-005".to_string())),
        ]),
    ]);
    // println!(">>> keys: {:?}", keys);
    let res = dynamo.batch_get(keys, None).await;
    // println!("??? {:?}", res);
    match res.unwrap().responses() {
        Some(tab_items) => {
            let items = &tab_items["ici-shop"];
            assert_eq!(items.len(), 3);
            assert_eq!(items[0]["sk"].as_s().ok(), Some(&"FL001".to_string()));
        }
        None => {
            assert!(false, "No results");
        }
    }
}

async fn scan_carts(
    dynamo: &DynamoClient,
) -> Result<Vec<HashMap<String, AttributeValue>>, DynamoError> {
    let pfx = "Cart#";
    let filter = "begins_with(#pk, :pkv)";
    let ean = HashMap::from([("#pk".to_string(), "pk".to_string())]);
    let eav = HashMap::from([(":pkv".to_string(), AttributeValue::S(pfx.to_string()))]);
    let so = dynamo
        .scan_with_filter2(filter, ean, eav, None, None)
        .await?;
    // println!("so::::{:?}", so);
    Ok(so
        .items
        .unwrap_or(Vec::new() as Vec<HashMap<String, AttributeValue>>))
}

#[tokio::test]
async fn test_batch_delete() {
    let dynamo = DynamoClient::new(String::from("ici-shop")).await;
    let carts = scan_carts(&dynamo).await.expect("scan error");
    let items = carts.iter().map(|v| {
        let pk = v["pk"].as_s().ok().unwrap();
        let sk = v["sk"].as_s().ok().unwrap();
        HashMap::from([
            ("pk".to_owned(), AttributeValue::S(pk.to_owned())),
            ("sk".to_owned(), AttributeValue::S(sk.to_owned())),
        ])
    }).collect();
    let _ = dynamo
        .batch_delete(items, None)
        .await
        .expect("delete failed");
    let carts2 = scan_carts(&dynamo).await.expect("scan_carts failed for carts2");
    assert!(carts2.len() != carts.len());
}
