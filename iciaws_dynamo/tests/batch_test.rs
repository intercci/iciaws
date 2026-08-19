use aws_sdk_dynamodb::types::AttributeValue;
use iciaws_dynamo::DynamoClient;
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
