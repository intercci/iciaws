use iciaws_dynamo::{DynamoClient, pagekey::last_evaluated_key_to_base64};
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

#[tokio::test]
async fn dynamo_get_forward() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo.query_by_pk("User#intercci", None).await;
    match res.unwrap().items {
        Some(items) => {
            assert!(items.len() >= 1);
            assert_eq!(
                items[0].get("sk").unwrap(),
                &AttributeValue::S(String::from("#"))
            );
            assert_eq!(items[0].get("email").unwrap(), &AttributeValue::S(String::from("admin@intercci.com")));
        }
        None => assert!(false, "Items not found"),
    }
}

#[tokio::test]
async fn test_query_page_by_pk() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let pk = "User#tedwen";
    let limit = Some(2);
    let r = dynamo
        .query_page_by_pk(pk, None, limit, None)
        .await
        .unwrap();
    assert_eq!(r.count, 2, "{:?}", r);
    let last_k = r.last_evaluated_key().map_or(None, |k| Some(k.clone()));
    assert!(last_k.is_some(), "last_evaluated_key is None");
    // let items = r.items.unwrap();
    let last_key = last_k.unwrap();
    let last_keys = last_evaluated_key_to_base64(last_key).expect("last_key error");
    let r2 = dynamo
        .query_page_by_pk(pk, Some(last_keys), None, None)
        .await
        .unwrap();
    // println!("Page 2: {:?}", r2);
    assert!(r2.last_evaluated_key.is_none(), "{:?}", r2);
    // run this test for println! result: cargo test -- --nocapture
}

#[tokio::test]
async fn dynamo_query_latest_by_pk() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query_latest_by_pk("User#tedwen", Some(2), None)
        .await
        .unwrap();
    assert_eq!(res.count, 2, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 2);
    // descending by sk (assumes sk is a timestamp-like string)
    assert_eq!(
        items[0].get("sk").unwrap(),
        &AttributeValue::S(String::from("1779284476884"))
    );
    assert_eq!(
        items[1].get("sk").unwrap(),
        &AttributeValue::S(String::from("1776001606714"))
    );
}

#[tokio::test]
async fn dynamo_query_by_pk_with_sk_prefix() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query_by_pk_with_sk_prefix("User#tedwen", "1776", None)
        .await
        .unwrap();
    assert_eq!(res.count, 2, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 2);
    for it in &items {
        let sk = it.get("sk").unwrap().as_s().unwrap();
        assert!(sk.starts_with("1776"), "sk {} does not start with 1776", sk);
    }
}

#[tokio::test]
async fn dynamo_query_by_composite_key() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query("User#tedwen~1779284476884", None)
        .await
        .unwrap();
    assert_eq!(res.count, 1, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 1);
    // sk does not end in # or * -> equality key condition
    assert_eq!(
        items[0].get("sk").unwrap(),
        &AttributeValue::S(String::from("1779284476884"))
    );
}

#[tokio::test]
async fn dynamo_query_by_composite_key_prefix() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo.query("User#tedwen~1776*", None).await.unwrap();
    assert_eq!(res.count, 2, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 2);
    // sk ends with * -> begins_with key condition, trailing * stripped
    for it in &items {
        let sk = it.get("sk").unwrap().as_s().unwrap();
        assert!(sk.starts_with("1776"), "sk {} does not start with 1776", sk);
    }
}

#[tokio::test]
async fn dynamo_query_with_key_gsi() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query_with_key(
            Some(String::from("email-index")),
            "email = :e",
            None,
            Some(HashMap::from([(
                ":e".to_string(),
                AttributeValue::S(String::from("admin@intercci.com")),
            )])),
            None,
        )
        .await
        .unwrap();
    assert_eq!(res.count, 1, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("pk").unwrap(),
        &AttributeValue::S(String::from("User#intercci"))
    );
}

#[tokio::test]
async fn dynamo_query_gsi_by_pk() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query_gsi_by_pk("role-index", "role", "staff", true, None)
        .await
        .unwrap();
    assert!(res.count >= 3, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), res.count as usize);
    for it in &items {
        assert_eq!(
            it.get("role").unwrap(),
            &AttributeValue::S(String::from("staff"))
        );
    }
}

#[tokio::test]
async fn dynamo_query_gsi_by_pk_with_sk_prefix() {
    let dynamo = DynamoClient::new(String::from("ici-award")).await;
    let res = dynamo
        .query_gsi_by_pk_with_sk_prefix(
            "gsi1-index",
            "gsi1pk",
            "icci#26#Selected",
            "gsi1sk",
            "1",
            None,
        )
        .await
        .unwrap();
    assert!(res.count >= 1, "{:?}", res);
    let items = res.items.expect("items");
    for it in &items {
        let gsi1sk = it.get("gsi1sk").unwrap().as_s().unwrap();
        assert!(
            gsi1sk.starts_with("1"),
            "gsi1sk {} does not start with 1",
            gsi1sk
        );
    }
}

#[tokio::test]
async fn dynamo_query_gsi_page_by_pk() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let r = dynamo
        .query_gsi_page_by_pk("role-index", "role", "staff", true, None, Some(2), None)
        .await
        .unwrap();
    assert_eq!(r.count, 2, "{:?}", r);
    let last_k = r.last_evaluated_key().map_or(None, |k| Some(k.clone()));
    assert!(last_k.is_some(), "last_evaluated_key is None");
    let last_key = last_k.unwrap();
    let last_keys = last_evaluated_key_to_base64(last_key).expect("last_key error");
    let r2 = dynamo
        .query_gsi_page_by_pk(
            "role-index",
            "role",
            "staff",
            true,
            Some(last_keys),
            Some(2),
            None,
        )
        .await
        .unwrap();
    assert!(r2.count >= 1, "{:?}", r2);
    let items2 = r2.items.expect("items on page 2");
    assert!(!items2.is_empty(), "page 2 has no items");
}

#[tokio::test]
async fn dynamo_query_by_pk_with_filter() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let res = dynamo
        .query_by_pk_with_filter(
            "User#tedwen",
            "folder = :fld",
            None,
            Some(HashMap::from([(
                ":fld".to_string(),
                AttributeValue::S(String::from("inbox")),
            )])),
            None,
        )
        .await
        .unwrap();
    assert_eq!(res.count, 4, "{:?}", res);
    let items = res.items.expect("items");
    assert_eq!(items.len(), 4);
}

#[tokio::test]
async fn dynamo_query_page_by_pk_with_filter() {
    let dynamo = DynamoClient::new(String::from("ici-email")).await;
    let r = dynamo
        .query_page_by_pk_with_filter(
            "User#tedwen",
            None,
            Some(2),
            false,
            "folder = :fld",
            None,
            Some(HashMap::from([(
                ":fld".to_string(),
                AttributeValue::S(String::from("inbox")),
            )])),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.count, 2, "{:?}", r);
    let last_k = r.last_evaluated_key().map_or(None, |k| Some(k.clone()));
    assert!(last_k.is_some(), "last_evaluated_key is None");
    let items = r.items.expect("items");
    // descending order: first page holds the two largest sk values
    assert_eq!(
        items[0].get("sk").unwrap(),
        &AttributeValue::S(String::from("1779284476884"))
    );
    assert_eq!(
        items[1].get("sk").unwrap(),
        &AttributeValue::S(String::from("1776001606714"))
    );
    let last_key = last_k.unwrap();
    let last_keys = last_evaluated_key_to_base64(last_key).expect("last_key error");
    let r2 = dynamo
        .query_page_by_pk_with_filter(
            "User#tedwen",
            Some(last_keys),
            None,
            false,
            "folder = :fld",
            None,
            Some(HashMap::from([(
                ":fld".to_string(),
                AttributeValue::S(String::from("inbox")),
            )])),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r2.count, 2, "{:?}", r2);
    assert!(r2.last_evaluated_key.is_none(), "{:?}", r2);
    // Second call with filter_names (expression attribute names) to prove the
    // ean/eav merge in QueriesBuilder::set_filter works end-to-end: both the
    // #pk/:pk key placeholders and the #f/:fld filter placeholders coexist.
    let r3 = dynamo
        .query_page_by_pk_with_filter(
            "User#tedwen",
            None,
            Some(1),
            false,
            "#f = :fld",
            Some(HashMap::from([("#f".to_string(), String::from("folder"))])),
            Some(HashMap::from([(
                ":fld".to_string(),
                AttributeValue::S(String::from("inbox")),
            )])),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r3.count, 1, "{:?}", r3);
}
