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

// ============================================================================
// Live integration tests for query_page_by_pk_with_sk_expr and
// query_page_by_pk_with_sk_between. Each test is self-contained: reset
// (delete_by_pk) -> put_over fixtures -> query -> assert -> cleanup. Both use
// the ici-track table and distinct pk prefixes so they can run in parallel
// without colliding. The sk fixtures are zero-padded numeric strings so that
// DynamoDB's lexicographic string ordering matches numeric ordering.
// ============================================================================

#[tokio::test]
async fn dynamo_query_page_by_pk_with_sk_expr() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#q_skexpr";
    let _ = dynamo.delete_by_pk(pk, None).await; // idempotent reset

    for sk in ["1000", "2000", "3000", "4000"] {
        dynamo
            .put_over(
                HashMap::from([
                    ("pk".to_string(), AttributeValue::S(pk.to_string())),
                    ("sk".to_string(), AttributeValue::S(sk.to_string())),
                    ("value".to_string(), AttributeValue::N(sk.into())),
                ]),
                None,
            )
            .await
            .unwrap();
    }

    // sk > 1000, descending, page size 2 -> first page holds the two largest sk.
    let r = dynamo
        .query_page_by_pk_with_sk_expr(pk, None, Some(2), false, ">", "1000", None)
        .await
        .unwrap();
    assert_eq!(r.count, 2, "{:?}", r);
    let items = r.items.as_ref().expect("items on page 1");
    assert_eq!(items[0].get("sk").unwrap(), &AttributeValue::S(String::from("4000")));
    assert_eq!(items[1].get("sk").unwrap(), &AttributeValue::S(String::from("3000")));
    let last_k = r.last_evaluated_key().map_or(None, |k| Some(k.clone()));
    assert!(last_k.is_some(), "last_evaluated_key is None");
    let last_keys = last_evaluated_key_to_base64(last_k.unwrap()).expect("last_key error");

    // Page 2 continues after the last key of page 1 -> remaining item "2000".
    let r2 = dynamo
        .query_page_by_pk_with_sk_expr(pk, Some(last_keys), None, false, ">", "1000", None)
        .await
        .unwrap();
    assert_eq!(r2.count, 1, "{:?}", r2);
    let items2 = r2.items.as_ref().expect("items on page 2");
    assert_eq!(items2[0].get("sk").unwrap(), &AttributeValue::S(String::from("2000")));
    assert!(r2.last_evaluated_key.is_none(), "{:?}", r2);

    // Same key condition, ascending -> smallest qualifying sk first.
    let r3 = dynamo
        .query_page_by_pk_with_sk_expr(pk, None, None, true, ">", "1000", None)
        .await
        .unwrap();
    assert_eq!(r3.count, 3, "{:?}", r3);
    let items3 = r3.items.expect("items ascending");
    assert_eq!(items3[0].get("sk").unwrap(), &AttributeValue::S(String::from("2000")));
    assert_eq!(items3[1].get("sk").unwrap(), &AttributeValue::S(String::from("3000")));
    assert_eq!(items3[2].get("sk").unwrap(), &AttributeValue::S(String::from("4000")));

    // A different operator: sk < 3000, descending -> ["2000", "1000"].
    let r4 = dynamo
        .query_page_by_pk_with_sk_expr(pk, None, None, false, "<", "3000", None)
        .await
        .unwrap();
    assert_eq!(r4.count, 2, "{:?}", r4);
    let items4 = r4.items.expect("items for sk < 3000");
    assert_eq!(items4[0].get("sk").unwrap(), &AttributeValue::S(String::from("2000")));
    assert_eq!(items4[1].get("sk").unwrap(), &AttributeValue::S(String::from("1000")));

    let _ = dynamo.delete_by_pk(pk, None).await; // cleanup
}

#[tokio::test]
async fn dynamo_query_page_by_pk_with_sk_between() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#q_skbetween";
    let _ = dynamo.delete_by_pk(pk, None).await; // idempotent reset

    for sk in ["1000", "2000", "3000", "4000"] {
        dynamo
            .put_over(
                HashMap::from([
                    ("pk".to_string(), AttributeValue::S(pk.to_string())),
                    ("sk".to_string(), AttributeValue::S(sk.to_string())),
                    ("value".to_string(), AttributeValue::N(sk.into())),
                ]),
                None,
            )
            .await
            .unwrap();
    }

    // sk between 2000 and 4000 (inclusive), descending, page size 2 -> page 1
    // holds the two largest sk, page 2 the remaining one.
    let r = dynamo
        .query_page_by_pk_with_sk_between(pk, None, Some(2), false, "2000", "4000", None)
        .await
        .unwrap();
    assert_eq!(r.count, 2, "{:?}", r);
    let items = r.items.as_ref().expect("items on page 1");
    assert_eq!(items[0].get("sk").unwrap(), &AttributeValue::S(String::from("4000")));
    assert_eq!(items[1].get("sk").unwrap(), &AttributeValue::S(String::from("3000")));
    let last_k = r.last_evaluated_key().map_or(None, |k| Some(k.clone()));
    assert!(last_k.is_some(), "last_evaluated_key is None");
    let last_keys = last_evaluated_key_to_base64(last_k.unwrap()).expect("last_key error");

    let r2 = dynamo
        .query_page_by_pk_with_sk_between(pk, Some(last_keys), None, false, "2000", "4000", None)
        .await
        .unwrap();
    assert_eq!(r2.count, 1, "{:?}", r2);
    let items2 = r2.items.as_ref().expect("items on page 2");
    assert_eq!(items2[0].get("sk").unwrap(), &AttributeValue::S(String::from("2000")));
    assert!(r2.last_evaluated_key.is_none(), "{:?}", r2);

    // Ascending: between bounds are inclusive and returned in ascending order.
    let r3 = dynamo
        .query_page_by_pk_with_sk_between(pk, None, None, true, "2000", "4000", None)
        .await
        .unwrap();
    assert_eq!(r3.count, 3, "{:?}", r3);
    let items3 = r3.items.expect("items ascending");
    assert_eq!(items3[0].get("sk").unwrap(), &AttributeValue::S(String::from("2000")));
    assert_eq!(items3[1].get("sk").unwrap(), &AttributeValue::S(String::from("3000")));
    assert_eq!(items3[2].get("sk").unwrap(), &AttributeValue::S(String::from("4000")));

    let _ = dynamo.delete_by_pk(pk, None).await; // cleanup
}
