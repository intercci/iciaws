use iciaws_dynamo::DynamoClient;
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use serde_json::json;


#[tokio::test]
async fn dynamo_update_n() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_n0";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await; // idempotent reset

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("value".to_string(), AttributeValue::N("0".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists before update_n");
    let nv1 = item
        .get("value")
        .expect("value field present before update_n")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();

    // update_n is SET #fld = :sval -> it REPLACES the value, it does NOT
    // increment. nv2 == nv1 + 1 holds only because byval == 1 and the fixture
    // starts at 0 (0 -> 1, so 1 == 0 + 1).
    dynamo.update_n(&res_id, "value", 1, None).await.unwrap();
    let item2 = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_n");
    let nv2 = item2
        .get("value")
        .expect("value field present after update_n")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(nv2, nv1 + 1, "SET semantics: value goes 0 -> 1");

    let _ = dynamo.delete_by_pk(pk, None).await; // cleanup
}

// ============================================================================
// Live integration tests for the update-oriented functions of DynamoClient.
// Each test is self-contained: reset (delete_by_pk) -> put_over fixture ->
// update -> assert via get -> cleanup (delete_by_pk). All tests use the
// ici-track table and distinct pk prefixes so they can run in parallel without
// colliding.
// ============================================================================

#[tokio::test]
async fn dynamo_update_s() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_s";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await; // idempotent reset

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("name".to_string(), AttributeValue::S("old".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    // SET #fld = :sval replaces an existing field; UpdatedNew is returned.
    let out = dynamo.update_s(&res_id, "name", "new", None).await.unwrap();
    let attrs = out.attributes.as_ref().expect("UpdatedNew attributes");
    assert_eq!(
        attrs.get("name").unwrap(),
        &AttributeValue::S(String::from("new"))
    );

    // SET also creates fields that do not exist yet.
    dynamo.update_s(&res_id, "added", "yes", None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_s");
    assert_eq!(
        item.get("added").unwrap(),
        &AttributeValue::S(String::from("yes"))
    );

    let _ = dynamo.delete_by_pk(pk, None).await; // cleanup
}

#[tokio::test]
async fn dynamo_update_n_value() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_n";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("value".to_string(), AttributeValue::N("10".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    // update_n is SET #fld = :sval -> it REPLACES the value, it does NOT increment.
    dynamo.update_n(&res_id, "value", 3, None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_n");
    let v = item
        .get("value")
        .expect("value field present after update_n")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(v, 3, "update_n must REPLACE value (SET semantics), not add");

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_add_inc() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_add";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("count".to_string(), AttributeValue::N("10".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    // update_add: SET #fld = if_not_exists(#fld, :zero) + :one -> increments.
    dynamo.update_add(&res_id, "count", 5, None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_add count");
    let c = item
        .get("count")
        .expect("count field present after update_add")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(c, 15, "10 + 5");

    // On a missing field, if_not_exists defaults to 0, so the result is 0 + 7.
    dynamo.update_add(&res_id, "fresh", 7, None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_add fresh");
    let f = item
        .get("fresh")
        .expect("fresh field present after update_add")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(f, 7, "if_not_exists default 0 + 7");

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_add_ts() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_ts";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("c".to_string(), AttributeValue::N("1".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    // update_add_ts increments #fld AND stamps #ts with %y%m%d%H%M%S (12 chars).
    dynamo.update_add_ts(&res_id, "c", 2, "ts", None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_add_ts");
    let c = item
        .get("c")
        .expect("c field present after update_add_ts")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(c, 3, "1 + 2");
    let ts = item.get("ts").expect("ts field present").as_s().unwrap();
    assert_eq!(ts.len(), 12, "ts must be formatted as %y%m%d%H%M%S");

    // A second call keeps incrementing and refreshes the timestamp.
    dynamo.update_add_ts(&res_id, "c", 3, "ts", None).await.unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after second update_add_ts");
    let c = item
        .get("c")
        .expect("c field present after second update_add_ts")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(c, 6, "3 + 3");

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_generic_expr() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_gen";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("name".to_string(), AttributeValue::S("a".into())),
                ("age".to_string(), AttributeValue::N("1".into())),
                ("junk".to_string(), AttributeValue::S("x".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    // Generic update with a raw expression: SET two fields + REMOVE one.
    let key = dynamo.resid_to_keys(&res_id);
    let ean: HashMap<String, String> = HashMap::from([
        ("#n".to_string(), "name".to_string()),
        ("#a".to_string(), "age".to_string()),
    ]);
    let eav: HashMap<String, AttributeValue> = HashMap::from([
        (":nv".to_string(), AttributeValue::S("b".into())),
        (":av".to_string(), AttributeValue::N("2".into())),
    ]);
    dynamo
        .update(
            key,
            "SET #n = :nv, #a = :av REMOVE junk".to_string(),
            ean,
            eav,
            None,
        )
        .await
        .unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after generic SET/REMOVE update");
    assert_eq!(
        item.get("name").unwrap(),
        &AttributeValue::S(String::from("b"))
    );
    assert_eq!(
        item.get("age")
            .expect("age field present after SET")
            .as_n()
            .unwrap()
            .parse::<i32>()
            .unwrap(),
        2
    );
    assert!(item.get("junk").is_none(), "REMOVE junk must delete the field");

    // Generic ADD: ADD on a missing number field creates it with the operand.
    let key = dynamo.resid_to_keys(&res_id);
    let ean: HashMap<String, String> = HashMap::from([("#h".to_string(), "hits".to_string())]);
    let eav: HashMap<String, AttributeValue> =
        HashMap::from([(":one".to_string(), AttributeValue::N("1".into()))]);
    dynamo
        .update(key, "ADD #h :one".to_string(), ean, eav, None)
        .await
        .unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after generic ADD update");
    let hits = item
        .get("hits")
        .expect("hits field present after ADD")
        .as_n()
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(hits, 1, "ADD #h :one on a missing field must create it as 1");

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_add_list_str() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_ls";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
            ]),
            None,
        )
        .await
        .unwrap();

    let key = dynamo.resid_to_keys(&res_id);
    dynamo
        .update_add_list_str(key, "tags", "a", None)
        .await
        .unwrap();
    let key = dynamo.resid_to_keys(&res_id);
    dynamo
        .update_add_list_str(key, "tags", "b", None)
        .await
        .unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_add_list_str");
    let tags = item
        .get("tags")
        .expect("tags field present after list append")
        .as_l()
        .unwrap();
    assert_eq!(tags.len(), 2, "list_append appends values");
    assert_eq!(tags[0], AttributeValue::S(String::from("a")));
    assert_eq!(tags[1], AttributeValue::S(String::from("b")));

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_add_list_json() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_lj";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
            ]),
            None,
        )
        .await
        .unwrap();

    let key = dynamo.resid_to_keys(&res_id);
    dynamo
        .update_add_list(key, "items", json!({"k": "v"}), None)
        .await
        .unwrap();
    let key = dynamo.resid_to_keys(&res_id);
    dynamo
        .update_add_list(key, "items", json!({"k": "v"}), None)
        .await
        .unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_add_list");
    let items = item
        .get("items")
        .expect("items field present after list append")
        .as_l()
        .unwrap();
    assert_eq!(items.len(), 2, "two list_append calls");
    assert_eq!(
        items[0].as_m().unwrap().get("k").unwrap(),
        &AttributeValue::S(String::from("v"))
    );
    assert_eq!(
        items[1].as_m().unwrap().get("k").unwrap(),
        &AttributeValue::S(String::from("v"))
    );

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_update_remove_attr() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#upd_rm";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("temp".to_string(), AttributeValue::S("x".into())),
                ("keep".to_string(), AttributeValue::S("y".into())),
            ]),
            None,
        )
        .await
        .unwrap();

    dynamo.update_remove_attr(&res_id, "temp", None).await.unwrap();

    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after update_remove_attr");
    assert!(item.get("temp").is_none(), "temp must be removed");
    assert_eq!(
        item.get("keep").unwrap(),
        &AttributeValue::S(String::from("y"))
    );

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_delete_by_pksk_cleanup() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#del_pksk";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
            ]),
            None,
        )
        .await
        .unwrap();

    dynamo.delete_by_pksk(pk, sk, None).await.unwrap();

    let item = dynamo.get(&res_id, None).await.unwrap().item;
    assert!(item.is_none(), "item must be gone after delete_by_pksk");

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_delete_with_condition() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#del_cond";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
            ]),
            None,
        )
        .await
        .unwrap();

    // Condition holds -> delete succeeds.
    dynamo
        .delete(&res_id, "attribute_exists(pk)", None)
        .await
        .unwrap();
    let item = dynamo.get(&res_id, None).await.unwrap().item;
    assert!(item.is_none(), "item deleted when condition holds");

    // Recreate, then delete with a condition that does NOT hold -> DynamoError
    // (ConditionalCheckFailedException).
    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
            ]),
            None,
        )
        .await
        .unwrap();
    let res = dynamo
        .delete(&res_id, "attribute_not_exists(pk)", None)
        .await;
    assert!(
        res.is_err(),
        "delete with failing condition must return a DynamoError (ConditionalCheckFailedException)"
    );

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_batch_delete_items() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#del_batch";
    let _ = dynamo.delete_by_pk(pk, None).await;

    for sk in ["1", "2", "3"] {
        dynamo
            .put_over(
                HashMap::from([
                    ("pk".to_string(), AttributeValue::S(pk.to_string())),
                    ("sk".to_string(), AttributeValue::S(sk.to_string())),
                    ("v".to_string(), AttributeValue::N("1".into())),
                ]),
                None,
            )
            .await
            .unwrap();
    }

    let keys: Vec<HashMap<String, AttributeValue>> = ["1", "2", "3"]
        .iter()
        .map(|sk| dynamo.resid_to_keys(&format!("{}~{}", pk, sk)))
        .collect();
    dynamo
        .batch_delete(keys, "ici-track")
        .await
        .expect("batch_delete must succeed");

    for sk in ["1", "2", "3"] {
        let item = dynamo
            .get(&format!("{}~{}", pk, sk), None)
            .await
            .unwrap()
            .item;
        assert!(item.is_none(), "item {} must be gone after batch_delete", sk);
    }

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_delete_by_pk_batch() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#del_pk";
    let _ = dynamo.delete_by_pk(pk, None).await;

    for sk in ["1", "2", "3"] {
        dynamo
            .put_over(
                HashMap::from([
                    ("pk".to_string(), AttributeValue::S(pk.to_string())),
                    ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ]),
                None,
            )
            .await
            .unwrap();
    }

    dynamo.delete_by_pk(pk, None).await.unwrap();

    let qo = dynamo
        .query_by_pk(pk, None)
        .await
        .expect("query after delete_by_pk must succeed");
    // Assert count BEFORE consuming .items (partial-move gotcha).
    assert_eq!(qo.count, 0, "{:?}", qo);

    let _ = dynamo.delete_by_pk(pk, None).await;
}

#[tokio::test]
async fn dynamo_put_no_overwrite_condition() {
    let dynamo = DynamoClient::new(String::from("ici-track")).await;
    let pk = "TST#put";
    let sk = "item";
    let res_id = format!("{}~{}", pk, sk);
    let _ = dynamo.delete_by_pk(pk, None).await;

    // put() carries condition_expression("attribute_not_exists(pk)") -> first
    // write to a fresh pk succeeds.
    dynamo
        .put(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("v".to_string(), AttributeValue::S("1".into())),
            ]),
            None,
        )
        .await
        .expect("first put with attribute_not_exists(pk) must succeed");

    // Same pk again -> condition fails (pk already exists) -> DynamoError.
    let res = dynamo
        .put(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("v".to_string(), AttributeValue::S("2".into())),
            ]),
            None,
        )
        .await;
    assert!(
        res.is_err(),
        "second put with the same pk must fail the attribute_not_exists(pk) condition"
    );

    // put_over ignores conditions -> overwrite succeeds.
    dynamo
        .put_over(
            HashMap::from([
                ("pk".to_string(), AttributeValue::S(pk.to_string())),
                ("sk".to_string(), AttributeValue::S(sk.to_string())),
                ("v".to_string(), AttributeValue::S("2".into())),
            ]),
            None,
        )
        .await
        .unwrap();
    let item = dynamo
        .get(&res_id, None)
        .await
        .unwrap()
        .item
        .expect("item exists after put_over");
    assert_eq!(
        item.get("v").unwrap(),
        &AttributeValue::S(String::from("2"))
    );

    let _ = dynamo.delete_by_pk(pk, None).await;
}
