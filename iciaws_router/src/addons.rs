use super::errors::RouterError;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::RwLock;

#[derive(Debug)]
pub struct AddonHolder {
    addons: RwLock<HashMap<String, Box<dyn Any + Send + Sync>>>,
}

impl AddonHolder {
    pub fn new() -> Self {
        Self {
            addons: RwLock::new(HashMap::new()),
        }
    }

    pub fn put_addon<T: Any + Send + Sync>(&self, key: &str, value: T) {
        let mut map = self.addons.write().unwrap();
        map.insert(key.to_string(), Box::new(value));
    }

    pub fn get_addon<T: Any + Send + Sync>(&self, key: &str) -> Option<T>
    where
        T: Clone,
    {
        let map = self.addons.read().unwrap();
        map.get(key)
            .and_then(|boxed| boxed.downcast_ref::<T>())
            .cloned()
    }

    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Result<T, RouterError>
    where
        T: Clone + Debug,
    {
        let map = self.addons.read().unwrap();
        let addon_or_none = map
            .get(key)
            .and_then(|boxed| boxed.downcast_ref::<T>())
            .cloned();
        match addon_or_none {
            Some(addon) => Ok(addon),
            None => Err(RouterError::AddonMissing(format!("{} not found!", key))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iciaws_dynamo::{DynamoClient, get_dynamo_client};
    use aws_sdk_dynamodb::types::AttributeValue;

    #[derive(Clone, Debug, PartialEq)]
    struct TestStruct {
        value: i32,
        name: String,
    }

    #[test]
    fn test_addon() {
        let test_data = TestStruct {
            value: 42,
            name: "test".to_string(),
        };
        let addon_map = AddonHolder::new();
        addon_map.put_addon("test_key", test_data.clone());
        let retrieved = addon_map.get::<TestStruct>("test_key").unwrap();
        assert_eq!(
            retrieved, test_data,
            "get back whats added: {:?}",
            retrieved
        );
    }

    #[tokio::test]
    async fn test_addon_dynamo() {
        // this test should run using local dynamodb with DYNAMO_ENDPOINT_URL=http://localhost:8000 set in .env
        let dynamo = get_dynamo_client(Some("ici-email")).await;
        let addon_map = AddonHolder::new();
        addon_map.put_addon("dynamo", dynamo);
        let retrived = addon_map.get::<&DynamoClient>("dynamo").unwrap();
        let res = retrived.get_by_pksk("User", "#qywen", None).await;
        println!("\x1b[94m>>>>> res: {:?}\x1b[0m", res);
        match res.unwrap().item {
            Some(item) => assert_eq!(item.get("email").unwrap(), &AttributeValue::S(String::from("qy.wen@intercci.com")), "item is {:?}", item),
            None => assert!(false, "No item returned")
        }
    }
}
