#![allow(dead_code)]
use super::{
    errors::DynamoError,
    types::{ItemType, StringMap},
};
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Updates {
    pub key: ItemType,
    pub ues: Vec<String>, // SET #attr = :val[, #attr = :val, #list_elem[1] = :val1]
    pub uer: Vec<String>, // REMOVE #attr[, #list_elem[x]]
    pub uea: Vec<String>, // ADD #attr :num[,#set_attr :prop]
    pub ued: Vec<String>, // DELETE #set_attr :prop[, #set_attr2 :prop2]
    pub ean: StringMap,   // {"#attr": {"S":"name"}}
    pub eav: ItemType,    // {":val": {"S":"Adam"}}
}

impl Updates {
    pub fn is_empty(&self) -> bool {
        !(self.key.contains_key("pk")
            && (!self.uea.is_empty()
                || !self.ues.is_empty()
                || !self.uer.is_empty()
                || !self.ued.is_empty()))
    }

    pub fn uex(&self) -> String {
        let mut cmds: Vec<String> = Vec::new();
        if !self.ues.is_empty() {
            cmds.push(format!("SET {}", self.ues.join(", ")));
        }
        if !self.uer.is_empty() {
            cmds.push(format!("REMOVE {}", self.uer.join(", ")));
        }
        if !self.uea.is_empty() {
            cmds.push(format!("ADD {}", self.uea.join(", ")));
        }
        if !self.ued.is_empty() {
            cmds.push(format!("DELETE {}", self.ued.join(", ")));
        }
        cmds.join(" ")
    }

    pub fn builder() -> UpdatesBuilder {
        UpdatesBuilder {
            updates: Updates::default(),
        }
    }

    pub fn make_key(pk: &str, sk: &str) -> ItemType {
        HashMap::from([
            ("pk".to_string(), AttributeValue::S(pk.to_string())),
            ("sk".to_string(), AttributeValue::S(sk.to_string())),
        ])
    }
}

#[derive(Debug)]
pub struct UpdatesBuilder {
    updates: Updates,
}

impl UpdatesBuilder {
    pub fn pk(mut self, pks: impl Into<String>) -> Self {
        self.updates
            .key
            .insert("pk".to_owned(), AttributeValue::S(pks.into()));
        self
    }

    pub fn sk(mut self, sks: impl Into<String>) -> Self {
        self.updates
            .key
            .insert("sk".to_owned(), AttributeValue::S(sks.into()));
        self
    }

    pub fn set_pk(mut self, pk: Option<impl Into<String>>) -> Self {
        match pk {
            Some(pks) => {
                self.updates
                    .key
                    .insert("pk".to_owned(), AttributeValue::S(pks.into()));
            }
            None => (),
        }
        self
    }

    pub fn set_sk(mut self, sk: Option<impl Into<String>>) -> Self {
        match sk {
            Some(sks) => {
                self.updates
                    .key
                    .insert("sk".to_owned(), AttributeValue::S(sks.into()));
            }
            None => (),
        }
        self
    }

    pub fn set_pksk(
        self,
        pk: Option<impl Into<String>>,
        sk: Option<impl Into<String>>,
    ) -> Self {
        self.set_pk(pk).set_sk(sk)
    }

    /// compatible legacy fn, == set method, use method: set, remove, add, delete instead
    pub fn add_update(mut self, name: &str, value: AttributeValue) -> Self {
        self.updates.ues.push(format!("#{} = :{}", name, name));
        self.updates
            .ean
            .insert(format!("#{}", name), name.to_owned());
        self.updates.eav.insert(format!(":{}", name), value);
        self
    }

    pub fn add_update_with_value(self, name: &str, value: &serde_json::Value) -> Self {
        let v: AttributeValue = serde_dynamo::to_attribute_value(value).unwrap();
        self.add_update(name, v)
    }

    /// Add an element of key:value into a map attribute of the specified item.
    /// 
    /// # Note: the following UpdateExpression does not work (so, the mapName must exist beforehand):
    ///     SET #mapName = if_not_exists(#mapName, :emptyMap), #mapName.#keyName = :valueName
    /// 
    /// # Example:
    /// 
    /// SET #roles.#appid = :role  (attrib_name="roles", key="appid", value="role")
    /// SET #pr.#5star[1] = :r5, .. for adding nested map attributes
    /// 
    pub fn add_map_element(mut self, attrib_name: &str, key: &str, value: &serde_json::Value) -> Self {
        let v: AttributeValue = serde_dynamo::to_attribute_value(value).unwrap();
        // self.updates.ues.push("#att = if_not_exists(#att, :emm), #att.#mek = :mev".to_string());
        self.updates.ues.push("#mapName.#keyName = :valueName".to_string());
        self.updates.ean.insert("#mapName".to_string(), attrib_name.to_string());
        self.updates.ean.insert("#keyName".to_string(), key.to_string());
        self.updates.eav.insert(":valueName".to_string(), v);
        self
    }

    /// New update expression methods for SET
    /// SET #attr = :val, #attr2 = :val2
    /// SET #list_elem[x] = :newVal, .. for setting an element value in a list
    /// SET #pr = #pr - :p, .. for decrementing numeric attribute
    /// SET #list_attr = list_append(#list_attr, :val_list)
    /// SET #pr = if_not_exists(#pr, :pv)
    pub fn set(self, name: &str, value: &serde_json::Value) -> Self {
        self.add_update_with_value(name, value)
    }
    
    /// SET #list_name = list_append(if_not_exists(#list_name, :elst), :val)
    pub fn append(mut self, list_name: &str, value: &serde_json::Value) -> Self {
        self.updates.ues.push(format!("#{} = list_append(if_not_exists(#{}, :elst), :val)", list_name, list_name));
        self.updates.ean.insert(format!("#{}", list_name), list_name.to_string());
        self.updates.eav.insert(format!(":elst"), AttributeValue::L(Vec::new()));
        self.updates.eav.insert(format!(":val"), serde_dynamo::to_attribute_value(value).unwrap());
        self
    }

    /// REMOVE #attr
    /// REMOVE #list_elem[1], .. for removing element from a list
    pub fn remove(mut self, name: &str) -> Self {
        let vn = format!("#{}", name);
        self.updates.uer.push(vn.clone());
        let attr_name = name.split('[').next().unwrap_or(name);
        self.updates.ean.insert(format!("#{attr_name}"), attr_name.to_string());
        self
    }

    /// ADD #attr :num[, #set_attr, :elem]
    pub fn add(mut self, name: &str, value: &serde_json::Value) -> Self {
        self.updates.uea.push(format!("#{} :{}", name, name));
        self.updates
            .ean
            .insert(format!("#{}", name), name.to_string());
        let v: AttributeValue = serde_dynamo::to_attribute_value(value).unwrap();
        self.updates.eav.insert(format!(":{}", name), v);
        self
    }

    /// DELETE #set_attr :subset
    pub fn delete(mut self, name: &str, subset: &serde_json::Value) -> Self {
        self.updates.ued.push(format!("#{} :{}", name, name));
        self.updates
            .ean
            .insert(format!("#{}", name), name.to_string());
        let v: AttributeValue = serde_dynamo::to_attribute_value(subset).unwrap();
        self.updates.eav.insert(format!(":{}", name), v);
        self
    }

    pub fn build(self) -> Result<Updates, DynamoError> {
        if self.updates.is_empty() {
            return Err(DynamoError::BuildError(
                "UpdateExpression build empty".to_string(),
            ));
        }

        Ok(self.updates)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_dynamo::aws_sdk_dynamodb_1::to_attribute_value;
    use serde_json::json;

    #[test]
    fn test_updates_default() {
        let u = Updates::default();
        assert_eq!(u.key.len(), 0);
        assert_eq!(u.uea.len(), 0);
        assert_eq!(u.ean.len(), 0);
        assert_eq!(u.eav.len(), 0);
        assert!(u.is_empty());
    }

    #[test]
    fn test_builder() {
        let pk = "PK".to_owned();
        let sk = "SK".to_owned();
        let mut b = Updates::builder().set_pk(Some(&pk)).set_sk(Some(&sk));
        let name = "Name".to_owned();
        let age: u32 = 25;
        b = b.add_update("name", to_attribute_value(name).unwrap());
        b = b.add_update("age", to_attribute_value(age).unwrap());
        let u = b.build().unwrap();
        assert!(!u.is_empty());
        assert_eq!(u.uex(), "SET #name = :name, #age = :age");
        assert_eq!(u.ean.get("#name").unwrap(), "name");
        assert_eq!(u.ean.get("#age").unwrap(), "age");
        assert_eq!(
            u.eav.get(":name").unwrap(),
            &AttributeValue::S("Name".to_string())
        );
        assert_eq!(
            u.eav.get(":age").unwrap(),
            &AttributeValue::N("25".to_string())
        );
    }

    #[test]
    fn test_builder_new() {
        let pk = "PK";
        let sk = "SK";
        let up = Updates::builder()
            .set_pk(Some(pk))
            .set_sk(Some(sk))
            .set("name", &json!("Name"))
            .set("age", &json!(25))
            .remove("x")
            .add("count", &json!(1))
            .delete("mset", &json!({"a": 1}))
            .build().unwrap();
        assert!(!up.is_empty());
        assert_eq!(up.uex(), "SET #name = :name, #age = :age REMOVE #x ADD #count :count DELETE #mset :mset");
        assert_eq!(up.ean.get("#name").unwrap(), "name");
        assert_eq!(up.ean.get("#age").unwrap(), "age");
        assert_eq!(up.ean.get("#count").unwrap(), "count");
        assert_eq!(up.ean.get("#mset").unwrap(), "mset");
        assert_eq!(up.eav.get(":name").unwrap(), &AttributeValue::S("Name".to_string()));
        assert_eq!(up.eav.get(":age").unwrap(), &AttributeValue::N("25".to_string()));
        assert_eq!(up.eav.get(":count").unwrap(), &AttributeValue::N("1".to_string()));
        let avm = json!({"a": 1});
        assert_eq!(up.eav.get(":mset").unwrap(), &to_attribute_value(avm).unwrap());
    }

    #[test]
    fn test_add_map_element() {
        let up = Updates::builder().set_pksk(Some("PK"), Some("SK"))
            .add_map_element("roles", "iciaward", &serde_json::Value::String("admin".to_string()))
            .build().unwrap();
        assert_eq!(up.uex(), "SET #mapName.#keyName = :valueName");
        assert_eq!(up.ean.get("#mapName").unwrap(), "roles");
        assert_eq!(up.ean.get("#keyName").unwrap(), "iciaward");
        assert_eq!(up.eav.get(":valueName"), Some(&AttributeValue::S("admin".to_string())));
    }
    
    #[test]
    fn test_builder_list_append() {
        let up = Updates::builder()
            .set_pk(Some("PK".to_owned())).set_sk(Some("SK".to_owned()))
            .append("users", &json!({"uid": "U3", "name": "N3", "email": "E3"}))
            .build().unwrap();
        assert_eq!(up.uex(), "SET #users = list_append(if_not_exists(#users, :elst), :val)");
        assert_eq!(up.ean.get("#users").unwrap(), "users");
        assert_eq!(up.eav.get(":elst").unwrap(), &AttributeValue::L(Vec::new()));
        let lst = format!("{:?}", up.eav.get(":val").unwrap().as_l());
        assert!(lst.contains("U3"), "{}", lst);
        // assert_eq!(lst.as_m().unwrap().get("uid").unwrap(), &AttributeValue::S("U3".to_string()));
    }

    #[test]
    fn test_builder_list_remove() {
        let items = json!([
            {"uid": "U1", "name": "N1", "email": "E1"},
            {"uid": "U2", "name": "N2", "email": "E2"},
        ]);
        let up = Updates::builder()
            .set_pk(Some("PK".to_owned())).set_sk(Some("SK".to_owned()))
            .set("users", &items)
            .remove("users[1]")
            .build().unwrap();
        assert_eq!(up.uex(), "SET #users = :users REMOVE #users[1]");
        assert_eq!(up.ean.get("#users").unwrap(), "users");
    }

}
