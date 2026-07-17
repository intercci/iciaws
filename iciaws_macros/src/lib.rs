use heck::ToUpperCamelCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, ItemFn, LitStr, parse_macro_input};

#[proc_macro_attribute]
/// Procedural macro to decorate a request handler function for Router
///
/// #Example
///
/// ```rust,ignore
/// use std::pin::Pin;
/// use std::future::Future;
/// use iciaws_router::{
///     addons::AddonHolder,
///     input::RouteHandlerInput,
///     output::RouteHandlerOutput,
///     types::RouteHandler,
/// }
/// use anyhow::Result;
///
/// #[route("GET/homes/{id}")]
/// pub fn get_home(input: RouteHandlerInput, addons: &AddonHolder) -> Result<RouteHandlerOutput> {
///     let r = RouteHandlerOutput::message_output(StatusCode::OK, "Hello".to_string());
///     Ok(r)
/// }
/// ```
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_args = parse_macro_input!(attr as LitStr);
    let path_str = input_args.value();
    let path_ident = format!("{}", path_str);

    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_block = &input_fn.block;
    // let fn_vis = &input_fn.vis;
    // let fn_sig = &input_fn.sig;
    let fn_name_camel_case = fn_name.to_string().to_upper_camel_case(); // get_homes to GetHomes
    let struct_name = format_ident!("{}Handler", fn_name_camel_case); // GetHomesHandler
    let key_name = format_ident!("{}KEY", fn_name_camel_case.to_uppercase()); //GETHOMESKEY

    let expanded = quote! {
        static #key_name: &'static str = #path_ident;
        #[derive(Debug)]
        pub struct #struct_name;
        impl RouteHandler for #struct_name{
            fn handle<'a>(&self, input: RouteHandlerInput, addons: &'a AddonHolder) -> Pin<Box<dyn Future<Output = Result<RouteHandlerOutput>> + Send + 'a>> {
                Box::pin(async move #fn_block)
            }
        }
        impl #struct_name{
            pub fn get_key() -> &'static str {
                #key_name
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(TransDynamo)]
/// Procedural macro for derive on a struct to add functions to convert from and to DynamoDB items.
///
/// #Example
/// ```rust,ignore
/// use serde_dynamo;
/// use iciaws_router::types::DefaultKeys;
/// use aws_sdk_dynamodb:types::AttributeValue;
///
/// #[derive(TransDynamo, Debug, Serialize, Deserialize)]
/// pub struct User{
///    ...
/// }
/// 
/// impl DefaultKeys for User {
///   fn set_default_keys(&mut self, from_map: &Value) -> Result<()> {}
/// }
/// ```
///
/// The above example will generate the following functions:
/// ```rust,ignore
///
/// pub fn users_from_dynamodb(items: Vec<HashMap<String, AttributeValue>>) -> Result<Vec<User>> {
///     serde_dynamo::from_items(items)
/// }
///
/// And implement the TryFrom trait for serde_json::Value and HashMap<String, AttributeValue>: serde_dynamo::from_item(..)
/// And implement the TryFrom<#struct_id> trait for HashMap<String, AttributeValue>: serde_dynamo::to_item(..)
/// ```
pub fn add_serde_dynamo_fns(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let struct_id = &input.ident; // like User
    let prefix = struct_id.to_string().to_lowercase(); // like 'user'
    // let one_from = format_ident!("{}_from_dynamodb", prefix);
    // let one_to = format_ident!("{}_to_dynamodb", prefix);
    let more_from = format_ident!("{}s_from_dynamodb", prefix);

    let expanded = quote! {
        #[automatically_derived]
        pub fn #more_from (items: Vec<HashMap<String, AttributeValue>>) -> Result<Vec<#struct_id>> {
            serde_dynamo::from_items(items).map_err(|e|e.into())
        }
        impl TryFrom<serde_json::Value> for #struct_id {
            type Error = anyhow::Error;
            fn try_from(value: serde_json::Value) -> Result<Self> {
                if value.get("pk").is_none() {
                    let vc = value.clone();
                    let mut s: Self = serde_json::from_value(value)?;
                    s.set_default_keys(&vc)?;
                    Ok(s)
                } else {
                    Ok(serde_json::from_value(value)?)
                }
            }
        }
        impl TryFrom<HashMap<String, AttributeValue>> for #struct_id {
            type Error = anyhow::Error;
            fn try_from(value: HashMap<String, AttributeValue>) -> Result<#struct_id> {
                serde_dynamo::from_item(value).map_err(|e| e.into())
            }
        }
        impl TryFrom<#struct_id> for HashMap<String, AttributeValue> {
            type Error = anyhow::Error;
            fn try_from(value: #struct_id) -> Result<HashMap<String, AttributeValue>> {
                serde_dynamo::to_item(value).map_err(|e| e.into())
            }
        }
    };

    TokenStream::from(expanded)
}
