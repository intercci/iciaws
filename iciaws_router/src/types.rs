use super::{addons::AddonHolder, input::RouteHandlerInput, output::RouteHandlerOutput};
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub trait RouteHandler: Send + Sync {
    fn handle<'a>(
        &self,
        input: RouteHandlerInput,
        addons: &'a AddonHolder,
    ) -> Pin<Box<dyn Future<Output = Result<RouteHandlerOutput>> + Send + 'a>>;
}

pub type RouteHandlerType = Box<dyn RouteHandler>;

pub trait DefaultKeys {
    fn set_default_keys(&mut self, from_map: &serde_json::Value) -> Result<()>;
}
