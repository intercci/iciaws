#![allow(dead_code)]
use aws_config::BehaviorVersion;
use aws_sdk_sns::{Client, error::DisplayErrorContext};
use dotenv::dotenv;
use std::env;
use thiserror::Error;
use tokio::sync::OnceCell;

#[derive(Error, Debug)]
pub enum SnsError {
    #[error("env TOPIC_ARN not set")]
    NoTopicArn,
    #[error("publish error {0}")]
    Publish(String),
}

pub async fn sns_client() -> Client {
    if env::var("LAMBDA_TASK_ROOT").is_err() {
        dotenv().ok();
    }
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    Client::new(&config)
}

#[derive(Debug)]
pub struct SnsClient {
    client: Client,
    topic_arn: String,
}

impl SnsClient {
    pub async fn new() -> Self {
        Self {
            client: sns_client().await,
            topic_arn: env::var("TOPIC_ARN").unwrap_or_default(),
        }
    }

    /// Publish a SNS message to the topic.
    ///
    /// #Example
    /// ```rust,ignore
    /// let sns = SnsClient::new();
    /// let message_id = sns.publish("Some message", None)?; // set None to use the topic arn from env
    /// ```
    pub async fn publish(
        &self,
        msg: impl Into<String>,
        topic_arn: Option<&str>,
    ) -> Result<String, SnsError> {
        let ta = topic_arn.unwrap_or(&self.topic_arn);
        if ta.is_empty() {
            return Err(SnsError::NoTopicArn);
        }

        let res = self.client.publish()
            .topic_arn(ta.to_owned())
            .message(msg)
            .send().await
            .map_err(|e| SnsError::Publish(format!("{}", DisplayErrorContext(e))))?;

        Ok(res.message_id.unwrap_or_default())
    }
}

pub static SNS: OnceCell<SnsClient> = OnceCell::const_new();

pub async fn get_sns_client() -> &'static SnsClient {
    SNS.get_or_init(|| async { SnsClient::new().await }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish() {
        // let topic_arn = env::var("TOPIC_ARN".to_string()).unwrap_or("".to_string());
        let c = get_sns_client().await;

        let re1 = c.publish("...", None).await;
        if let Ok(_s) = re1 {
            assert!(false, "Should return NoTopicArn error");
        }

        let acc = env::var("AWS_ACCOUNT").unwrap();
        let ta2 = format!("arn:aws:sns:eu-north-1:{}:email-arrived", acc);
        let re2 = c.publish("Topic not found error", Some(&ta2)).await;
        if let Err(e) = re2 {
            // assert!(false, "{:?}", e);
        } else {
            assert!(false, "Should return Publish error");
        }

        let ta3 = env::var("TOPIC_ARN2").unwrap();
        let re3 = c
            .publish("Test SNS publish from rust_libs unittest", Some(&ta3))
            .await;
        if let Ok(s) = re3 {
            println!("Successful, message_id={}", s);
        } else {
            assert!(false, "SNS publish failed for {:?}", re3);
        }
    }
}
