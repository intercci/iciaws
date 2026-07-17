use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    Client,
    error::DisplayErrorContext,
    operation::{get_object::GetObjectOutput, put_object::PutObjectOutput},
    presigning::PresigningConfig,
};
use bytes::Bytes;
use dotenv::dotenv;
use serde_json::Value;
use std::{env, time::Duration};
use thiserror::Error;
use tokio::sync::OnceCell;

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Object not found: {0}")]
    NotFound(String),
    #[error("GetObject error: {0}")]
    GetObject(String),
    #[error("PutObject error: {0}")]
    PutObject(String),
    #[error("Presign error: {0}")]
    Presign(String),
}

pub async fn s3_client() -> Client {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    Client::new(&config)
}

#[derive(Debug)]
pub struct S3Client {
    client: Client,
    default_bucket: String,
}

impl S3Client {
    pub async fn new(bucket: Option<String>) -> Self {
        if env::var("LAMBDA_TASK_ROOT").is_err() {
            dotenv().ok();
        }
        let bkt = env::var("BUCKET")
            .unwrap_or_else(|_| bucket.unwrap_or_else(|| "ici-uploads".to_string()));
        eprintln!("* S3 init using bucket '{bkt}'");
        S3Client {
            client: s3_client().await,
            default_bucket: bkt,
        }
    }

    pub async fn get_object(
        &self,
        object: &str,
        bucket: Option<&str>,
    ) -> Result<GetObjectOutput, S3Error> {
        let go = self
            .client
            .get_object()
            .bucket(bucket.unwrap_or(&self.default_bucket))
            .key(object.to_string())
            .send()
            .await
            .map_err(|e| S3Error::GetObject(format!("{}", DisplayErrorContext(e))))?;

        Ok(go)
    }

    pub async fn put_object(
        &self,
        object: &str,
        body: aws_sdk_s3::primitives::ByteStream,
        bucket: Option<&str>,
    ) -> Result<PutObjectOutput, S3Error> {
        let po = self
            .client
            .put_object()
            .bucket(bucket.unwrap_or(&self.default_bucket))
            .key(object.to_string())
            .body(body)
            .send()
            .await
            .map_err(|e| S3Error::PutObject(format!("{}", DisplayErrorContext(e))))?;
        Ok(po)
    }

    pub async fn get_bytes(&self, object: &str, bucket: Option<&str>) -> Result<Bytes, S3Error> {
        let output = self.get_object(object, bucket).await?;

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| S3Error::GetObject(format!("ByteStreamError: {e}")))?
            .into_bytes();
        Ok(bytes)
    }

    pub async fn get_string(&self, object: &str, bucket: Option<&str>) -> Result<String, S3Error> {
        let output = self.get_object(object, bucket).await?;

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| S3Error::GetObject(format!("ByteStreamError: {e}")))?
            .into_bytes();

        String::from_utf8(bytes.into())
            .map_err(|e| S3Error::GetObject(format!("Invalid UTF-8 sequence: {e}")))
    }

    pub async fn get_json(&self, object: &str, bucket: Option<&str>) -> Result<Value, S3Error> {
        let output = self.get_object(object, bucket).await?;

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| S3Error::GetObject(format!("ByteStreamError: {e}")))?
            .into_bytes();

        #[cfg(debug_assertions)]
        if let Ok(s) = std::str::from_utf8(&bytes) {
            println!("\n\x1b[41mS3::get_object returned: {:?}\x1b[0m", s);
        }

        serde_json::from_slice(&bytes).map_err(|e| S3Error::GetObject(e.to_string()))
    }

    pub async fn get_presign(
        &self,
        object: impl Into<String>,
        bucket: Option<&str>,
    ) -> Result<String, S3Error> {
        let pr = self
            .client
            .get_object()
            .key(object)
            .bucket(bucket.unwrap_or(&self.default_bucket))
            .presigned(
                PresigningConfig::builder()
                    .expires_in(Duration::from_secs(60))
                    .build()
                    .map_err(|e| {
                        S3Error::Presign(format!("PresigningConfig::builder error: {:?}", e))
                    })
                    .unwrap(),
            )
            .await
            .map_err(|e| S3Error::Presign(format!("{}", DisplayErrorContext(e))))?;

        Ok(pr.uri().to_string())
    }

    pub async fn put_presign(
        &self,
        object: impl Into<String>,
        bucket: Option<&str>,
    ) -> Result<String, S3Error> {
        let pr = self
            .client
            .put_object()
            .key(object)
            .bucket(bucket.unwrap_or(&self.default_bucket))
            .presigned(
                PresigningConfig::builder()
                    .expires_in(Duration::from_secs(60 * 5))
                    .build()
                    .map_err(|e| {
                        S3Error::Presign(format!("PresigningConfig::builder error: {:?}", e))
                    })
                    .unwrap(),
            )
            .await
            .map_err(|e| S3Error::Presign(format!("{}", DisplayErrorContext(e))))?;

        Ok(pr.uri().to_string())
    }

    pub async fn list_images(
        &self,
        folder: impl Into<String>,
        bucket: Option<&str>,
    ) -> Result<Vec<String>, S3Error> {
        let output = self
            .client
            .list_objects_v2()
            .bucket(bucket.unwrap_or(&self.default_bucket))
            .prefix(folder)
            .send()
            .await
            .map_err(|e| S3Error::GetObject(format!("{}", DisplayErrorContext(e))))?;

        let exts = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
        let imgs: Vec<String> = output
            .contents()
            .iter()
            .filter_map(|obj| obj.key())
            .filter(|key| {
                let lower_key = key.to_lowercase();
                exts.iter().any(|&ext| lower_key.ends_with(ext))
            })
            .map(|key| key.to_string())
            .collect();
        Ok(imgs)
    }
}

pub static S3: OnceCell<S3Client> = OnceCell::const_new();

pub async fn get_s3_client() -> &'static S3Client {
    S3.get_or_init(|| async { S3Client::new(None).await }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_presign() {
        let s3c = get_s3_client().await;
        let rs = s3c.get_presign("img_file.png", None).await;
        if let Ok(s) = rs {
            println!("get_presign returns: {}", s);
        } else {
            assert!(false, "get_presign error: {:?}", rs);
        }
    }
}
